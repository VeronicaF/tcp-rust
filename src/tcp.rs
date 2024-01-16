use anyhow::Context;
use std::io::Write;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Quad {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

/// the connection state
#[derive(Debug, Default)]
pub enum State {
    // #[default]
    Closed,
    #[default]
    Listen,
    SynReceived,
    Established,
}

/**

# State Of The Send Sequence Space (RFC 793 3.2 Figure 4)
```
                   1         2          3          4
              ----------|----------|----------|----------
                     SND.UNA    SND.NXT    SND.UNA
                                          +SND.WND

        1 - old sequence numbers which have been acknowledged
        2 - sequence numbers of unacknowledged data
        3 - sequence numbers allowed for new data transmission
        4 - future sequence numbers which are not yet allowed
```
 **/
struct SendSequenceSpace {
    /// send unacknowledged, AKA UNA
    unacknowledged: u32,
    /// send next, AKA NXT
    next: u32,
    /// send window, AKA WND
    window: u16,
    /// send urgent pointer, AKA UP
    urgent_pointer: bool,
    /// segment sequence number used for last window update
    wl1: u32,
    /// segment acknowledgment number used for last window update
    wl2: u32,
    /// initial send sequence number, AKA ISS
    initial_send_sequence_number: u32,
}

/**
# State Of The Receive Sequence Space (RFC 793 3.2 Figure 5)
```

                       1          2          3
                   ----------|----------|----------
                          RCV.NXT    RCV.NXT
                                    +RCV.WND

        1 - old sequence numbers which have been acknowledged
        2 - sequence numbers allowed for new reception
        3 - future sequence numbers which are not yet allowed
```
 **/
struct ReceiveSequenceSpace {
    /// receive next, AKA NXT
    next: u32,
    /// receive window, AKA WND
    window: u16,
    /// receive urgent pointer, AKA UP
    urgent_pointer: bool,
    /// initial receive sequence number, AKA IRS
    initial_receive_sequence_number: u32,
}

// todo this should be generated from a clock-driven scheme
const INIT_SEQ: u32 = 0;
const INIT_WINDOW: u16 = 10;

pub struct Connection {
    state: State,
    ip_header: etherparse::Ipv4Header,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
}

impl Connection {
    // todo this is incorrect yet because we allocate data when we receive a SYN but we should do it after we receive an ACK for our SYN_ACK
    pub fn accept(
        device: &mut tun::platform::Device,
        ip_header: &etherparse::Ipv4HeaderSlice,
        tcp_header: &etherparse::TcpHeaderSlice,
    ) -> anyhow::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcp_header.syn() {
            tracing::debug!("Only expect syn");
            return Ok(None);
        }

        tracing::debug!(
            "SYN {}:{} -> {}:{}",
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
        );

        let mut connection = Connection {
            state: State::SynReceived,
            ip_header: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::ip_number::TCP,
                ip_header.destination(),
                ip_header.source(),
            ),
            send: SendSequenceSpace {
                unacknowledged: INIT_SEQ,
                next: INIT_SEQ + 1,
                window: INIT_WINDOW,
                urgent_pointer: false,
                wl1: 0,
                wl2: 0,
                initial_send_sequence_number: INIT_SEQ,
            },
            recv: ReceiveSequenceSpace {
                next: tcp_header.sequence_number() + 1,
                window: tcp_header.window_size(),
                urgent_pointer: false,
                initial_receive_sequence_number: tcp_header.sequence_number(),
            },
        };

        let mut syn_ack_tcp_header = etherparse::TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            connection.send.initial_send_sequence_number,
            connection.send.window,
        );
        syn_ack_tcp_header.syn = true;
        syn_ack_tcp_header.ack = true;
        syn_ack_tcp_header.acknowledgment_number = connection.recv.next;

        connection
            .ip_header
            .set_payload_len(syn_ack_tcp_header.header_len() as usize)
            .context("cannot set ip payload len")?;

        syn_ack_tcp_header.checksum = syn_ack_tcp_header
            .calc_checksum_ipv4(&connection.ip_header, &[])
            .context("failed to calc checksum")?;

        let mut unwritten = &mut buf[..];

        let _ = unwritten.write(&[0, 0, 0, 2])?;

        connection.ip_header.write(&mut unwritten)?;
        syn_ack_tcp_header.write(&mut unwritten)?;
        let unwritten_len = unwritten.len();
        let written_len = buf.len() - unwritten_len;

        tracing::trace!("buf written: {:02x?}", &buf[..written_len]);

        device.write_all(&buf[..written_len])?;

        Ok(Some(connection))
    }

    pub fn on_packet(
        &mut self,
        device: &mut tun::platform::Device,
        ip_header: &etherparse::Ipv4HeaderSlice,
        tcp_header: &etherparse::TcpHeaderSlice,
        tcp_payload: &[u8],
    ) -> anyhow::Result<()> {
        tracing::trace!(
            "{}:{} -> {}:{}, {} bytes",
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            tcp_payload.len()
        );

        // acceptable ACK check
        // SND.UNA < SEG.ACK =< SND.NXT
        // todo this should consider number wrapping

        if tcp_header.acknowledgment_number() <= self.send.unacknowledged
            || tcp_header.acknowledgment_number() > self.send.next
        {
            tracing::trace!(
                "Unacceptable ACK, SND.UNA: {} SEG.ACK: {} SND.NXT: {}",
                self.send.unacknowledged,
                tcp_header.acknowledgment_number(),
                self.send.next
            );
            return Ok(());
        }

        match self.state {
            State::SynReceived => {
                // expect to receive an ACK for out SYN_ACK
            }
            State::Established => {}
            State::Closed => {}
            State::Listen => {}
        }

        Ok(())
    }
}
