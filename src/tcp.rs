use crate::utils::{is_in_range_wrapped, is_in_range_wrapped1, is_in_range_wrapped2};
use anyhow::Context;
use std::cmp::min;
use std::io::Write;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Quad {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

/// the connection state
#[derive(Debug)]
pub enum State {
    Listen,
    SynReceived,
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    CloseWait,
    LastAck,
    TimeWait,
    Closed,
}

impl State {
    pub fn is_synced(&self) -> bool {
        matches!(
            self,
            State::Established
                | State::FinWait1
                | State::FinWait2
                | State::Closing
                | State::CloseWait
                | State::LastAck
                | State::TimeWait
        )
    }
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

/**
```
                             +---------+ ---------\      active OPEN
                             |  CLOSED |            \    -----------
                             +---------+<---------\   \   create TCB
                               |     ^              \   \  snd SYN
                  passive OPEN |     |   CLOSE        \   \
                  ------------ |     | ----------       \   \
                   create TCB  |     | delete TCB         \   \
                               V     |                      \   \
                             +---------+            CLOSE    |    \
                             |  LISTEN |          ---------- |     |
                             +---------+          delete TCB |     |
                  rcv SYN      |     |     SEND              |     |
                 -----------   |     |    -------            |     V
+---------+      snd SYN,ACK  /       \   snd SYN          +---------+
|         |<-----------------           ------------------>|         |
|   SYN   |                    rcv SYN                     |   SYN   |
|   RCVD  |<-----------------------------------------------|   SENT  |
|         |                    snd ACK                     |         |
|         |------------------           -------------------|         |
+---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
  |           --------------   |     |   -----------
  |                  x         |     |     snd ACK
  |                            V     V
  |  CLOSE                   +---------+
  | -------                  |  ESTAB  |
  | snd FIN                  +---------+
  |                   CLOSE    |     |    rcv FIN
  V                  -------   |     |    -------
+---------+          snd FIN  /       \   snd ACK          +---------+
|  FIN    |<-----------------           ------------------>|  CLOSE  |
| WAIT-1  |------------------                              |   WAIT  |
+---------+          rcv FIN  \                            +---------+
  | rcv ACK of FIN   -------   |                            CLOSE  |
  | --------------   snd ACK   |                           ------- |
  V        x                   V                           snd FIN V
+---------+                  +---------+                   +---------+
|FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
+---------+                  +---------+                   +---------+
  |                rcv ACK of FIN |                 rcv ACK of FIN |
  |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
  |  -------              x       V    ------------        x       V
   \ snd ACK                 +---------+delete TCB         +---------+
    ------------------------>|TIME WAIT|------------------>| CLOSED  |
                             +---------+                   +---------+

                     TCP Connection State Diagram
```
 **/

pub struct Connection {
    state: State,
    active: bool,
    ip_header: etherparse::Ipv4Header,
    tcp_header: etherparse::TcpHeader,
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
            active: false,
            ip_header: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::ip_number::TCP,
                ip_header.destination(),
                ip_header.source(),
            ),
            tcp_header: etherparse::TcpHeader::new(
                tcp_header.destination_port(),
                tcp_header.source_port(),
                INIT_SEQ,
                INIT_WINDOW,
            ),
            send: SendSequenceSpace {
                unacknowledged: INIT_SEQ,
                next: INIT_SEQ,
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

        connection.tcp_header.syn = true;
        connection.tcp_header.ack = true;
        connection.tcp_header.acknowledgment_number = connection.recv.next;

        connection.write(device, &[])?;

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

        tracing::trace!("old state: {:?}", self.state);

        let recv_window = self.recv.window as u32;
        let seg_seq = tcp_header.sequence_number();
        let seg_ack = tcp_header.acknowledgment_number();
        let seg_len = tcp_payload.len() as u32;

        if tcp_header.fin() && matches!(self.state, State::Closed | State::Listen | State::SynSent)
        {
            // In these States the SEG.SEQ cannot be validated
            // drop the segment and return
            return Ok(());
        }

        match self.state {
            State::Closed => {
                // discard all segments, send a reset to rst
                if !tcp_header.rst() {
                    if tcp_header.ack() {
                        // <SEQ=SEG.ACK><CTL=RST>
                        self.tcp_header.ack = false;
                        self.send_reset(device, seg_ack, 0)?;
                    } else {
                        // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
                        self.send_reset(device, seg_seq.wrapping_add(seg_len), 0)?;
                    }
                }
                return Ok(());
            }
            State::Listen => {
                // check rst
                if tcp_header.rst() {
                    return Ok(());
                }
                if tcp_header.ack() {
                    //  <SEQ=SEG.ACK><CTL=RST>
                    self.send_reset(device, seg_seq, 0)?;
                    return Ok(());
                }

                // check the SYN
                if tcp_header.syn() {
                    // check the security and precedence ignore for now

                    // Set RCV.NXT to SEG.SEQ+1
                    self.recv.next = seg_seq.wrapping_add(1);
                    // IRS is set to SEG.SEQ
                    self.recv.initial_receive_sequence_number = seg_seq;

                    // todo select an ISS, which is a const for now
                    self.send.initial_send_sequence_number = INIT_SEQ;

                    // send a SYN_ACK segment :
                    // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
                    self.tcp_header.syn = true;
                    self.tcp_header.sequence_number = self.send.initial_send_sequence_number;
                    self.tcp_header.acknowledgment_number = self.recv.next;

                    self.write(device, &[])?;

                    // set SND.UNA to ISS
                    self.send.unacknowledged = INIT_SEQ;
                    self.state = State::SynReceived;

                    return Ok(());
                }
            }
            State::SynSent => {
                // first check ack
                let seg_ack_acceptable = if tcp_header.ack() {
                    // SND.UNA < SEG.ACK =< SND.NXT
                    if !is_in_range_wrapped(self.send.unacknowledged, self.send.next, seg_ack) {
                        // ack is not acceptable
                        if !tcp_header.rst() {
                            // <SEQ=SEG.ACK><CTL=RST>
                            self.send_reset(device, seg_ack, 0)?;
                        }
                        return Ok(());
                    }
                    true
                } else {
                    false
                };

                // Second, check the RST
                if tcp_header.rst() {
                    if seg_ack_acceptable {
                        println!("error: connection reset");
                        self.state = State::Closed;
                        // todo delete TCB
                    }
                    return Ok(());
                }

                // Third, check the security which we ignore for now

                // Fourth, check the SYN bit
                // This step should be reached only if the ACK is ok, or there is no ACK, and the segment did not contain a RST.
                if (seg_ack_acceptable || (!tcp_header.ack() && !tcp_header.rst()))
                    && tcp_header.syn()
                {
                    // set RCV.NXT to SEG.SEQ+1
                    self.recv.next = seg_seq.wrapping_add(1);

                    // set IRS to SEG.SEQ.
                    self.recv.initial_receive_sequence_number = seg_seq;

                    // if there is an ACK set SND.UNA to SEG.ACK
                    if tcp_header.ack() {
                        self.send.unacknowledged = seg_ack;
                    }

                    // If SND.UNA > ISS (our SYN has been ACKed)
                    // this segment is a SYN_ACK
                    if self.send.unacknowledged > self.send.initial_send_sequence_number {
                        // change the connection state to ESTABLISHED
                        self.state = State::Established;
                        // send an ACK <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                        self.tcp_header.sequence_number = self.send.next;
                        self.tcp_header.acknowledgment_number = self.recv.next;
                        self.write(device, &[])?;
                        return Ok(());
                    } else {
                        // this happens in Simultaneous initiation
                        self.state = State::SynReceived;
                        // ACK <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
                        self.tcp_header.sequence_number = self.send.initial_send_sequence_number;
                        self.tcp_header.acknowledgment_number = self.recv.next;
                        self.tcp_header.syn = true;
                        self.write(device, &[])?;
                        // SND.WND <- SEG.WND
                        // SND.WL1 <- SEG.SEQ
                        // SND.WL2 <- SEG.ACK
                        self.send.window = tcp_header.window_size();
                        self.send.wl1 = seg_seq;
                        self.send.wl2 = seg_ack;
                    }
                }
            }
            _ => {
                // first check sequence number
                //     Segment  Receive  Test
                //     Length   Window
                //     -------  -------  ------------------------------------------
                //        0        0      SEG.SEQ = RCV.NXT
                //
                //        0        >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                //
                //       >0        0      not acceptable
                //
                //       >0        >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                //                     or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
                let seg_seq_acceptable = {
                    if seg_len == 0 {
                        if recv_window == 0 {
                            // case 1
                            seg_seq == self.recv.next
                        } else {
                            // case 2
                            is_in_range_wrapped1(
                                self.recv.next,
                                self.recv.next.wrapping_add(recv_window),
                                seg_seq,
                            )
                        }
                    } else if recv_window == 0 {
                        // case 3
                        false
                    } else {
                        // case 4
                        is_in_range_wrapped1(
                            self.recv.next,
                            self.recv.next.wrapping_add(recv_window),
                            seg_seq,
                        ) || is_in_range_wrapped1(
                            self.recv.next,
                            self.recv.next.wrapping_add(recv_window),
                            seg_seq.wrapping_add(seg_len).wrapping_sub(1),
                        )
                    }
                };

                // todo If the RCV.WND is zero, no segments will be acceptable,
                //  but special allowance should be made to accept valid ACKs, URGs, and RSTs.

                // send an ACK for unacceptable segments if the RST bit is off
                if !seg_seq_acceptable {
                    tracing::trace!(
                        "Unacceptable ACK, SEG.SEQ: {} SEG.LEN: {} RCV.NXT: {} RCV.WND: {}",
                        seg_seq,
                        seg_len,
                        self.recv.next,
                        self.recv.window
                    );
                    if !tcp_header.rst() {
                        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                        self.tcp_header.sequence_number = self.send.next;
                        self.tcp_header.acknowledgment_number = self.recv.next;
                        self.write(device, &[])?;
                    }
                    return Ok(());
                }

                // Second, check the RST bit
                if tcp_header.rst() {
                    match self.state {
                        State::SynReceived if !self.active => {
                            self.state = State::Listen;
                            return Ok(());
                        }
                        State::SynReceived if self.active => {
                            self.state = State::Closed;
                            println!("connection refused");
                            // todo delete TCB
                            return Ok(());
                        }
                        State::Established
                        | State::FinWait1
                        | State::FinWait2
                        | State::CloseWait => {
                            // todo do something associated with the connection abort
                            println!("connection reset");
                            self.state = State::Closed;
                            // todo delete TCB
                            return Ok(());
                        }
                        State::Closing | State::LastAck | State::TimeWait => {
                            self.state = State::Closed;
                            // todo delete TCB
                            return Ok(());
                        }
                        _ => {
                            unreachable!()
                        }
                    }
                }

                // Third, check security, which we ignore for now

                // Fourth, check the SYN bit
                if tcp_header.syn() {
                    return match self.state {
                        State::SynReceived => {
                            if !self.active {
                                self.state = State::Listen;
                            }
                            Ok(())
                        }
                        _ => {
                            // synced state
                            // we follow RFC 793 here for simplicity
                            self.state = State::Closed;
                            println!("connection reset");
                            // todo delete TCB
                            Ok(())
                        }
                    };
                }

                // Fifth, check the ACK field
                // we follow RFC 793 here for simplicity
                if !tcp_header.ack() {
                    return Ok(());
                } else {
                    // SND.UNA < SEG.ACK =< SND.NXT
                    let seg_ack_acceptable =
                        is_in_range_wrapped(self.send.unacknowledged, self.send.next, seg_ack);

                    // todo maybe we should send a reset if the ack is not acceptable since we are in a synced state RFC 9293 3.5.2.3

                    match self.state {
                        State::SynReceived => {
                            if seg_ack_acceptable {
                                self.state = State::Established;
                                // SND.WND <- SEG.WND
                                // SND.WL1 <- SEG.SEQ
                                // SND.WL2 <- SEG.ACK
                                self.send.window = tcp_header.window_size();
                                self.send.wl1 = seg_seq;
                                self.send.wl2 = seg_ack;
                                //test active close todo delete this
                                {
                                    self.tcp_header.fin = true;
                                    self.tcp_header.sequence_number = self.send.next;
                                    self.tcp_header.acknowledgment_number = self.recv.next;
                                    self.write(device, &[])?;
                                    self.state = State::FinWait1;
                                }
                            } else {
                                // <SEQ=SEG.ACK><CTL=RST>
                                self.tcp_header.ack = false;
                                self.send_reset(device, seg_ack, 0)?;
                                return Ok(());
                            }
                        }
                        State::Established
                        | State::FinWait1
                        | State::FinWait2
                        | State::CloseWait
                        | State::Closing => {
                            if seg_ack_acceptable {
                                // set SND.UNA <- SEG.ACK.
                                self.send.unacknowledged = seg_ack;
                            } else {
                                //  todo these cmp may be incorrect because of wraparound
                                if seg_ack < self.send.unacknowledged {
                                    //  If the ACK is a duplicate (SEG.ACK =< SND.UNA), it
                                    //  can be ignored.
                                } else if seg_ack > self.send.next {
                                    //  If the ACK acks something not yet sent
                                    //  (SEG.ACK > SND.NXT), then send an ACK, drop the
                                    //  segment, and return.
                                    // todo is this correct?
                                    //  <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                                    self.tcp_header.sequence_number = self.send.next;
                                    self.tcp_header.acknowledgment_number = self.recv.next;
                                    self.write(device, &[])?;
                                    return Ok(());
                                }
                            }

                            // SND.UNA =< SEG.ACK =< SND.NXT
                            if is_in_range_wrapped2(
                                self.send.unacknowledged,
                                self.send.next,
                                seg_ack,
                            ) {
                                // the send window should be updated
                                // prevent using old segments to update the window
                                // SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)
                                // todo these cmp may be incorrect because of wraparound
                                if self.send.wl1 < seg_seq
                                    || (self.send.wl1 == seg_seq && self.send.wl2 <= seg_ack)
                                {
                                    // SND.WND <- SEG.WND
                                    // SND.WL1 <- SEG.SEQ
                                    // SND.WL2 <- SEG.ACK
                                    self.send.window = tcp_header.window_size();
                                    self.send.wl1 = seg_seq;
                                    self.send.wl2 = seg_ack;
                                }
                            }

                            match self.state {
                                State::FinWait1 => {
                                    if seg_seq_acceptable {
                                        self.state = State::FinWait2;
                                    }
                                }
                                State::FinWait2 => {
                                    // if the retransmission queue is empty, the user's CLOSE can be acknowledged ("ok") but do not delete the TCB.
                                }
                                State::Closing => {
                                    if seg_ack_acceptable {
                                        self.state = State::TimeWait;
                                    }
                                }
                                _ => {}
                            }
                        }
                        State::LastAck => {
                            // The only thing that can arrive in this state is an
                            // acknowledgment of our FIN.
                            if seg_ack_acceptable {
                                self.state = State::Closed;
                                // todo delete TCB
                                return Ok(());
                            }
                        }
                        State::TimeWait => {
                            // The only thing that can arrive in this state is a
                            // retransmission of the remote FIN.
                            // Acknowledge it, and restart the 2 MSL timeout.
                            if seg_ack_acceptable {
                                // todo is this ack correct?
                                self.tcp_header.sequence_number = self.send.next;
                                self.tcp_header.acknowledgment_number = self.recv.next;
                                self.write(device, &[])?;
                                // todo restart the 2 MSL timeout
                            }
                        }
                        _ => {
                            unreachable!()
                        }
                    }
                }

                // Sixth, check the URG bit, which we ignore for now

                // todo Seventh, process the segment text

                // Eighth, check the FIN bit

                if tcp_header.fin() {
                    println!("connection closing");
                    // advance RCV.NXT over the FIN, and send an acknowledgment for the FIN.
                    self.recv.next = self.recv.next.wrapping_add(1);
                    self.tcp_header.sequence_number = self.send.next;
                    self.tcp_header.acknowledgment_number = self.recv.next;
                    self.write(device, &[])?;

                    match self.state {
                        State::SynReceived | State::Established => {
                            self.state = State::CloseWait;

                            // for passive close test todo this should be moved to the close call
                            // {
                            //     // send a FIN
                            //     self.tcp_header.fin = true;
                            //     self.tcp_header.sequence_number = self.send.next;
                            //     self.tcp_header.acknowledgment_number = self.recv.next;
                            //     self.write(device, &[])?;
                            //     // enter LAST-ACK
                            //     self.state = State::LastAck;
                            // }
                        }
                        State::FinWait1 => {
                            // If our FIN has been ACKed
                            // todo is this correct?
                            if self.send.unacknowledged == seg_ack {
                                self.state = State::TimeWait;
                            } else {
                                self.state = State::Closing;
                            }
                        }
                        State::FinWait2 => {
                            self.state = State::TimeWait;
                        }
                        State::CloseWait | State::Closing | State::LastAck => {}
                        State::TimeWait => {
                            // todo restart the 2 MSL timeout
                        }
                        _ => {
                            unreachable!()
                        }
                    }
                }
            }
        }

        tracing::trace!("new state: {:?}", self.state);
        Ok(())
    }

    fn send_reset(
        &mut self,
        device: &mut tun::platform::Device,
        seq: u32,
        ack: u32,
    ) -> anyhow::Result<()> {
        self.tcp_header.rst = true;
        self.tcp_header.sequence_number = seq;
        self.tcp_header.acknowledgment_number = ack;

        self.write(device, &[])?;
        Ok(())
    }

    fn write(
        &mut self,
        device: &mut tun::platform::Device,
        payload: &[u8],
    ) -> anyhow::Result<usize> {
        // todo this is not zero copy
        let mut buf = [0u8; 1504]; // this is IP MTU + 4 bytes for the packet info

        let mut unwritten = &mut buf[..];

        let _ = unwritten.write(&[0, 0, 0, 2])?;

        let ip_header_len = self.ip_header.header_len();
        let tcp_header_len = self.tcp_header.header_len() as usize;

        let size = min(
            unwritten.len() - ip_header_len,
            payload.len() + tcp_header_len,
        );

        self.ip_header
            .set_payload_len(size)
            .context("cannot set ip payload len")?;

        self.tcp_header.checksum = self
            .tcp_header
            .calc_checksum_ipv4(&self.ip_header, &[])
            .context("failed to calc checksum")?;

        self.ip_header.write(&mut unwritten)?;
        self.tcp_header.write(&mut unwritten)?;

        let payload_written = unwritten.write(payload)?;

        let unwritten_len = unwritten.len();
        let written_len = buf.len() - unwritten_len;

        tracing::trace!("raw buf written to device: {:02x?}", &buf[..written_len]);

        device.write_all(&buf[..written_len])?;

        // When the sender creates a segment and transmits it the sender advances
        // SND.NXT.
        self.send.next = self.send.next.wrapping_add(payload_written as u32);

        // set flags to default after sending
        if self.tcp_header.syn {
            self.send.next = self.send.next.wrapping_add(1);
            self.tcp_header.syn = false;
        }

        if self.tcp_header.fin {
            self.send.next = self.send.next.wrapping_add(1);
            self.tcp_header.fin = false;
        }

        self.tcp_header.ack = true;
        self.tcp_header.rst = false;

        Ok(payload_written)
    }
}
