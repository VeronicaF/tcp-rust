use crate::tcp::{Connection, Quad};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::Read;
use tun::Device;

extern crate tun;

mod tcp;
mod utils;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let mut connections: HashMap<Quad, Connection> = HashMap::default();

    let mut config = tun::Configuration::default();
    config
        .address((192, 168, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    #[cfg(target_os = "linux")]
    {
        config.packet_information(true);
    }

    let mut device = tun::create(&config)?;

    let dev_name = device.name()?;

    #[cfg(target_os = "macos")]
    {
        // Add static route on Mac OS
        // route add -net 192.168.0.0/24 -interface utun4
        let mut handler = std::process::Command::new("route")
            .arg("-nv")
            .arg("add")
            .arg("-net")
            .arg("192.168.0.0/24")
            .arg("-interface")
            .arg(&dev_name)
            .stdout(std::process::Stdio::null())
            .spawn()?;

        handler.wait()?;
    }

    tracing::info!("Listening on {:?}", dev_name);

    let mut buf = [0; 4096];

    while let Ok(amount) = device.read(&mut buf) {
        tracing::trace!("Read {} bytes", amount);
        let raw_ether = &buf[..amount];

        tracing::trace!("raw_ether: {:02x?}", raw_ether);

        let packet_info_len = 4;

        let ether_header = &raw_ether[..4];
        let proto_family = u32::from_be_bytes([
            ether_header[0],
            ether_header[1],
            ether_header[2],
            ether_header[3],
        ]);
        tracing::trace!("ether_header: {:?}", ether_header);
        // ignore non-ipv4 packets`
        if proto_family != 2 {
            tracing::trace!("Not an ipv4 packet but {}", proto_family);
            continue;
        }

        let raw_ip = &raw_ether[packet_info_len..];

        let ip_header = match etherparse::Ipv4HeaderSlice::from_slice(raw_ip) {
            Ok(ip_header) => ip_header,

            Err(e) => {
                tracing::warn!("Malformed ipv4 packet: {}", e);
                continue;
            }
        };

        // ignore non-tcp packets
        if ip_header.protocol() != 6 {
            tracing::trace!("Not a tcp packet");
            continue;
        }

        let ip_header_len = ip_header.slice().len();

        let raw_tcp = &raw_ip[ip_header_len..];

        let tcp_header = match etherparse::TcpHeaderSlice::from_slice(raw_tcp) {
            Ok(tcp_header) => tcp_header,

            Err(e) => {
                tracing::warn!("Malformed tcp packet: {}", e);
                continue;
            }
        };

        let tcp_header_len = tcp_header.slice().len();

        match connections.entry(Quad {
            src: (ip_header.source_addr(), tcp_header.source_port()),
            dst: (ip_header.destination_addr(), tcp_header.destination_port()),
        }) {
            Entry::Occupied(mut entry) => {
                let connection = entry.get_mut();
                match connection.on_packet(
                    &mut device,
                    &ip_header,
                    &tcp_header,
                    &raw_tcp[tcp_header_len..],
                ) {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::warn!("Error while processing packet: {}", e);
                    }
                }
            }
            Entry::Vacant(entry) => {
                match Connection::accept(&mut device, &ip_header, &tcp_header) {
                    Ok(Some(connection)) => {
                        entry.insert(connection);
                    }
                    Ok(None) => {
                        tracing::trace!("Connection not established yet for {:?}", entry.key());
                    }
                    Err(e) => {
                        tracing::warn!("Error while accepting connection: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}
