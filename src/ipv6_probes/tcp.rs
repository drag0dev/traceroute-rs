use crate::{
    print::{Probe, ProbePrinter},
    Command
};
use anyhow::{anyhow, Context, Result};
use pnet::{
    packet::{
        icmpv6::{Icmpv6Packet, Icmpv6Types},
        ip::IpNextHeaderProtocols::{Icmpv6, Tcp},
        tcp::{ipv6_checksum, MutableTcpPacket}, Packet
    },
    transport::{icmpv6_packet_iter, tcp_packet_iter, transport_channel}
};
use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::{
        atomic::{
            AtomicBool,
            AtomicU16,
            Ordering,
        },
        mpsc,
        Arc
    },
    thread,
    time::{Duration, Instant}
};
use pnet::transport::TransportChannelType::Layer4;

const TCP_BUFFER_SIZE: usize = 8;
const SOURCE_PORT: u16 = 76;
const POLLING_TIMEOUT: Duration = Duration::from_millis(5);

pub fn tcp_probe(address: IpAddr, args: Command) -> Result<()> {
    let destination_port = args.port.unwrap_or(80);
    let source_address = discover_source_ip(address, SOURCE_PORT)
        .context("no source ip")?;

    let tcp_protocol = match address {
        IpAddr::V4(_) => unreachable!("passing ipv4 address to ipv6 probe"),
        IpAddr::V6(_) => pnet::transport::TransportProtocol::Ipv6(Tcp),
    };
    let icmp_protocol = match address {
        IpAddr::V4(_) => unreachable!("passing ipv4 address to ipv6 probe"),
        IpAddr::V6(_) => pnet::transport::TransportProtocol::Ipv6(Icmpv6),
    };

    let mut res_printer = ProbePrinter::new();

    let (mut tx, tcp_rx) = transport_channel(4096, Layer4(tcp_protocol))
        .context("creating tcp transport channel")?;
    let (_, icmp_rx) = transport_channel(4096, Layer4(icmp_protocol))
        .context("creating icmp transport channel")?;

    let timeout = Duration::from_millis(args.timeout);
    let atomic_ttl = Arc::new(AtomicU16::new(0));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let (res_tx, res_rx) = mpsc::sync_channel::<(Probe, bool)>(1);

    let icmp_handle = {
        let atomic_ttl = atomic_ttl.clone();
        let stop_flag = stop_flag.clone();
        let res_tx = res_tx.clone();
        thread::spawn(move || {
            let mut icmp_rx = icmp_rx;
            let mut res_icmp_iter = icmpv6_packet_iter(&mut icmp_rx);
            let mut ttl;
            loop {
                if stop_flag.load(Ordering::Relaxed) { break }

                if let Ok(Some((icmp_packet, address))) = res_icmp_iter.next_with_timeout(POLLING_TIMEOUT) {
                    ttl = atomic_ttl.load(Ordering::SeqCst);

                    let res_ports = extract_tcp_header_from_icmp_reply(&icmp_packet);
                    if let Some((res_source_port, res_destination_port)) = res_ports {
                        if res_source_port == SOURCE_PORT + ttl && res_destination_port == destination_port {
                            match icmp_packet.get_icmpv6_type() {
                                Icmpv6Types::TimeExceeded => {
                                    let probe = Probe::Response(address, Duration::ZERO);
                                    let _ = res_tx.try_send((probe, false));
                                },
                                Icmpv6Types::DestinationUnreachable => {
                                    let probe = Probe::Response(address, Duration::ZERO);
                                    let _ = res_tx.try_send((probe, true));
                                },
                                _ => {}
                            }
                        }
                    }
                }
            }
        })
    };

    let tcp_handle = {
        let atomic_ttl = atomic_ttl.clone();
        let stop_flag = stop_flag.clone();
        let res_tx = res_tx.clone();
        thread::spawn(move || {
            let mut tcp_rx = tcp_rx;
            let mut res_tcp_iter = tcp_packet_iter(&mut tcp_rx);
            let mut ttl;
            loop {
                if stop_flag.load(Ordering::Acquire) { break }
                if let Ok(Some((tcp_packet, address))) = res_tcp_iter.next_with_timeout(POLLING_TIMEOUT) {
                    ttl = atomic_ttl.load(Ordering::SeqCst);
                    if tcp_packet.get_destination() == SOURCE_PORT + ttl && tcp_packet.get_source() == destination_port {
                        let tcp_flags = tcp_packet.get_flags();
                        // RST (0x04) or SYN+ACK (0x12) expected responses from the final hop
                        if ((tcp_flags & 0x04) != 0x0) || ((tcp_flags & 0x12) != 0x0) {
                            let probe = Probe::Response(address, Duration::ZERO);
                            let _ = res_tx.try_send((probe, true));
                        }
                    }
                }
            }
        })
    };

    for ttl in 1..=args.hops {
        let mut target_hit = false;
        for _ in 0..args.probes {
            tx.set_ttl(ttl as u8)
                .context("setting ttl")?;

            let mut tcp_buffer = [0u8; TCP_BUFFER_SIZE + 20];
            let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer)
                .context("creating tcp packet")?;
            tcp_packet.set_source(SOURCE_PORT + (ttl as u16));
            tcp_packet.set_destination(destination_port);
            tcp_packet.set_sequence(ttl as u32);
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_flags(0x02); // SYN flag
            tcp_packet.set_window(5840);
            tcp_packet.set_checksum(0);
            let checksum = match address {
                IpAddr::V4(_) => { unreachable!("passing ipv6 address to ipv4 probe") },
                IpAddr::V6(addr) => {
                    let source_address = match source_address {
                        IpAddr::V4(_) => unreachable!("mismatch between source and destination ip version"),
                        IpAddr::V6(addr) => addr,
                    };
                    ipv6_checksum(
                        &tcp_packet.to_immutable(),
                        &source_address,
                        &addr,
                    )
                },
            };
            tcp_packet.set_checksum(checksum);

            // drain everything from the channel
            while let Ok(_) = res_rx.try_recv() { }

            atomic_ttl.store(ttl as u16, Ordering::SeqCst);
            tx.send_to(tcp_packet, address)
                .context("sending tcp packet")?;

            let start_time = Instant::now();

            let mut got_response = false;
            if let Ok((probe, end)) = res_rx.recv_timeout(timeout) {
                got_response = true;
                let probe = match probe {
                    Probe::Unreachable => unreachable!(),
                    Probe::Response(addr, _) => {
                        Probe::Response(addr, start_time.elapsed())
                    }
                };
                target_hit = end;
                res_printer.push_hop(probe);
            }


            if !got_response { res_printer.push_hop(Probe::Unreachable); }
        }
        if target_hit { break }
        res_printer.next_ttl();
    }

    stop_flag.swap(true, Ordering::Relaxed);
    let _ = icmp_handle.join();
    let _ = tcp_handle.join();

    Ok(())
}

fn extract_tcp_header_from_icmp_reply<'a>(icmp_packet: &'a Icmpv6Packet) -> Option<(u16, u16)> {
    let icmp_payload = icmp_packet.payload();

    // +4 because there is four bytes of padding added to the beginning of the payload
    let ip_header_len = 40 + 4;

    // +4 for source and destination port in the tcp header
    if icmp_payload.len() < ip_header_len + 4 { return None; }

    let tcp_header_start = ip_header_len;
    let source_port = u16::from_be_bytes([icmp_payload[tcp_header_start], icmp_payload[tcp_header_start+1]]);
    let destination_port = u16::from_be_bytes([icmp_payload[tcp_header_start+2], icmp_payload[tcp_header_start+3]]);

    Some((source_port, destination_port))
}

fn discover_source_ip(destination: IpAddr, port: u16) -> Result<IpAddr> {
    let socket = UdpSocket::bind("[::]:0").context("failed to bind UDP socket for IPv6")?;

    let destination_socket = SocketAddr::new(destination, port);
    if let Err(e) = socket.connect(destination_socket) {
        let e = anyhow!("failed to connect to destination: {}", e);
        return Err(e);
    }

    if let Ok(local_addr) = socket.local_addr() { Ok(local_addr.ip()) } else { Err(anyhow!("no local address")) }
}
