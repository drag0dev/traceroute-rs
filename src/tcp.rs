use crate::Command;
use pnet::{
    packet::{
        icmp::{IcmpPacket, IcmpTypes},
        ip::IpNextHeaderProtocols,
        tcp::{ipv4_checksum, ipv6_checksum, MutableTcpPacket, TcpPacket}, Packet},
    transport::{icmp_packet_iter, tcp_packet_iter, transport_channel}
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    time::{Duration, Instant}
};
use pnet::transport::TransportChannelType::Layer4;

const TCP_BUFFER_SIZE: usize = 8;
const SOURCE_PORT: u16 = 76;

pub fn tcp_probe(address: IpAddr, args: Command) {
    let destination_port = args.port.unwrap_or(80);
    let source_address = discover_source_ip(address, SOURCE_PORT)
        .expect("no source ip");

    let tcp_protocol = match address {
        IpAddr::V4(_) => pnet::transport::TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp),
        IpAddr::V6(_) => pnet::transport::TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp),
    };
    let icmp_protocol = match address {
        IpAddr::V4(_) => pnet::transport::TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp),
        IpAddr::V6(_) => pnet::transport::TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6),
    };

    let (mut tx, mut tcp_rx) = transport_channel(4096, Layer4(tcp_protocol))
        .expect("creating tcp transport channel");
    let (_, mut icmp_rx) = transport_channel(4096, Layer4(icmp_protocol))
        .expect("creating icmp transport channel");

    // timeout divided by two as a compromise due to a need to check both icmp and tcp responses
    let timeout = Duration::from_millis(args.timeout/2);
    let mut res_tcp_iter = tcp_packet_iter(&mut tcp_rx);
    let mut res_icmp_iter = icmp_packet_iter(&mut icmp_rx);

    for ttl in 1..args.hops {
        tx.set_ttl(ttl as u8)
            .expect("setting ttl");

        let mut tcp_buffer = [0u8; TCP_BUFFER_SIZE + 20];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer)
            .expect("creating tcp packet");
        tcp_packet.set_source(SOURCE_PORT + (ttl as u16));
        tcp_packet.set_destination(destination_port);
        tcp_packet.set_sequence(ttl as u32);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(0x02); // SYN flag
        tcp_packet.set_window(5840);
        tcp_packet.set_checksum(0);
        let checksum = match address {
            IpAddr::V4(addr) => {
                let source_address = match source_address {
                    IpAddr::V4(addr) => addr,
                    IpAddr::V6(_) => unreachable!("mismatch between source and destination ip version"),
                };
                let source_address = Ipv4Addr::from(source_address);
                ipv4_checksum(
                    &tcp_packet.to_immutable(),
                    &source_address,
                    &addr,
                )
            },
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

        tx.send_to(tcp_packet, address)
            .expect("sending tcp packet");

        let mut response_address = None;
        let start_time = Instant::now();

        let mut icmp_received = false;
        while start_time.elapsed() < timeout {
            if let Ok(Some((packet, address))) = res_icmp_iter.next_with_timeout(timeout) {
                if let Some(icmp_packet) = IcmpPacket::new(packet.packet()) {
                    let res_ports = extract_tcp_header_from_icmp_reply(&icmp_packet, args.v6);
                    if let Some((res_source_port, res_destination_port)) = res_ports {
                        if res_source_port == SOURCE_PORT + (ttl as u16) && res_destination_port == destination_port {
                            match icmp_packet.get_icmp_type() {
                                IcmpTypes::TimeExceeded => {
                                    response_address = Some(address);
                                    icmp_received = true;
                                    break;
                                },
                                IcmpTypes::DestinationUnreachable => {
                                    println!("Hop: {}: {}", ttl, address);
                                    return;
                                },
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        if !icmp_received {
            let start_time = Instant::now();
            while start_time.elapsed() < timeout {
                if let Ok(Some((packet, address))) = res_tcp_iter.next_with_timeout(timeout) {
                    if let Some(tcp_packet) = TcpPacket::new(packet.packet()) {
                        if tcp_packet.get_destination() == SOURCE_PORT + (ttl as u16) && tcp_packet.get_source() == destination_port {
                            let tcp_flags = tcp_packet.get_flags();
                            // RST (0x04) or SYN+ACK (0x12) expected responses from the final hop
                            if ((tcp_flags & 0x04) != 0x0) || ((tcp_flags & 0x12) != 0x0) {
                                    println!("Hop: {}: {}", ttl, address);
                                    return
                            }
                        }
                    }
                }
            }
        }
        match response_address {
            Some(response_address) => println!("Hop: {}: {}", ttl, response_address),
            None => println!("Hop: {}: No response", ttl),
        }
    }
}

fn extract_tcp_header_from_icmp_reply<'a>(icmp_packet: &'a IcmpPacket, is_ipv6: bool) -> Option<(u16, u16)> {
    let icmp_payload = icmp_packet.payload();

    // +4 because there is four bytes of padding added to the beginning of the payload
    let ip_header_len = if is_ipv6 { 40 } else { 20 } + 4;

    // +4 for source and destination port in the tcp header
    if icmp_payload.len() < ip_header_len + 4 { return None; }

    let tcp_header_start = ip_header_len;
    let source_port = u16::from_be_bytes([icmp_payload[tcp_header_start], icmp_payload[tcp_header_start+1]]);
    let destination_port = u16::from_be_bytes([icmp_payload[tcp_header_start+2], icmp_payload[tcp_header_start+3]]);

    Some((source_port, destination_port))
}

fn discover_source_ip(destination: IpAddr, port: u16) -> Option<IpAddr> {
    let socket = if destination.is_ipv6() {
        UdpSocket::bind("[::]:0").expect("failed to bind UDP socket for IPv6")
    } else {
        UdpSocket::bind("0.0.0.0:0").expect("failed to bind UDP socket for IPv4")
    };

    let destination_socket = SocketAddr::new(destination, port);
    if let Err(e) = socket.connect(destination_socket) {
        println!("Failed to connect to destination: {}", e);
        return None;
    }

    if let Ok(local_addr) = socket.local_addr() { Some(local_addr.ip()) } else { None }
}
