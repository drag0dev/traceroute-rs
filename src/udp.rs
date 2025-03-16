use crate::Command;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols::{self, Udp};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, transport_channel};
use pnet::transport::TransportChannelType::Layer4;

const UDP_BUFFER_SIZE: usize = 8;
const SOURCE_PORT: u16 = 33434;

pub fn udp_probe(address: IpAddr, args: Command) {
    let destination_port = args.port.unwrap_or(33434);
    let udp_protocol = match address {
        IpAddr::V4(_) => pnet::transport::TransportProtocol::Ipv4(Udp),
        IpAddr::V6(_) => pnet::transport::TransportProtocol::Ipv4(Udp),
    };
    let icmp_protocol = match address {
        IpAddr::V4(_) => pnet::transport::TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp),
        IpAddr::V6(_) => pnet::transport::TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6),
    };

    let (mut tx, _) = transport_channel(4096, Layer4(udp_protocol))
        .expect("creating udp transport channel");
    let (_, mut rx) = transport_channel(4096, Layer4(icmp_protocol))
        .expect("creating icmp transport channel");

    let timeout = Duration::from_millis(args.timeout);
    let mut res_icmp_iter = icmp_packet_iter(&mut rx);

    for ttl in 1..args.hops {
        tx.set_ttl(ttl as u8)
            .expect("setting ttl");
        let mut udp_buffer = [0u8; UDP_BUFFER_SIZE + 8];

        let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
        udp_packet.set_source(SOURCE_PORT + (ttl as u16));
        udp_packet.set_destination(destination_port);
        udp_packet.set_length(UDP_BUFFER_SIZE as u16 + 8);
        udp_packet.set_payload(&[0u8; 8]);

        tx.send_to(udp_packet, address)
            .expect("sending udp packet");

        let mut response_address = None;
        let start_time = Instant::now();


        while start_time.elapsed() < timeout {
            if let Ok(Some((packet, address))) = res_icmp_iter.next_with_timeout(timeout) {
                if let Some(icmp_packet) = IcmpPacket::new(packet.packet()) {
                    let udp_response = extract_udp_header_from_icmp_reply(&icmp_packet, args.v6).unwrap();
                    if udp_response.get_source() == SOURCE_PORT + (ttl as u16) {
                        match icmp_packet.get_icmp_type() {
                            IcmpTypes::TimeExceeded => {
                                response_address = Some(address);
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

        match response_address {
            Some(response_address) => println!("Hop: {}: {}", ttl, response_address),
            None => println!("Hop: {}: No response", ttl),
        }
    }
}

fn extract_udp_header_from_icmp_reply<'a>(icmp_packet: &'a IcmpPacket, is_ipv6: bool) -> Option<UdpPacket<'a>> {
    let icmp_payload = icmp_packet.payload();

    // +4 because there is four bytes of padding added to the beginning of the payload
    let ip_header_len = if is_ipv6 { 40 } else { 20 } + 4;

    if icmp_payload.len() < ip_header_len + 8 { return None; }

    let udp_header_start = ip_header_len;
    let udp_header_end = udp_header_start + 8;
    let udp_header = &icmp_payload[udp_header_start..udp_header_end];

    UdpPacket::new(udp_header)
}
