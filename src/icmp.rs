use crate::Command;
use std::net::IpAddr;
use std::time::Duration;

use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, icmp_packet_iter};
use pnet::transport::TransportChannelType::Layer4;

const ICMP_BUFFER_SIZE: usize = 64;

pub fn icmp_ping(address: IpAddr, args: Command) {
    let protocol = match address {
        IpAddr::V4(_) => pnet::transport::TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp),
        IpAddr::V6(_) => pnet::transport::TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6),
    };

    let (mut tx, mut rx) = transport_channel(4096, Layer4(protocol))
        .expect("creating transport channel");

    let identifier: u16 = std::process::id() as u16 & 0xFFFF;
    let timeout = Duration::from_millis(args.timeout);
    let mut res_icmp_iter = icmp_packet_iter(&mut rx);

    for ttl in 1..args.hops {
        tx.set_ttl(ttl as u8)
            .expect("setting ttl");
        let mut icmp_buffer = [0u8; ICMP_BUFFER_SIZE];

        let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_identifier(identifier);
        icmp_packet.set_sequence_number(ttl as u16);
        let checksum = pnet::util::checksum(icmp_packet.packet(), icmp_packet.packet().len());
        icmp_packet.set_checksum(checksum);

        tx.send_to(icmp_packet, address)
            .expect("sending icmp packet");

        let mut response_address = None;

        if let Ok(Some((packet, address))) = res_icmp_iter.next_with_timeout(timeout) {
            if let Some(icmp_packet) = IcmpPacket::new(packet.packet()) {
                match icmp_packet.get_icmp_type() {
                    IcmpTypes::EchoReply => {
                        println!("Hop: {}: {}", ttl, address);
                        return;
                    },
                    IcmpTypes::TimeExceeded => {
                        response_address = Some(address);
                    },
                    IcmpTypes::DestinationUnreachable => {
                        println!("Destination unreachable: {}", address);
                    },
                    _ => {}
                }
            }
        }

        match response_address {
            Some(response_address) => println!("Hop: {}: {}", ttl, response_address),
            None => println!("Hop: {}: No response", ttl),
        }
    }
}
