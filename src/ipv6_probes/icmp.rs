use crate::print::{Probe, ProbePrinter};
use crate::Command;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use pnet::packet::icmpv6::echo_reply::EchoReplyPacket;
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{icmpv6_packet_iter, transport_channel};
use pnet::transport::TransportChannelType::Layer4;

const ICMP_BUFFER_SIZE: usize = 64;

pub fn icmp_probe(address: IpAddr, args: Command) -> Result<()> {
    let protocol = match address {
        IpAddr::V4(_) => unreachable!("passing ipv4 address to ipv6 probe"),
        IpAddr::V6(_) => pnet::transport::TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6),
    };

    let mut res_printer = ProbePrinter::new();

    let (mut tx, mut rx) = transport_channel(4096, Layer4(protocol))
        .context("creating transport channel")?;

    let identifier: u16 = std::process::id() as u16;
    let timeout = Duration::from_millis(args.timeout);
    let mut res_icmp_iter = icmpv6_packet_iter(&mut rx);

    for ttl in 1..=args.hops {
        let mut target_hit = false;
        for _ in 0..args.probes {
            tx.set_ttl(ttl as u8)
                .context("setting ttl")?;
            let mut icmp_buffer = [0u8; ICMP_BUFFER_SIZE];

            let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer)
                .context("creating icmp packet")?;
            icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
            icmp_packet.set_identifier(identifier);
            icmp_packet.set_sequence_number(ttl as u16);
            let checksum = pnet::util::checksum(icmp_packet.packet(), icmp_packet.packet().len());
            icmp_packet.set_checksum(checksum);

            tx.send_to(icmp_packet, address)
                .context("sending icmp packet")?;

            let start_time = Instant::now();

            let mut got_response = false;
            while start_time.elapsed() < timeout {
                if let Ok(Some((icmp_packet, address))) = res_icmp_iter.next_with_timeout(timeout) {
                    match icmp_packet.get_icmpv6_type() {
                        Icmpv6Types::EchoReply => {
                            if let Some(reply_packet) = EchoReplyPacket::new(icmp_packet.packet()) {
                                if reply_packet.get_identifier() == identifier &&
                                    reply_packet.get_sequence_number() == ttl as u16 {
                                        res_printer.push_hop(Probe::Response(address, start_time.elapsed()));
                                        got_response = true;
                                        target_hit = true;
                                        break;
                                }
                            }
                        },
                        Icmpv6Types::TimeExceeded => {
                            if let Some((res_identifier, res_sequence)) = extract_original_icmp_info_from_reply(&icmp_packet) {
                                if res_identifier == identifier && res_sequence == ttl as u16 {
                                    res_printer.push_hop(Probe::Response(address, start_time.elapsed()));
                                    got_response = true;
                                    break;
                                }
                            }
                        },
                        Icmpv6Types::DestinationUnreachable => {
                            if let Some((res_identifier, res_sequence)) = extract_original_icmp_info_from_reply(&icmp_packet) {
                                if res_identifier == identifier && res_sequence == ttl as u16 {
                                    res_printer.push_hop(Probe::Unreachable);
                                    got_response = true;
                                    target_hit = true;
                                    break;
                                }
                            }
                        },
                        _ => {}
                    }
                }
            }
            if !got_response { res_printer.push_hop(Probe::Unreachable); }
        }
        if target_hit { break }
        res_printer.next_ttl();
    }

    Ok(())
}

fn extract_original_icmp_info_from_reply(icmp_packet: &Icmpv6Packet) -> Option<(u16, u16)> {
    let icmp_payload = icmp_packet.payload();

    // +4 because there is four bytes of padding added to the beginning of the payload
    let ip_header_len = 40 + 4;

    if icmp_payload.len() < ip_header_len + 8 { return None; }

    let icmp_header_start = ip_header_len;

    let identifier = u16::from_be_bytes([
        icmp_payload[icmp_header_start + 4],
        icmp_payload[icmp_header_start + 5]
    ]);

    let sequence = u16::from_be_bytes([
        icmp_payload[icmp_header_start + 6],
        icmp_payload[icmp_header_start + 7]
    ]);

    Some((identifier, sequence))
}
