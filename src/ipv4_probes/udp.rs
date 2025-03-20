use crate::print::{Probe, ProbePrinter};
use crate::Command;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use anyhow::{Context, Result};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols::{Udp, Icmp};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, transport_channel};
use pnet::transport::TransportChannelType::Layer4;

const UDP_BUFFER_SIZE: usize = 8;
const SOURCE_PORT: u16 = 33434;

pub fn udp_probe(address: IpAddr, args: Command) -> Result<()> {
    let destination_port = args.port.unwrap_or(33434);
    let udp_protocol = match address {
        IpAddr::V4(_) => pnet::transport::TransportProtocol::Ipv4(Udp),
        IpAddr::V6(_) => unreachable!("passing ipv6 address to ipv4 probe")
    };
    let icmp_protocol = match address {
        IpAddr::V4(_) => pnet::transport::TransportProtocol::Ipv4(Icmp),
        IpAddr::V6(_) => unreachable!("passing ipv6 address to ipv4 probe")
    };

    let mut res_printer = ProbePrinter::new();

    let (mut tx, _) = transport_channel(4096, Layer4(udp_protocol))
        .context("creating udp transport channel")?;
    let (_, mut rx) = transport_channel(4096, Layer4(icmp_protocol))
        .context("creating icmp transport channel")?;

    let timeout = Duration::from_millis(args.timeout);
    let mut res_icmp_iter = icmp_packet_iter(&mut rx);

    for ttl in 1..=args.hops {
        let mut target_hit = false;
        for _ in 0..args.probes {
            tx.set_ttl(ttl as u8)
                .context("setting ttl")?;
            let mut udp_buffer = [0u8; UDP_BUFFER_SIZE + 8];

            let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer)
                .context("creating udp packet")?;
            udp_packet.set_source(SOURCE_PORT + (ttl as u16));
            udp_packet.set_destination(destination_port);
            udp_packet.set_length(UDP_BUFFER_SIZE as u16 + 8);
            udp_packet.set_payload(&[0u8; 8]);

            tx.send_to(udp_packet, address)
                .context("sending udp packet")?;

            let start_time = Instant::now();

            let mut got_response = false;
            while start_time.elapsed() < timeout {
                if let Ok(Some((icmp_packet, address))) = res_icmp_iter.next_with_timeout(timeout) {
                    let resp_source_port = extract_udp_source_from_icmp_reply(&icmp_packet);
                    if let Some(resp_source_port) = resp_source_port {
                        if resp_source_port == SOURCE_PORT + (ttl as u16) {
                            match icmp_packet.get_icmp_type() {
                                IcmpTypes::TimeExceeded => {
                                    res_printer.push_hop(Probe::Response(address, start_time.elapsed()));
                                    got_response = true;
                                    break;
                                },
                                IcmpTypes::DestinationUnreachable => {
                                    res_printer.push_hop(Probe::Response(address, start_time.elapsed()));
                                    target_hit = true;
                                    got_response = true;
                                    break;
                                },
                                _ => {}
                            }
                        }
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

fn extract_udp_source_from_icmp_reply<'a>(icmp_packet: &'a IcmpPacket) -> Option<u16> {
    let icmp_payload = icmp_packet.payload();

    // +4 because there is four bytes of padding added to the beginning of the payload
    let ip_header_len = 20 + 4;

    if icmp_payload.len() < ip_header_len + 8 { return None; }

    let udp_header_start = ip_header_len;
    let udp_header_end = udp_header_start + 8;
    let udp_header = &icmp_payload[udp_header_start..udp_header_end];

    if let Some(header) = UdpPacket::new(udp_header) { Some(header.get_source()) } else { None }
}
