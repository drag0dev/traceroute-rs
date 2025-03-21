use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr
};
use clap::Parser;

mod command;
mod ipv4_probes;
mod ipv6_probes;
mod print;
use command::Command;
use ipv4_probes::icmp_probe;
use ipv4_probes::udp_probe;
use ipv4_probes::tcp_probe;
use ipv6_probes::icmp_probev6;
use ipv6_probes::udp_probev6;
use ipv6_probes::tcp_probev6;

fn main() {
    let args = Command::parse();

    if (args.v4 && args.v6) || (!args.v4 && !args.v6) {
        println!("Malformed input, missing v4 or v6 switch");
        return;
    }

    let mut tracerouting_method_count = args.icmp as usize;
    tracerouting_method_count += args.udp as usize;
    tracerouting_method_count += args.tcp as usize;
    if tracerouting_method_count > 1 {
        println!("Only one method for tracerouting must be selected");
        return;
    } else if tracerouting_method_count == 0 {
        println!("Method for tracerouting has to be specified");
        return;
    }

    let addr = match args.v4 {
        true => {
            let addr = Ipv4Addr::from_str(&args.address);
            match addr {
                Ok(addr) => Some(IpAddr::V4(addr)),
                Err(_e) => { None }
            }
        },
        false => {
            let addr = Ipv6Addr::from_str(&args.address);
            match addr {
                Ok(addr) => Some(IpAddr::V6(addr)),
                Err(_e) => { None }
            }
        }
    };

    let addr = if let Some(addr) = addr {
        addr
    } else {
        let ips = dns_lookup::lookup_host(&args.address);
        if let Err(e) = ips {
            println!("Error resolving domain: {}", e);
            return;
        }
        let ips = ips.unwrap();

        let valid_ips: Vec<IpAddr> = ips.into_iter().filter(|ip| match ip {
            IpAddr::V4(_) => {args.v4}
            IpAddr::V6(_) => {args.v6}
        }).collect();

        if let Some(addr) = valid_ips.first() {
            *addr
        } else {
            println!("Cannot resolve the provided hostname");
            return;
        }
    };

    let e = if args.v4 {
        if args.icmp { icmp_probe(addr, args) }
        else if args.udp { udp_probe(addr, args) }
        else if args.tcp { tcp_probe(addr, args) }
        else { unreachable!("no tracerouting method selected"); }
    } else {
        if args.icmp { icmp_probev6(addr, args) }
        else if args.udp { udp_probev6(addr, args) }
        else if args.tcp { tcp_probev6(addr, args) }
        else { unreachable!("no tracerouting method selected"); }
    };

    if let Err(e) = e {
        println!("error: {}", e);
        for (i, small_e) in e.chain().enumerate().skip(1) {
            println!("{}{small_e}", "\t".repeat(i));
        }
    }
}
