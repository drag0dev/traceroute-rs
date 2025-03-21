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
        println!("Malformed input, missing v4 or v6 swtich");
        return;
    }

    let mut tracerouting_method_count = args.icmp as usize;
    tracerouting_method_count += args.udp as usize;
    tracerouting_method_count += args.tcp as usize;
    if tracerouting_method_count != 1 {
        println!("Malformed input, only one method of tracerouting must be selected");
        return;
    }

    let addr = match args.v4 {
        true => {
            let addr = Ipv4Addr::from_str(&args.address);
            match addr {
                Ok(addr) => IpAddr::V4(addr),
                Err(_e) => {
                    println!("Invalid IPv4 address, exiting...");
                    return;
                }
            }
        },
        false => {
            let addr = Ipv6Addr::from_str(&args.address);
            match addr {
                Ok(addr) => IpAddr::V6(addr),
                Err(_e) => {
                    println!("Invalid IPv6 address, exiting...");
                    return;
                }
            }
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
