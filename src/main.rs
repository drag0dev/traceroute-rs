use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, str::FromStr};
use clap::Parser;

mod command;
mod icmp;
use command::Command;
use icmp::icmp_ping;

fn main() {
    let args = Command::parse();

    if (args.v4 && args.v6) || (!args.v4 && !args.v6) {
        println!("Malformed input, missing v4 or v6 swtich");
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
                    println!("Invalid IPv4 address, exiting...");
                    return;
                }
            }
        }
    };

    icmp_ping(addr, args);
}
