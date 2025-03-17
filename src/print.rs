use std::{
    net::IpAddr,
    time::Duration
};
use dns_lookup::lookup_addr;

pub enum Probe {
    Unreachable,
    Response(IpAddr, Duration)
}

pub struct ProbePrinter {
    ttl: u8,
    ttl_printed: bool,
}

impl ProbePrinter {
    pub fn new() -> Self {
        ProbePrinter { ttl: 1, ttl_printed: false }
    }

    pub fn push_hop(&mut self, hop: Probe) {
        let mut msg = String::new();
        if self.ttl_printed { msg.push_str(&format!("    ")); }
        else { msg.push_str(&format!("{:3} ", self.ttl)); }

        match hop {
            Probe::Unreachable => { msg.push('*'); },
            Probe::Response(address, duration) => {
                let hostname = lookup_addr(&address).map_or(None, |address| Some(address));
                if let Some(hostname) = hostname { msg.push_str(&format!("{hostname} ")); }
                else { msg.push_str(&format!("{address} ")); }
                msg.push_str(&format!("({address}) "));
                msg.push_str(&format!("{} ms", duration.as_millis()));
            }
        }
        println!("{msg}");
        self.ttl_printed = true;
    }

    pub fn next_ttl(&mut self) {
        self.ttl += 1;
        self.ttl_printed = false;
    }
}
