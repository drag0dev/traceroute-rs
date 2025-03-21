use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "traceroute-rs", version = "1.0", about = "Follow your packet across the internet")]
pub struct Command {

    #[arg(long, help = "Use IPv4")]
    pub v4: bool,

    #[arg(long, help = "Use IPv6")]
    pub v6: bool,

    #[arg(long, default_value_t = 2000, help =  "Timeout in milliseconds per each probe")]
    pub timeout: u64,

    #[arg(long, default_value_t = 30, help = "Maximum number of hops" )]
    pub hops: u8,

    #[arg(short, long, help = "Port to target when using UDP or TCP for tracerouting [default: TCP 80, UDP 33434]")]
    pub port: Option<u16>,

    #[arg(long, default_value_t = 3, help = "Number of probes to send per hop")]
    pub probes: u16,

    #[arg(short, long, default_value_t = false, help = "Use ICMP ECHO for tracerouting")]
    pub icmp: bool,

    #[arg(short, long, default_value_t = false, help = "Use UDP for tracerouting")]
    pub udp: bool,

    #[arg(short, long, default_value_t = false, help = "Use TCP SYN for tracerouting")]
    pub tcp: bool,

    #[arg(help = "Host to traceroute to, IP or hostname")]
    pub address: String,
}
