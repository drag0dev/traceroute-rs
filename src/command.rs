use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "traceroute-rs", version = "1.0", about = "Follow your packet across the internet")]
pub struct Command {

    #[arg(long)]
    pub v4: bool,

    #[arg(long)]
    pub v6: bool,

    #[arg(short, long, default_value_t = 5000)]
    pub timeout: u64,

    #[arg(long, default_value_t = 30)]
    pub hops: u8,

    #[arg(short, long)]
    pub port: Option<u16>,

    #[arg(short, long, default_value_t = false)]
    pub icmp: bool,

    #[arg(short, long, default_value_t = false)]
    pub udp: bool,

    pub address: String,
}
