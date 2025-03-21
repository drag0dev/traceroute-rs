# traceroute-rs

Traceroute-rs is a Rust-based clone of the classic traceroute utility, designed to help you follow your packets as they travel across the internet. It provides insights into the path your data takes to reach a destination, including the IP addresses of intermediate hops and the time taken for each hop. While it aims to replicate the core functionality of traceroute, it is **not intended to be a drop-in replacement** and may differ in behavior or options.

## Features

- Support for both **IPv4** and **IPv6**.
- Multiple protocols for tracerouting: **ICMP ECHO**, **UDP**, and **TCP SYN**.
- Customizable timeout, maximum hops, and number of probes per hop.

## Usage
Usage: traceroute-rs [OPTIONS] \<ADDRESS\>

Arguments:
```
  <ADDRESS>  Host to traceroute to, IP or hostname
  ```
Options:
```
      --v4                 Use IPv4  
      --v6                 Use IPv6  
      --timeout <TIMEOUT>  Timeout in milliseconds per each probe [default: 2000]
      --hops <HOPS>        Maximum number of hops [default: 30]
  -p, --port <PORT>        Port to target when using UDP or TCP for tracerouting [default: TCP 80, UDP 33434]
      --probes <PROBES>    Number of probes to send per hop [default: 3]
  -i, --icmp               Use ICMP ECHO for tracerouting
  -u, --udp                Use UDP for tracerouting
  -t, --tcp                Use TCP SYN for tracerouting
  -h, --help               Print help
  -V, --version            Print version
  ```
## Examples

1. Trace using IPv4 and ICMP
```bash
traceroute-rs --v4 --icmp example.com
```
2. Trace using IPv6 and UDP with a custom port
```bash
traceroute-rs --v6 --udp -p 33435 example.com
```
3. Set a custom timeout and maximum hops
```bash
traceroute-rs --v4 --icmp --timeout 1000 --hops 20 example.com
```

## Installation

To install traceroute-rs, ensure you have Rust installed on your system. Then, clone the repository and build the project:

```bash
git clone https://github.com/drag0dev/traceroute-rs.git
cd traceroute-rs
cargo install --path .
```

Traceroute-rs requires elevated privileges to function properly. Optionally, on Linux, you can avoid the need for elevating privileges by doing the following:

```bash
cd ~/.cargo/bin/
sudo chown root:root ./traceroute-rs
sudo chmod 4755 ./traceroute-rs
``` 