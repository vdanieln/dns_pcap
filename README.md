# DNS Response Capture

Small C tool that listens for DNS **responses** and prints the resolved domain names alongside returned A, AAAA, and CNAME records.

## Build (Ubuntu)
```bash
sudo apt update
sudo apt install -y libpcap-dev
make
```

## Usage
Run as root or give `dns_capture` permission to capture packets (e.g., `sudo setcap cap_net_raw,cap_net_admin=eip dns_capture`).
```bash
./dns_capture -i <interface>
./dns_capture -i wlp1s0
./dns_capture -r sample.pcapng
./dns_capture -i wlp1s0 -c 50
```

- `-i` interface: live capture (e.g., `wlp1s0`, `eth0`, `lo`, `docker0`).
- `-r` file: read from a pcap/pcapng file.
- `-c` count: number of packets to process (0 = infinite, default).

## Output format
```
Domain: www.example.com -> CNAME web-123.host.net, 203.0.113.10, 2001:db8::10
Domain: api.example.com -> 1.1.1.1
Domain: ipv6.example.com -> 2001:db8:abcd::42
```

## Notes
- This program filter captures UDP DNS responses (`udp port 53` with QR bit set). you can use capture.c/h API for different set of filter captures, as he stands alone as capture API using libpcap.
- Supports IPv4 and IPv6 packets and parses A, AAAA, and CNAME records across answer/authority/additional sections.
- should build on modern Ubuntu with gcc.
