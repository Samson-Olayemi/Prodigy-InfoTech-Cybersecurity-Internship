# Task 5 — NetSniff: Network Packet Analyzer v1.0 📡

## 📌 Description
NetSniff is a Python-based live network packet analyzer that captures real-time network traffic, decodes each packet's protocol, source/destination IPs, size, and meaning — then generates a full statistical summary of everything captured. It is the kind of tool used in real-world network security monitoring and incident response.

## 🚀 How to Run
```bash
sudo python3 packet_analyzer.py
```
> Requires sudo for raw socket access on Linux.

Press `Ctrl+C` to stop the capture and generate the statistics report.

## ⚙️ How It Works
- Captures live packets on the specified network interface (e.g. `eth0`)
- Decodes and displays each packet in real time:
  - Timestamp
  - Protocol (ICMP, UDP, ARP, IPv6, TCP, etc.)
  - Source IP → Destination IP
  - Packet size
  - Human-readable description (DNS query, Echo Request, ARP reply, etc.)
- On stop, generates a **Capture Statistics** report including:
  - Total packets and bytes captured
  - Average packet size
  - Protocol breakdown with percentages
  - Top source and destination IPs
  - Top conversations on the network

## 🧪 Example Output
```
[12:23:12.972] IPv6    fe80::ec89 → ff02::16         len=110
[12:23:27.803] UDP     192.168.64.2 → 192.168.64.1   len=70   49051 → 53 (DNS) Query: google.com
[12:23:27.836] ARP     192.168.64.2 → 192.168.64.1   len=42   Request: Who has 192.168.64.2?
[12:23:27.854] ICMP    192.168.64.2 → 142.251.39.205 len=98   Echo Request (Code 0)

--- CAPTURE STATISTICS ---
Total Packets:  45
Total Bytes:    4,235
Avg Size:       94 bytes

Protocols:
  ICMP    32  (71.1%) ████████████████████████████████
  UDP      6  (13.3%) ██████
  ARP      4   (8.9%) ████
  IPv6     3   (6.7%) ███
```

## 📚 What I Learned
- A network is never quiet — traffic flows constantly even when you think a device is idle
- Protocols tell a story: understanding ICMP, UDP, ARP, and IPv6 behaviour is fundamental to spotting anomalies
- Visibility is the foundation of security — you cannot protect what you cannot see
- Packet analysis is a core skill in network defence, threat hunting, and incident response

## 🛠️ Requirements
```bash
pip install scapy
```

## ⚠️ Disclaimer
This tool is for **educational and ethical purposes ONLY**. Unauthorized packet sniffing on networks you do not own or have explicit permission to monitor is **illegal**. Always use on your own network or in a controlled lab environment only.
