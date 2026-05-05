#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║        NETSNIFF — Network Packet Analyzer v1.0           ║
╠═══════════════════════════════════════════════════════════╣
║  Author: Olayemi Samson                                  ║
║  Internship Task 5 - Cybersecurity Intern                ║
║  Description: A packet sniffer tool that captures and    ║
║               analyzes network packets. Displays source  ║
║               and destination IP addresses, protocols,   ║
║               and payload data. Designed for ethical     ║
║               and educational use only.                  ║
╚═══════════════════════════════════════════════════════════╝

DISCLAIMER:
  This tool is intended SOLELY for educational purposes.
  Unauthorized interception of network traffic is illegal in
  many jurisdictions. Only use on networks you own or have
  explicit written permission to monitor.
"""

import sys
import argparse
import logging
from datetime import datetime
from collections import defaultdict

# Suppress scapy startup warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import (
        sniff, conf, get_if_list,
        Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw
    )
except ImportError:
    print("[!] Scapy not found. Install with:")
    print("    sudo apt install python3-scapy")
    sys.exit(1)

conf.verb = 0  # Suppress scapy verbosity


# ─── ANSI Colors ────────────────────────────────────────────────
class C:
    RST  = '\033[0m'
    BOLD = '\033[1m'
    DIM  = '\033[2m'
    RED  = '\033[91m'
    GRN  = '\033[92m'
    YEL  = '\033[93m'
    BLU  = '\033[94m'
    MAG  = '\033[95m'
    CYN  = '\033[96m'


# ─── Reference Tables ──────────────────────────────────────────
IP_PROTO = {
    1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP',
    41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH',
    58: 'ICMPv6', 89: 'OSPF', 132: 'SCTP',
}

PORT_SERVICES = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
    80: 'HTTP', 110: 'POP3', 123: 'NTP', 143: 'IMAP',
    161: 'SNMP', 194: 'IRC', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    27017: 'MongoDB',
}

ICMP_TYPES = {
    0: 'Echo Reply', 3: 'Dest Unreachable', 5: 'Redirect',
    8: 'Echo Request', 11: 'Time Exceeded', 12: 'Param Problem',
    13: 'Timestamp', 14: 'Timestamp Reply',
}


# ─── Statistics Tracker ────────────────────────────────────────
class PacketStats:
    """Accumulates capture statistics across all packets."""

    def __init__(self):
        self.total = 0
        self.total_bytes = 0
        self.protocols = defaultdict(int)
        self.src_ips = defaultdict(int)
        self.dst_ips = defaultdict(int)
        self.conversations = defaultdict(int)

    def update(self, src: str, dst: str, proto: str, pkt_len: int):
        self.total += 1
        self.total_bytes += pkt_len
        self.protocols[proto] += 1
        if src != 'N/A':
            self.src_ips[src] += 1
        if dst != 'N/A':
            self.dst_ips[dst] += 1
        if src != 'N/A' and dst != 'N/A':
            self.conversations[(src, dst)] += 1

    def display(self):
        if self.total == 0:
            print(f"\n{C.YEL}[!] No packets captured.{C.RST}")
            return

        width = 65
        print(f"\n{'═' * width}")
        print(f"  {C.BOLD}{C.CYN}CAPTURE STATISTICS{C.RST}")
        print(f"{'═' * width}")

        print(f"\n  {C.CYN}Total Packets:{C.RST}   {self.total}")
        print(f"  {C.CYN}Total Bytes:{C.RST}    {self.total_bytes:,}")
        print(f"  {C.CYN}Avg Size:{C.RST}       {self.total_bytes // self.total} bytes")

        # ── Protocol breakdown ──
        print(f"\n  {C.BOLD}Protocols:{C.RST}")
        for proto, count in sorted(self.protocols.items(), key=lambda x: -x[1]):
            pct = (count / self.total) * 100
            bar = '█' * int(pct / 2)
            print(f"    {C.GRN}{proto:<10}{C.RST} {count:>6}  "
                  f"({pct:5.1f}%) {C.DIM}{bar}{C.RST}")

        # ── Top source IPs ──
        print(f"\n  {C.BOLD}Top Source IPs:{C.RST}")
        for ip, count in sorted(self.src_ips.items(), key=lambda x: -x[1])[:5]:
            print(f"    {C.BLU}{ip:<20}{C.RST} {count:>6} packets")

        # ── Top destination IPs ──
        print(f"\n  {C.BOLD}Top Destination IPs:{C.RST}")
        for ip, count in sorted(self.dst_ips.items(), key=lambda x: -x[1])[:5]:
            print(f"    {C.RED}{ip:<20}{C.RST} {count:>6} packets")

        # ── Top conversations ──
        print(f"\n  {C.BOLD}Top Conversations:{C.RST}")
        for (src, dst), count in sorted(
            self.conversations.items(), key=lambda x: -x[1]
        )[:5]:
            print(f"    {C.BLU}{src}{C.RST} → {C.RED}{dst}{C.RST}  "
                  f"({count} packets)")

        print(f"\n{'═' * width}\n")


# ─── Packet Analyzer Engine ────────────────────────────────────
class PacketAnalyzer:
    """Captures, parses, and displays network packets in real time."""

    PROTO_COLORS = {
        'TCP': C.GRN, 'UDP': C.CYN, 'ICMP': C.YEL,
        'ARP': C.MAG, 'DNS': C.BLU, 'IPv6': C.CYN,
    }

    def __init__(self, interface=None, bpf_filter=None,
                 count=0, verbose=False, payload_bytes=64):
        self.interface = interface or conf.iface
        self.bpf_filter = bpf_filter
        self.count = count
        self.verbose = verbose
        self.payload_bytes = payload_bytes
        self.stats = PacketStats()
        self.captured = 0

    # ── Protocol identification ─────────────────────────────
    def _get_protocol(self, pkt) -> str:
        if pkt.haslayer(TCP):
            return 'TCP'
        if pkt.haslayer(UDP):
            return 'UDP'
        if pkt.haslayer(ICMP):
            return 'ICMP'
        if pkt.haslayer(ARP):
            return 'ARP'
        if pkt.haslayer(IP):
            return IP_PROTO.get(pkt[IP].proto, f'IP({pkt[IP].proto})')
        if pkt.haslayer(IPv6):
            return 'IPv6'
        return 'Other'

    # ── Port / service lookup ───────────────────────────────
    def _port_info(self, sport: int, dport: int) -> str:
        svc = PORT_SERVICES.get(dport) or PORT_SERVICES.get(sport)
        label = f" ({svc})" if svc else ""
        return f"{sport} → {dport}{label}"

    # ── Layer-specific detail strings ───────────────────────
    def _tcp_detail(self, pkt) -> str:
        flags = str(pkt[TCP].flags)
        ports = self._port_info(pkt[TCP].sport, pkt[TCP].dport)
        return f"{ports} [{flags}]"

    def _udp_detail(self, pkt) -> str:
        ports = self._port_info(pkt[UDP].sport, pkt[UDP].dport)
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qd:
                qname = dns.qd.qname.decode(errors='replace')
                return f"{ports} Query: {qname}"
            elif dns.qr == 1:
                return f"{ports} Response"
        return ports

    def _icmp_detail(self, pkt) -> str:
        t = pkt[ICMP].type
        name = ICMP_TYPES.get(t, f'Type {t}')
        return f"{name} (Code {pkt[ICMP].code})"

    def _arp_detail(self, pkt) -> str:
        op = pkt[ARP].op
        if op == 1:
            return (f"Request: Who has {pkt[ARP].pdst}? "
                    f"Tell {pkt[ARP].psrc}")
        elif op == 2:
            return (f"Reply: {pkt[ARP].psrc} "
                    f"is at {pkt[ARP].hwsrc}")
        return f"Op {op}"

    # ── Payload extraction ──────────────────────────────────
    def _extract_payload(self, pkt) -> str:
        if not pkt.haslayer(Raw):
            return None

        raw = bytes(pkt[Raw].load)[:self.payload_bytes]
        if not raw:
            return None

        # Try clean ASCII first
        try:
            text = raw.decode('utf-8', errors='strict')
            if all(31 < ord(c) < 127 or c in '\n\r\t' for c in text):
                return text
        except (UnicodeDecodeError, ValueError):
            pass

        # Mixed: printable chars + hex escapes
        parts = []
        for b in raw:
            if 31 < b < 127:
                parts.append(chr(b))
            elif b == 0x0a:
                parts.append('\\n')
            elif b == 0x0d:
                parts.append('\\r')
            elif b == 0x09:
                parts.append('\\t')
            else:
                parts.append(f'\\x{b:02x}')
        return ''.join(parts)

    # ── Per-packet callback ─────────────────────────────────
    def _process(self, pkt):
        self.captured += 1
        ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        proto = self._get_protocol(pkt)
        pkt_len = len(pkt)

        # MAC addresses
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else 'N/A'
        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else 'N/A'

        # IP addresses
        if pkt.haslayer(IP):
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        elif pkt.haslayer(ARP):
            src_ip, dst_ip = pkt[ARP].psrc, pkt[ARP].pdst
        else:
            src_ip = dst_ip = 'N/A'

        # Stats
        self.stats.update(src_ip, dst_ip, proto, pkt_len)

        # Layer detail
        detail = ''
        if pkt.haslayer(TCP):
            detail = self._tcp_detail(pkt)
        elif pkt.haslayer(UDP):
            detail = self._udp_detail(pkt)
        elif pkt.haslayer(ICMP):
            detail = self._icmp_detail(pkt)
        elif pkt.haslayer(ARP):
            detail = self._arp_detail(pkt)

        # Color for protocol
        pc = self.PROTO_COLORS.get(proto, C.RST)

        # Print main line
        print(
            f"{C.DIM}[{ts}]{C.RST} "
            f"{pc}{C.BOLD}{proto:<8}{C.RST} "
            f"{C.BLU}{src_ip:<20}{C.RST}→ "
            f"{C.RED}{dst_ip:<20}{C.RST} "
            f"{C.DIM}len={pkt_len:<5}{C.RST} "
            f"{detail}"
        )

        # Verbose extras
        if self.verbose:
            if pkt.haslayer(Ether) and src_mac != 'N/A':
                print(f"         {C.DIM}MAC: {src_mac} → {dst_mac}{C.RST}")
            payload = self._extract_payload(pkt)
            if payload:
                print(f"         {C.DIM}Payload: {payload}{C.RST}")

    # ── Banner ──────────────────────────────────────────────
    @staticmethod
    def _banner():
        print(f"""
{C.CYN}{'═' * 65}
  ┳┓┏┓┏┓  ┓ ┏┓  NetSniff — Network Packet Analyzer v1.0
  ┣┫┃ ┣   ┃ ┣    Author: Olayemi Samson
  ┛┗┗┛┗┛  ┗┛┗┛  Internship Task 5 - Cybersecurity Intern
{'═' * 65}{C.RST}
  {C.YEL}⚠  DISCLAIMER:{C.RST}
  {C.YEL}⚠  This tool is for EDUCATIONAL purposes only.{C.RST}
  {C.YEL}⚠  Unauthorized packet sniffing may be illegal.{C.RST}
  {C.YEL}⚠  Only use on networks you own or have permission.{C.RST}
""")

    # ── Start capture ───────────────────────────────────────
    def start(self):
        self._banner()

        print(f"  {C.BOLD}Capture Configuration:{C.RST}")
        print(f"    Interface  : {C.GRN}{self.interface}{C.RST}")
        print(f"    BPF Filter : {C.GRN}{self.bpf_filter or 'None (all packets)'}{C.RST}")
        print(f"    Max Count  : {C.GRN}{self.count or 'Unlimited'}{C.RST}")
        print(f"    Verbose    : {C.GRN}{self.verbose}{C.RST}")
        if self.verbose:
            print(f"    Payload Max: {C.GRN}{self.payload_bytes} bytes{C.RST}")
        print(f"\n  {C.YEL}[*] Starting capture... "
              f"Press Ctrl+C to stop.{C.RST}\n")
        print(f"{'─' * 65}")

        # Build sniff kwargs
        kwargs = {
            'iface': self.interface,
            'prn': self._process,
            'store': False,
        }
        if self.bpf_filter:
            kwargs['filter'] = self.bpf_filter
        if self.count > 0:
            kwargs['count'] = self.count

        try:
            sniff(**kwargs)
        except KeyboardInterrupt:
            print(f"\n{C.YEL}[!] Capture stopped by user (Ctrl+C).{C.RST}")
        except PermissionError:
            print(f"\n{C.RED}[!] Permission denied.{C.RST}")
            print(f"    Run with: {C.BOLD}sudo python3 {sys.argv[0]}{C.RST}")
            sys.exit(1)
        except Exception as e:
            print(f"\n{C.RED}[!] Error: {e}{C.RST}")
            print(f"    Check that interface '{self.interface}' exists.")
            sys.exit(1)

        # Show stats
        self.stats.display()


# ─── List Interfaces ────────────────────────────────────────────
def list_interfaces():
    print(f"\n{C.CYN}{'═' * 50}")
    print(f"  Available Network Interfaces")
    print(f"{'═' * 50}{C.RST}\n")
    for iface in sorted(get_if_list()):
        default = " ← default" if iface == conf.iface else ""
        print(f"    {C.GRN}{iface}{C.RST}{default}")
    print()


# ─── CLI Entry Point ────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="NETSNIFF — Network Packet Analyzer | Author: Olayemi Samson | Internship Task 5",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 packet_analyzer.py                        # Capture all on default iface
  sudo python3 packet_analyzer.py -i eth0 -c 50          # 50 packets on eth0
  sudo python3 packet_analyzer.py -f "tcp port 80" -v    # HTTP with payloads
  sudo python3 packet_analyzer.py -f "arp"               # ARP packets only
  sudo python3 packet_analyzer.py -f "icmp" -v           # Ping traffic with details
  python3  packet_analyzer.py --list-interfaces          # List interfaces (no root)
"""
    )

    parser.add_argument(
        '-i', '--interface',
        help='Network interface to capture on (default: auto-detect)'
    )
    parser.add_argument(
        '-f', '--filter',
        help='BPF filter expression (e.g., "tcp port 80", "arp", "icmp")'
    )
    parser.add_argument(
        '-c', '--count',
        type=int, default=0,
        help='Number of packets to capture (0 = unlimited)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show MAC addresses and payload data'
    )
    parser.add_argument(
        '-p', '--payload-bytes',
        type=int, default=64,
        help='Max payload bytes to display in verbose mode (default: 64)'
    )
    parser.add_argument(
        '-l', '--list-interfaces',
        action='store_true',
        help='List available interfaces and exit'
    )

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    analyzer = PacketAnalyzer(
        interface=args.interface,
        bpf_filter=args.filter,
        count=args.count,
        verbose=args.verbose,
        payload_bytes=args.payload_bytes,
    )
    analyzer.start()


if __name__ == '__main__':
    main()
