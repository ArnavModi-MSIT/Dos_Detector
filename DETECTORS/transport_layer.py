#!/usr/bin/env python3
"""
Transport Layer Attack Detector
==============================

Detects common transport layer attacks:
- SYN Floods
- RST Floods 
- Connection Floods
- Port Scans

Features:
- Real-time detection with configurable thresholds
- CSV logging for analysis and forensics
- Time-window based detection (1 second windows)
- Lightweight statistical analysis
"""

from scapy.all import IP, TCP, sniff
from collections import defaultdict
from datetime import datetime, timezone
import statistics
import signal
import sys
import csv
import os
import ipaddress

# === Configuration ===
INTERFACE = "wlan1"               # Network interface to monitor
OUTPUT_CSV = "transport_layer_attacks.csv"  # Output file for attack logs
WINDOW_SEC = 1                    # Detection window size in seconds
TARGET_IP = ""       # Optional target IP to filter for

# === Detection Thresholds ===
THRESH_SYN_FLOOD = 150    # SYN packets/sec to trigger flood detection
THRESH_RST_FLOOD = 150    # RST packets/sec to trigger flood detection  
THRESH_CONN_FLOOD = 150   # ACK packets/sec to trigger connection flood
THRESH_PORT_SCAN = 50     # Unique ports/sec to trigger port scan detection


def ip2int(ip: str) -> int:
    """Convert IP address to integer for efficient storage"""
    return int(ipaddress.IPv4Address(ip))


def current_bucket(ts: float) -> int:
    """Convert timestamp to time window bucket number"""
    return int(ts) // WINDOW_SEC


class BucketStats:
    """Tracks statistics for a single IP in a time window"""
    def __init__(self):
        self.tcp_syn = 0      # Count of SYN packets
        self.tcp_rst = 0      # Count of RST packets
        self.tcp_ack = 0      # Count of ACK packets
        self.dst_ports = set() # Unique destination ports
        self.lengths = []      # Packet lengths for averaging

    def add_packet(self, pkt):
        """Update statistics with a new packet"""
        if IP in pkt and TCP in pkt:
            tcp = pkt[TCP]
            self.lengths.append(len(pkt))
            
            # Check TCP flags
            if tcp.flags & 0x02:  # SYN flag
                self.tcp_syn += 1
            if tcp.flags & 0x04:  # RST flag
                self.tcp_rst += 1  
            if tcp.flags & 0x10:  # ACK flag
                self.tcp_ack += 1
                
            self.dst_ports.add(tcp.dport)

    def label(self):
        """Determine if traffic in this bucket represents an attack"""
        if self.tcp_syn > THRESH_SYN_FLOOD:
            return "SYN_FLOOD"
        if self.tcp_rst > THRESH_RST_FLOOD:
            return "RST_FLOOD"
        if self.tcp_ack > THRESH_CONN_FLOOD:
            return "CONNECTION_FLOOD"
        if len(self.dst_ports) > THRESH_PORT_SCAN and self.tcp_syn:
            return "PORT_SCAN"
        return "NONE"

    def to_row(self, ip_str, ts_bucket):
        """Convert stats to CSV row format"""
        avg_len = statistics.mean(self.lengths) if self.lengths else 0
        return [
            datetime.fromtimestamp(ts_bucket, timezone.utc).isoformat(),
            ip_str,
            ip2int(ip_str),
            self.tcp_syn,
            self.tcp_rst,
            self.tcp_ack,
            len(self.dst_ports),
            avg_len,
            self.label()
        ]


class TransportLayerDetector:
    """Main detection class that handles packet processing and alerting"""
    def __init__(self):
        self.csv_file = OUTPUT_CSV
        self.agg = defaultdict(BucketStats)  # Tracks stats per IP per time window
        self.last_bucket = None              # Current time window
        self.init_csv()
        signal.signal(signal.SIGINT, self.handle_exit)  # Setup CTRL+C handler

    def init_csv(self):
        """Initialize CSV output file with headers"""
        self.cols = [
            "timestamp", "src_ip", "dst_ip", "sport", "dport",
            "tcp_syn", "tcp_rst", "tcp_ack", "packet_size", "flag_label"
        ]

        # Only write headers if file doesn't exist
        header_needed = not os.path.exists(self.csv_file)
        self.fh = open(self.csv_file, "a", newline="")
        self.writer = csv.writer(self.fh)
        if header_needed:
            self.writer.writerow(self.cols)
            self.fh.flush()

    def flush(self, up_to_bucket):
        """Write completed time windows to CSV and check for attacks"""
        for (ip_str, b_id), stats in list(self.agg.items()):
            if b_id >= up_to_bucket:
                continue
                
            # Convert stats to CSV row and write
            row = stats.to_row(ip_str, b_id * WINDOW_SEC)
            self.writer.writerow(row)
            
            # Print alert if attack detected
            if row[-1] != "NONE":
                print(f"[ALERT] {row[-1]} from {ip_str}")
                
            del self.agg[(ip_str, b_id)]  # Remove processed data
        self.fh.flush()

    def process_packet(self, pkt):
        """Process each captured packet"""
        if not (IP in pkt and TCP in pkt):
            return

        # Extract packet fields
        ts = datetime.fromtimestamp(pkt.time, timezone.utc).isoformat()
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        tcp = pkt[TCP]
        packet_size = len(pkt)

        # Check TCP flags
        flags = tcp.flags
        syn = int(flags & 0x02 != 0)  # SYN flag
        rst = int(flags & 0x04 != 0)  # RST flag
        ack = int(flags & 0x10 != 0)  # ACK flag

        # Label packet type
        label = "NONE"
        if syn: label = "SYN"
        elif rst: label = "RST"
        elif ack: label = "ACK"

        # Write packet to CSV
        row = [
            ts,
            src_ip,
            dst_ip,
            tcp.sport,
            tcp.dport,
            syn,
            rst,
            ack,
            packet_size,
            label
        ]
        self.writer.writerow(row)

        # Log RST packets (potential connection resets)
        if rst:
            print(f"[LOG] RST packet from {src_ip}:{tcp.sport} to {dst_ip}:{tcp.dport}")

    def handle_exit(self, *_):
        """Cleanup handler for CTRL+C"""
        self.flush(current_bucket(datetime.now(timezone.utc).timestamp()) + 1)
        self.fh.close()
        print("[*] Detection stopped and data saved.")
        sys.exit(0)

    def start(self):
        """Start the packet capture and detection"""
        print(f"[*] Starting transport layer attack detection...")
        print(f"[*] Interface: {INTERFACE}")
        print(f"[*] Output CSV: {self.csv_file}")
        if TARGET_IP:
            print(f"[*] Filtering for IP: {TARGET_IP}")
        print("[*] Press Ctrl+C to stop\n")

        # Apply BPF filter if target IP specified
        bpf_filter = f"host {TARGET_IP}" if TARGET_IP else None
        sniff(iface=INTERFACE, prn=self.process_packet, store=0, filter=bpf_filter)


if __name__ == "__main__":
    # Create and start detector
    detector = TransportLayerDetector()
    detector.start()
