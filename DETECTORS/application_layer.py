#!/usr/bin/env python3

# Import necessary libraries
from scapy.all import DNS, DNSRR, Raw, TCP, UDP, IP, sniff
from collections import defaultdict
from datetime import datetime, timezone
import statistics
import signal
import sys
import csv
import os
import ipaddress
import re

# === Configuration Section ===
# Network interface to monitor (change to your actual interface)
INTERFACE = "lo"
# File where detection results will be saved
OUTPUT_CSV = "application_layer_attacks.csv"
# Time window (in seconds) for aggregating statistics
WINDOW_SEC = 1

# === Detection Thresholds ===
# These values determine when an alert is triggered
TH_DNS_SPOOF = 20      # Max allowed DNS spoofing attempts per window
TH_DNS_TUNNEL = 10     # Max allowed DNS tunneling attempts per window
TH_XSS = 3             # Max allowed XSS patterns per window
TH_SQLI = 3            # Max allowed SQL injection patterns per window
TH_SSL_STRIP = 5       # Max allowed SSL stripping attempts per window
TH_CRED = 3            # Max allowed credential patterns per window
TH_HTTP_DOS = 100      # Max allowed HTTP requests per window (DoS threshold)

# === Regex Patterns for Attack Detection ===
# Patterns to detect common web attacks in packet payloads
xss_pat = re.compile(br"<script|%3cscript", re.I)  # Cross-site scripting
sqli_pat = re.compile(br"union.*select|'\s*or\s*1=1", re.I)  # SQL injection
cred_pat = re.compile(br"password=|Authorization:\s*Basic", re.I)  # Credential exposure

# Helper function to convert IP address to integer for easier storage
def ip2int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))

# Helper function to determine current time window bucket
def current_bucket(ts: float) -> int:
    return int(ts) // WINDOW_SEC

# Main class for tracking application layer statistics
class AppLayerStats:
    def __init__(self):
        # Initialize counters for all attack types we track
        self.dns_spoof = 0      # DNS spoofing attempts
        self.dns_tunnel = 0     # DNS tunneling attempts
        self.http_xss = 0       # XSS attack attempts
        self.http_sqli = 0      # SQL injection attempts
        self.http_sslstrip = 0  # SSL stripping attempts
        self.http_creds = 0     # Credential exposure attempts
        self.http_reqs = 0      # Total HTTP requests (for DoS detection)

    # Process a packet and update relevant counters
    def add(self, pkt):
        # Check for DNS responses (UDP port 53)
        if UDP in pkt and pkt[UDP].dport == 53 and DNS in pkt and pkt[DNS].qr == 1:
            rr = pkt[DNS]
            # Check each answer in the DNS response
            for i in range(rr.ancount):
                ans = rr.an[i]
                ttl = getattr(ans, 'ttl', 0)
                # Low TTL may indicate DNS spoofing
                if ttl < 60:
                    self.dns_spoof += 1
                # Large TXT records may indicate DNS tunneling
                if ans.type == 16 and len(ans.rdata) > 100:
                    self.dns_tunnel += 1

        # Check for HTTP traffic (TCP port 80)
        if TCP in pkt and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
            self.http_reqs += 1

            # Extract payload from raw bytes if needed
            try:
                raw_bytes = bytes(pkt[TCP].payload)
                if raw_bytes:
                    payload = raw_bytes.lower()

                    # Check for various attack patterns in the payload
                    if xss_pat.search(payload):
                        self.http_xss += 1
                    if sqli_pat.search(payload):
                        self.http_sqli += 1
                    if cred_pat.search(payload):
                        self.http_creds += 1
                    # Check for HTTP redirects (possible SSL stripping)
                    if b"location: http://" in payload and (b"301" in payload or b"302" in payload):
                        self.http_sslstrip += 1
            except Exception as e:
                print(f"[ERROR parsing payload] {e}")

    # Format statistics into a CSV row
    def row(self, ip_str: str, bucket_time: int):
        return [
            datetime.fromtimestamp(bucket_time, timezone.utc).isoformat(),
            ip_str,
            ip2int(ip_str),
            self.dns_spoof,
            self.dns_tunnel,
            self.http_xss,
            self.http_sqli,
            self.http_sslstrip,
            self.http_creds,
            self.http_reqs,
            self.label()  # Add the detected attack label
        ]

    # Determine if any attack thresholds were exceeded
    def label(self):
        if self.http_reqs > TH_HTTP_DOS:
            return "DOS"
        if self.dns_spoof > TH_DNS_SPOOF:
            return "DNS_SPOOFING"
        if self.dns_tunnel > TH_DNS_TUNNEL:
            return "DNS_TUNNELING"
        if self.http_xss > TH_XSS:
            return "XSS"
        if self.http_sqli > TH_SQLI:
            return "SQLI"
        if self.http_sslstrip > TH_SSL_STRIP:
            return "SSL_STRIP"
        if self.http_creds > TH_CRED:
            return "CREDENTIAL_THEFT"
        return "NONE"

# Main detector class that handles packet processing and output
class AppLayerDetector:
    def __init__(self):
        self.csv_file = OUTPUT_CSV
        self.stats = defaultdict(AppLayerStats)  # Tracks stats per IP per time window
        self.last_bucket = None  # Tracks current time window
        self.init_csv()  # Set up output file
        signal.signal(signal.SIGINT, self.handle_exit)  # Handle Ctrl+C gracefully

    # Initialize the CSV output file
    def init_csv(self):
        self.cols = [
            "timestamp", "src_ip", "src_ip_int",
            "dns_spoof", "dns_tunnel",
            "http_xss", "http_sqli", "http_sslstrip", "http_creds", "http_reqs",
            "attack_label"
        ]
        # Only write header if file doesn't exist
        need_header = not os.path.exists(self.csv_file)
        self.fh = open(self.csv_file, "a", newline="")
        self.writer = csv.writer(self.fh)
        if need_header:
            self.writer.writerow(self.cols)
            self.fh.flush()

    # Write stats for completed time windows to CSV
    def flush(self, bucket_limit):
        for (ip_str, b_id), stat in list(self.stats.items()):
            if b_id >= bucket_limit:
                continue
            row = stat.row(ip_str, b_id * WINDOW_SEC)
            self.writer.writerow(row)
            # Print alert if attack detected
            if row[-1] != "NONE":
                print(f"[ALERT] {row[-1]} from {ip_str}")
            del self.stats[(ip_str, b_id)]
        self.fh.flush()

    # Process each captured packet
    def process_packet(self, pkt):
        if IP not in pkt:
            return
        ts = pkt.time
        b_id = current_bucket(ts)
        if self.last_bucket is None:
            self.last_bucket = b_id
        # If we've moved to a new time window, flush old data
        if b_id != self.last_bucket:
            self.flush(b_id)
            self.last_bucket = b_id
        # Update statistics for this IP in current time window
        ip_str = pkt[IP].src
        self.stats[(ip_str, b_id)].add(pkt)

    # Clean up when exiting
    def handle_exit(self, *_):
        self.flush(current_bucket(datetime.now(timezone.utc).timestamp()) + 1)
        self.fh.close()
        print("[*] Application-layer detection stopped and data saved.")
        sys.exit(0)

    # Start the packet capture
    def start(self):
        print(f"[*] Starting application-layer attack detection...")
        print(f"[*] Interface: {INTERFACE}")
        print(f"[*] Results will be saved to: {self.csv_file}")
        print("[*] Press Ctrl+C to stop\n")
        sniff(iface=INTERFACE, store=False, prn=self.process_packet)

# Main entry point
if __name__ == "__main__":
    AppLayerDetector().start()
