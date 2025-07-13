#!/usr/bin/env python3
"""
Wireless Network Attack Detector
===============================

Detects common internet layer attacks in wireless networks:
- IP Spoofing (TTL/MAC inconsistencies)
- Ping Flood (ICMP flood)
- SYN Flood (TCP SYN flood)
- UDP Flood 
- Port Scanning

Features:
- Real-time detection with configurable thresholds
- CSV logging for analysis and forensics
- Lightweight detection algorithms
- Wireless network focused
"""

from scapy.all import sniff, IP, ICMP, TCP, UDP, Dot11
from datetime import datetime
import csv
from collections import defaultdict, deque
import os

# Configuration Constants
MONITOR_INTERFACE = "wlan1"    # Wireless interface in monitor mode
TARGET_MAC = "MAC_ID"          # MAC address of device to monitor
DETECTION_WINDOW = 10          # Time window (seconds) for rate-based detection

class WirelessAttackDetector:
    def __init__(self):
        """Initialize detector with data structures and logging"""
        self.csv_file = f"internet_layer_attacks.csv"  # Attack log file
        
        # Detection data structures
        self.ip_ttl_map = {}           # Maps IPs to expected TTL values
        self.ip_mac_map = {}           # Maps IPs to MAC addresses
        self.ping_count = defaultdict(deque)  # ICMP packet timestamps per IP
        self.syn_count = defaultdict(deque)   # SYN packet timestamps per IP  
        self.udp_count = defaultdict(deque)    # UDP packet timestamps per IP
        self.port_activity = defaultdict(set)  # Unique ports per scanner IP
        
        self.packet_count = 0          # Total packets processed
        
        # Initialize CSV log file
        self.init_csv()

    def init_csv(self):
        """Initialize CSV file with required headers if it doesn't exist"""
        headers = [
            'timestamp', 'src_mac', 'src_ip', 'dst_ip', 'protocol', 'ttl',
            'packet_size', 'sport', 'dport', 'tcp_flags', 'icmp_type',
            'ip_spoofing', 'ping_flood', 'syn_flood', 'udp_flood', 'port_scan'
        ]
        
        # Only create new file if it doesn't exist
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()

    def detect_ip_spoofing(self, src_ip, src_mac, ttl):
        """
        Detect IP spoofing by checking TTL and MAC consistency
        
        Args:
            src_ip: Source IP address
            src_mac: Source MAC address 
            ttl: IP Time-To-Live value
            
        Returns:
            bool: True if spoofing detected
        """
        spoofing = False
        
        # Check for TTL anomalies (>10 difference from expected)
        if src_ip in self.ip_ttl_map:
            if abs(self.ip_ttl_map[src_ip] - ttl) > 10:
                spoofing = True
        else:
            self.ip_ttl_map[src_ip] = ttl  # Store initial TTL

        # Check for MAC address changes
        if src_ip in self.ip_mac_map:
            if self.ip_mac_map[src_ip] != src_mac:
                spoofing = True
        else:
            self.ip_mac_map[src_ip] = src_mac  # Store initial MAC

        return spoofing

    def detect_floods(self, src_ip, protocol):
        """
        Detect various flood attacks using rate limiting
        
        Args:
            src_ip: Source IP address
            protocol: Packet protocol type
            
        Returns:
            tuple: (ping_flood, syn_flood, udp_flood) detection status
        """
        now = datetime.now().timestamp()
        ping_flood = syn_flood = udp_flood = False

        # Clean up old timestamps outside detection window
        for counter in [self.ping_count, self.syn_count, self.udp_count]:
            if src_ip in counter:
                while counter[src_ip] and now - counter[src_ip][0] > DETECTION_WINDOW:
                    counter[src_ip].popleft()

        # Check flood thresholds
        if protocol == 'ICMP':
            self.ping_count[src_ip].append(now)
            ping_flood = len(self.ping_count[src_ip]) > 10  # >10 ICMP/sec
        elif protocol == 'TCP-SYN':
            self.syn_count[src_ip].append(now)
            syn_flood = len(self.syn_count[src_ip]) > 100   # >100 SYN/sec
        elif protocol == 'UDP':
            self.udp_count[src_ip].append(now)
            udp_flood = len(self.udp_count[src_ip]) > 100   # >100 UDP/sec

        return ping_flood, syn_flood, udp_flood

    def detect_port_scan(self, src_ip, dst_port):
        """
        Detect port scanning by tracking unique ports per source
        
        Args:
            src_ip: Source IP address
            dst_port: Destination port contacted
            
        Returns:
            bool: True if scanning detected (>20 unique ports)
        """
        self.port_activity[src_ip].add(dst_port)
        return len(self.port_activity[src_ip]) > 20

    def process_packet(self, pkt):
        """Main packet processing handler"""
        self.packet_count += 1
        
        # Debug output
        if ICMP in pkt:
            print(f"[ICMP] {pkt.summary()}")
        print(f"[DEBUG] Packet seen: {pkt.summary()}")

        # Skip non-IP packets
        if IP not in pkt:
            return

        # Extract MAC address (wireless specific)
        src_mac = pkt[Dot11].addr2 if Dot11 in pkt and hasattr(pkt[Dot11], "addr2") else None
        src_mac = "aa:bb:cc:dd:ee:ff"  # Placeholder for testing

        # Uncomment to filter for target MAC only
        #if not src_mac or src_mac != TARGET_MAC:
        #    return

        # Extract basic packet information
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl = pkt[IP].ttl
        packet_size = len(pkt)

        # Protocol-specific processing
        protocol = "OTHER"
        sport = dport = tcp_flags = icmp_type = 0

        if ICMP in pkt:
            protocol = "ICMP"
            icmp_type = pkt[ICMP].type
        elif TCP in pkt:
            protocol = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            tcp_flags = pkt[TCP].flags
            if tcp_flags == 2:  # SYN flag
                protocol = "TCP-SYN"
        elif UDP in pkt:
            protocol = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        # Run all detection modules
        ip_spoofing = self.detect_ip_spoofing(src_ip, src_mac, ttl)
        ping_flood, syn_flood, udp_flood = self.detect_floods(src_ip, protocol)
        port_scan = self.detect_port_scan(src_ip, dport)

        # Prepare CSV record
        packet_data = {
            'timestamp': timestamp,
            'src_mac': src_mac,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'ttl': ttl,
            'packet_size': packet_size,
            'sport': sport,
            'dport': dport,
            'tcp_flags': tcp_flags,
            'icmp_type': icmp_type,
            'ip_spoofing': int(ip_spoofing),
            'ping_flood': int(ping_flood),
            'syn_flood': int(syn_flood),
            'udp_flood': int(udp_flood),
            'port_scan': int(port_scan)
        }

        # Log to CSV
        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=packet_data.keys())
            writer.writerow(packet_data)

        # Generate alerts for any detected attacks
        if any([ip_spoofing, ping_flood, syn_flood, udp_flood, port_scan]):
            alerts = []
            if ip_spoofing: alerts.append("IP_SPOOFING")
            if ping_flood: alerts.append("PING_FLOOD")
            if syn_flood: alerts.append("SYN_FLOOD")
            if udp_flood: alerts.append("UDP_FLOOD")
            if port_scan: alerts.append("PORT_SCAN")
            print(f"[ALERT] Detected {'+'.join(alerts)} from {src_ip} → {dst_ip} ({src_mac})")

    def start_detection(self):
        """Start the packet capture and detection process"""
        print(f"[*] Starting wireless attack detection...")
        print(f"[*] Target MAC: {TARGET_MAC}")
        print(f"[*] Monitor Interface: {MONITOR_INTERFACE}")
        print(f"[*] Results will be saved to: {self.csv_file}")
        print("[*] Press Ctrl+C to stop\n")

        try:
            # Start packet capture
            sniff(iface=MONITOR_INTERFACE, prn=self.process_packet, store=0)
        except KeyboardInterrupt:
            print("\n[*] Stopping detection...")
            print("[*] Detection completed successfully!")
        except Exception as e:
            print(f"[ERROR] Detection failed: {e}")

if __name__ == "__main__":
    # Create and start detector
    detector = WirelessAttackDetector()
    detector.start_detection()
