#!/usr/bin/env python3

from scapy.all import sniff, IP, ICMP, TCP, UDP, Dot11
from datetime import datetime
import csv
from collections import defaultdict, deque
import os

# Configuration
MONITOR_INTERFACE = "wlan1"
TARGET_MAC = "MAC_ID"
DETECTION_WINDOW = 10  # seconds for rate-based detection

class WirelessAttackDetector:
    def __init__(self):
        self.csv_file = f"internet_layer_attacks.csv"
        self.ip_ttl_map = {}
        self.ip_mac_map = {}
        self.ping_count = defaultdict(deque)
        self.syn_count = defaultdict(deque)
        self.udp_count = defaultdict(deque)
        self.port_activity = defaultdict(set)
        self.packet_count = 0
        self.init_csv()

    def init_csv(self):
        headers = [
            'timestamp', 'src_mac', 'src_ip', 'dst_ip', 'protocol', 'ttl',
            'packet_size', 'sport', 'dport', 'tcp_flags', 'icmp_type',
            'ip_spoofing', 'ping_flood', 'syn_flood', 'udp_flood', 'port_scan'
        ]
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
        

    def detect_ip_spoofing(self, src_ip, src_mac, ttl):
        spoofing = False
        if src_ip in self.ip_ttl_map:
            if abs(self.ip_ttl_map[src_ip] - ttl) > 10:
                spoofing = True
        else:
            self.ip_ttl_map[src_ip] = ttl

        if src_ip in self.ip_mac_map:
            if self.ip_mac_map[src_ip] != src_mac:
                spoofing = True
        else:
            self.ip_mac_map[src_ip] = src_mac

        return spoofing

    def detect_floods(self, src_ip, protocol):
        now = datetime.now().timestamp()
        ping_flood = syn_flood = udp_flood = False

        for counter in [self.ping_count, self.syn_count, self.udp_count]:
            if src_ip in counter:
                while counter[src_ip] and now - counter[src_ip][0] > DETECTION_WINDOW:
                    counter[src_ip].popleft()

        if protocol == 'ICMP':
            self.ping_count[src_ip].append(now)
            ping_flood = len(self.ping_count[src_ip]) > 10
        elif protocol == 'TCP-SYN':
            self.syn_count[src_ip].append(now)
            syn_flood = len(self.syn_count[src_ip]) > 100
        elif protocol == 'UDP':
            self.udp_count[src_ip].append(now)
            udp_flood = len(self.udp_count[src_ip]) > 100

        return ping_flood, syn_flood, udp_flood

    def detect_port_scan(self, src_ip, dst_port):
        self.port_activity[src_ip].add(dst_port)
        return len(self.port_activity[src_ip]) > 20

    def process_packet(self, pkt):
        if ICMP in pkt:
            print(f"[ICMP] {pkt.summary()}")

        print(f"[DEBUG] Packet seen: {pkt.summary()}")
        self.packet_count += 1
        if IP not in pkt:
            return

        src_mac = pkt[Dot11].addr2 if Dot11 in pkt and hasattr(pkt[Dot11], "addr2") else None
        src_mac = "aa:bb:cc:dd:ee:ff"  # dummy MAC for testing

        #if not src_mac or src_mac != TARGET_MAC:
            #return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl = pkt[IP].ttl
        packet_size = len(pkt)

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
            if tcp_flags == 2:
                protocol = "TCP-SYN"
        elif UDP in pkt:
            protocol = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        ip_spoofing = self.detect_ip_spoofing(src_ip, src_mac, ttl)
        ping_flood, syn_flood, udp_flood = self.detect_floods(src_ip, protocol)
        port_scan = self.detect_port_scan(src_ip, dport)

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

        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=packet_data.keys())
            writer.writerow(packet_data)

        if any([ip_spoofing, ping_flood, syn_flood, udp_flood, port_scan]):
            alerts = []
            if ip_spoofing: alerts.append("IP_SPOOFING")
            if ping_flood: alerts.append("PING_FLOOD")
            if syn_flood: alerts.append("SYN_FLOOD")
            if udp_flood: alerts.append("UDP_FLOOD")
            if port_scan: alerts.append("PORT_SCAN")
            print(f"[ALERT] PING_FLOOD from {src_ip} → {dst_ip} ({src_mac})")

    def start_detection(self):
        print(f"[*] Starting wireless attack detection...")
        print(f"[*] Target MAC: {TARGET_MAC}")
        print(f"[*] Monitor Interface: {MONITOR_INTERFACE}")
        print(f"[*] Results will be saved to: {self.csv_file}")
        print("[*] Press Ctrl+C to stop\n")

        try:
            sniff(iface=MONITOR_INTERFACE, prn=self.process_packet, store=0)
        except KeyboardInterrupt:
            print("\n[*] Stopping detection...")
            print("[*] Detection completed successfully!")
        except Exception as e:
            print(f"[ERROR] Detection failed: {e}")

if __name__ == "__main__":
    detector = WirelessAttackDetector()
    detector.start_detection()
