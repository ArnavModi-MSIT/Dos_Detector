#!/usr/bin/env python3

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
INTERFACE = "wlan1"
OUTPUT_CSV = "transport_layer_attacks.csv"
WINDOW_SEC = 1
TARGET_IP = "192.168.0.139" 

# === Thresholds ===
THRESH_SYN_FLOOD = 150
THRESH_RST_FLOOD = 150
THRESH_CONN_FLOOD = 150
THRESH_PORT_SCAN = 50


def ip2int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


def current_bucket(ts: float) -> int:
    return int(ts) // WINDOW_SEC


class BucketStats:
    def __init__(self):
        self.tcp_syn = 0
        self.tcp_rst = 0
        self.tcp_ack = 0
        self.dst_ports = set()
        self.lengths = []

    def add_packet(self, pkt):
        if IP in pkt and TCP in pkt:
            tcp = pkt[TCP]
            self.lengths.append(len(pkt))
            if tcp.flags & 0x02:
                self.tcp_syn += 1
            if tcp.flags & 0x04:
                self.tcp_rst += 1
            if tcp.flags & 0x10:
                self.tcp_ack += 1
            self.dst_ports.add(tcp.dport)

    def label(self):
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
    def __init__(self):
        self.csv_file = OUTPUT_CSV
        self.agg = defaultdict(BucketStats)
        self.last_bucket = None
        self.init_csv()
        signal.signal(signal.SIGINT, self.handle_exit)

    def init_csv(self):
        self.cols = [
                    "timestamp", "src_ip", "dst_ip", "sport", "dport",
                    "tcp_syn", "tcp_rst", "tcp_ack", "packet_size", "flag_label"
        ]

        header_needed = not os.path.exists(self.csv_file)
        self.fh = open(self.csv_file, "a", newline="")
        self.writer = csv.writer(self.fh)
        if header_needed:
            self.writer.writerow(self.cols)
            self.fh.flush()

    def flush(self, up_to_bucket):
        for (ip_str, b_id), stats in list(self.agg.items()):
            if b_id >= up_to_bucket:
                continue
            row = stats.to_row(ip_str, b_id * WINDOW_SEC)
            self.writer.writerow(row)
            if row[-1] != "NONE":
                print(f"[ALERT] {row[-1]} from {ip_str}")
            del self.agg[(ip_str, b_id)]
        self.fh.flush()

    def process_packet(self, pkt):
        if not (IP in pkt and TCP in pkt):
            return

        ts = datetime.fromtimestamp(pkt.time, timezone.utc).isoformat()
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        tcp = pkt[TCP]
        packet_size = len(pkt)

        flags = tcp.flags
        syn = int(flags & 0x02 != 0)
        rst = int(flags & 0x04 != 0)
        ack = int(flags & 0x10 != 0)

        label = "NONE"
        if syn: label = "SYN"
        elif rst: label = "RST"
        elif ack: label = "ACK"

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

        if rst:
            print(f"[LOG] RST packet from {src_ip}:{tcp.sport} to {dst_ip}:{tcp.dport}")

    def handle_exit(self, *_):
        self.flush(current_bucket(datetime.now(timezone.utc).timestamp()) + 1)
        self.fh.close()
        print("[*] Detection stopped and data saved.")
        sys.exit(0)

    def start(self):
        print(f"[*] Starting transport layer attack detection...")
        print(f"[*] Interface: {INTERFACE}")
        print(f"[*] Output CSV: {self.csv_file}")
        if TARGET_IP:
            print(f"[*] Filtering for IP: {TARGET_IP}")
        print("[*] Press Ctrl+C to stop\n")

        bpf_filter = f"host {TARGET_IP}" if TARGET_IP else None
        sniff(iface=INTERFACE, prn=self.process_packet, store=0, filter=bpf_filter)


if __name__ == "__main__":
    detector = TransportLayerDetector()
    detector.start()
