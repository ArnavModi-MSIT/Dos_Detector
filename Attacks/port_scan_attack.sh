#!/bin/bash

# Port Scan Script using netcat
# ⚠️ Educational use only!

TARGET_IP="103.211.18.5"   # Change to your target
START_PORT=1
END_PORT=1024

echo "[+] Starting port scan on $TARGET_IP..."

for ((port=$START_PORT; port<=$END_PORT; port++)); do
    timeout 1 bash -c "echo >/dev/tcp/$TARGET_IP/$port" 2>/dev/null &&
    echo "[OPEN] Port $port"
done
