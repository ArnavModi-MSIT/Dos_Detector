#!/usr/bin/env python3

"""
Mobile Wireless Attack Detection System
=======================================
This script monitors network traffic on a specified interface to detect various 
types of application-layer attacks targeting a specific mobile device (identified by MAC address).

Key Features:
- DNS Spoofing detection
- DNS Tunneling detection using machine learning
- HTTP-based attack detection (SQLi, XSS)
- Credential sniffing detection
- DoS attack detection
- Logs all findings to a CSV file

Usage:
1. Put your wireless interface in monitor mode first (e.g., 'sudo airmon-ng start wlan1')
2. Run this script with Python 3
3. Enter the target device's MAC address when prompted
4. Enter the monitor interface name (e.g., 'wlan1mon')
"""

import os
import csv
import re
import time
import numpy as np
from datetime import datetime
from scapy.all import sniff, Ether, IP, DNS, DNSQR, Raw, TCP
from sklearn.ensemble import IsolationForest
from collections import defaultdict, deque
import warnings
warnings.filterwarnings('ignore')

# === CONFIGURATION ===
# Prompt user for target device MAC and monitoring interface
TARGET_MAC = input("Enter target device MAC address (e.g., aa:bb:cc:dd:ee:ff): ").strip()
MONITOR_INTERFACE = input("Enter monitor interface name (e.g., wlan1mon): ").strip()

# Output CSV file name
CSV_FILE = "application_layer_attack.csv"

# Window size for machine learning analysis (number of packets to analyze together)
WINDOW_SIZE = 50

# CSV file headers
FIELDNAMES = [
    "timestamp", "attack_type", "confidence", "src_ip", "dst_ip", 
    "src_mac", "dst_mac", "details", "payload_size", "anomaly_score"
]

# === GLOBAL VARIABLES ===
# Deques to store recent network activity for analysis
dns_queries = deque(maxlen=WINDOW_SIZE)      # Stores recent DNS queries
http_requests = deque(maxlen=WINDOW_SIZE)    # Stores recent HTTP requests
tcp_connections = defaultdict(list)          # Tracks TCP connections per IP

# === CSV FILE SETUP ===
def init_csv():
    """Initialize the CSV log file with headers if it doesn't exist"""
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
        print(f"[+] Created new CSV log file: {CSV_FILE}")
    else:
        print(f"[+] Using existing CSV log file: {CSV_FILE}")

def log_attack(attack_type, confidence, src_ip="", dst_ip="", src_mac="", dst_mac="", 
               details="", payload_size=0, anomaly_score=""):
    """
    Log detected attacks to the CSV file
    Args:
        attack_type: Type of attack detected (e.g., "DNS Spoofing")
        confidence: Confidence level ("Low", "Medium", "High")
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_mac: Source MAC address
        dst_mac: Destination MAC address
        details: Additional details about the attack
        payload_size: Size of the suspicious payload
        anomaly_score: Machine learning anomaly score (if applicable)
    """
    data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attack_type": attack_type,
        "confidence": confidence,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "details": details,
        "payload_size": payload_size,
        "anomaly_score": anomaly_score
    }
    
    with open(CSV_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writerow(data)
    
    print(f"[!] ALERT: {attack_type} detected - Confidence: {confidence}")

# === ATTACK DETECTION FUNCTIONS ===

def detect_dns_spoofing(pkt):
    """Detect DNS response spoofing attempts"""
    # Check if packet is a DNS response with answers
    if pkt.haslayer(DNS) and pkt[DNS].qr == 1 and pkt[DNS].ancount > 0:
        try:
            query_name = pkt[DNS].qd.qname.decode().rstrip('.')
            response_ip = str(pkt[DNS].an.rdata)
            
            # List of commonly spoofed domains
            suspicious_domains = ['google.com', 'facebook.com', 'instagram.com', 'whatsapp.com']
            
            # Private IP ranges that shouldn't be in DNS responses for public domains
            private_ips = ['192.168.', '10.', '172.16.', '127.']
            
            confidence = "Medium"
            # Check if response is for a sensitive domain pointing to a private IP
            if any(domain in query_name.lower() for domain in suspicious_domains):
                if any(response_ip.startswith(ip) for ip in private_ips):
                    confidence = "High"
            
            log_attack("DNS Spoofing", confidence, 
                      src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                      src_mac=pkt[Ether].src, dst_mac=pkt[Ether].dst,
                      details=f"Domain: {query_name}, Response: {response_ip}")
        except:
            pass  # Skip malformed DNS packets

def detect_dns_tunneling(pkt):
    """Detect DNS tunneling using machine learning anomaly detection"""
    # Check if packet contains a DNS query
    if pkt.haslayer(DNSQR):
        try:
            query = pkt[DNSQR].qname.decode().rstrip('.')
            query_len = len(query)
            subdomain_count = query.count('.')
            
            # Calculate entropy (randomness) of the query
            if len(query) > 0:
                entropy = -sum((query.count(c)/len(query)) * np.log2(query.count(c)/len(query)) 
                              for c in set(query) if query.count(c) > 0)
            else:
                entropy = 0
            
            # Add query features to analysis window
            dns_queries.append([query_len, subdomain_count, entropy])
            
            # Run ML analysis when we have enough samples
            if len(dns_queries) >= 20:
                try:
                    # Use Isolation Forest for anomaly detection
                    model = IsolationForest(contamination=0.1, random_state=42)
                    model.fit(list(dns_queries))
                    scores = model.decision_function(list(dns_queries))
                    predictions = model.predict(list(dns_queries))
                    
                    # Check if latest query is anomalous
                    if predictions[-1] == -1:  # Anomaly detected
                        score = scores[-1]
                        confidence = "High" if score < -0.5 else "Medium"
                        
                        log_attack("DNS Tunneling", confidence,
                                  src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                                  src_mac=pkt[Ether].src, dst_mac=pkt[Ether].dst,
                                  details=f"Suspicious query: {query}",
                                  anomaly_score=round(score, 4))
                except:
                    pass  # Skip ML errors
        except:
            pass  # Skip malformed DNS queries

def detect_http_attacks(pkt):
    """Detect HTTP-based attacks like SQL injection and XSS"""
    # Check for TCP packets with raw payload (likely HTTP)
    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            
            # Common SQL injection patterns
            sql_patterns = [
                r"union\s+select", r"drop\s+table", r"insert\s+into",
                r"'\s*or\s*'1'\s*=\s*'1", r"admin'\s*--", r"1'\s*or\s*'1'\s*=\s*'1"
            ]
            
            # Common XSS patterns
            xss_patterns = [
                r"<script.*?>.*?</script>", r"javascript:", r"onload\s*=",
                r"onerror\s*=", r"alert\s*\(", r"document\.cookie"
            ]
            
            # Check for SQL injection patterns
            for pattern in sql_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    log_attack("SQL Injection", "High",
                              src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                              src_mac=pkt[Ether].src, dst_mac=pkt[Ether].dst,
                              details=f"Pattern: {pattern}",
                              payload_size=len(payload))
                    return
            
            # Check for XSS patterns
            for pattern in xss_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    log_attack("XSS Attack", "High",
                              src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                              src_mac=pkt[Ether].src, dst_mac=pkt[Ether].dst,
                              details=f"Pattern: {pattern}",
                              payload_size=len(payload))
                    return
            
            # Check for SSL stripping (HTTP to HTTPS downgrade)
            if "HTTP/1.1 30" in payload and "Location:" in payload:
                location_match = re.search(r"Location:\s*(http://[^\r\n]+)", payload)
                if location_match:
                    log_attack("SSL Stripping", "Medium",
                              src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                              src_mac=pkt[Ether].src, dst_mac=pkt[Ether].dst,
                              details=f"Redirect to: {location_match.group(1)}")
        except:
            pass  # Skip malformed packets

def detect_credential_sniffing(pkt):
    """Detect plaintext credential transmission"""
    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            
            # FTP credentials (port 21)
            if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                if "USER " in payload or "PASS " in payload:
                    user_match = re.search(r"USER\s+(\S+)", payload)
                    pass_match = re.search(r"PASS\s+(\S+)", payload)
                    
                    details = ""
                    if user_match:
                        details += f"Username: {user_match.group(1)}"
                    if pass_match:
                        details += f" Password: {pass_match.group(1)}"
                    
                    log_attack("FTP Credential Sniffing", "High",
                              src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                              src_mac=pkt[Ether].src, dst_mac=pkt[Ether].dst,
                              details=details.strip())
            
            # HTTP Basic Authentication
            if "Authorization: Basic" in payload:
                log_attack("HTTP Basic Auth Sniffing", "High",
                          src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                          src_mac=pkt[Ether].src, dst_mac=pkt[Ether].dst,
                          details="Basic authentication detected")
            
            # Web form logins
            login_patterns = [
                r"password\s*=\s*[^&\s]+", r"passwd\s*=\s*[^&\s]+",
                r"username\s*=\s*[^&\s]+", r"email\s*=\s*[^&\s]+"
            ]
            
            for pattern in login_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    log_attack("Form Credential Sniffing", "Medium",
                              src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                              src_mac=pkt[Ether].src, dst_mac=pkt[Ether].dst,
                              details="Login form data detected")
                    break
        except:
            pass  # Skip malformed packets

def detect_dos_attacks(pkt):
    """Detect potential DoS attacks using connection rate analysis"""
    if pkt.haslayer(TCP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Track connection timestamps per source IP
        current_time = time.time()
        tcp_connections[src_ip].append(current_time)
        
        # Clean old connections (older than 10 seconds)
        tcp_connections[src_ip] = [t for t in tcp_connections[src_ip] 
                                  if current_time - t < 10]
        
        # Check for excessive connection rate (>20 connections in 10 seconds)
        if len(tcp_connections[src_ip]) > 20:
            log_attack("Potential DoS Attack", "Medium",
                      src_ip=src_ip, dst_ip=dst_ip,
                      src_mac=pkt[Ether].src, dst_mac=pkt[Ether].dst,
                      details=f"Connections in 10s: {len(tcp_connections[src_ip])}")

# === MAIN PACKET HANDLER ===
def packet_handler(pkt):
    """Main packet processing function that routes to specific detectors"""
    try:
        # Filter packets from/to our target device only
        if pkt.haslayer(Ether):
            if TARGET_MAC not in [pkt[Ether].src, pkt[Ether].dst]:
                return
        
        # Skip non-IP packets
        if not pkt.haslayer(IP):
            return
        
        # Route to appropriate detection functions
        if pkt.haslayer(DNS):
            detect_dns_spoofing(pkt)
            if pkt.haslayer(DNSQR):
                detect_dns_tunneling(pkt)
        
        if pkt.haslayer(TCP):
            detect_http_attacks(pkt)
            detect_credential_sniffing(pkt)
            detect_dos_attacks(pkt)
    
    except Exception as e:
        pass  # Silently handle any packet processing errors

# === MAIN EXECUTION ===
def main():
    # Display banner
    print("=" * 60)
    print("Mobile Wireless Attack Detection System")
    print("=" * 60)
    print(f"Target Device MAC: {TARGET_MAC}")
    print(f"Monitor Interface: {MONITOR_INTERFACE}")
    print(f"Log File: {CSV_FILE}")
    print("=" * 60)
    print("Detecting: DNS spoofing, DNS tunneling, SQLi, XSS,")
    print("credential sniffing, DoS attacks, SSL stripping")
    print("=" * 60)
    
    # Initialize CSV log file
    init_csv()
    
    # Check if interface exists and start capture
    try:
        print(f"[*] Starting packet capture on {MONITOR_INTERFACE}...")
        print("[*] Press Ctrl+C to stop monitoring")
        
        # Start sniffing packets (no storage, process in real-time)
        sniff(iface=MONITOR_INTERFACE, prn=packet_handler, store=0)
        
    except KeyboardInterrupt:
        print("\n[*] Stopping capture...")
    except Exception as e:
        print(f"[!] Error: {e}")
        print("[!] Make sure your interface is in monitor mode")
        print("[!] Try: sudo airmon-ng start wlan1")
        print("[!] Then use the monitor interface (e.g., wlan1mon)")

if __name__ == "__main__":
    main()
