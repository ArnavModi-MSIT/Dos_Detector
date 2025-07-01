#!/usr/bin/env python3

from scapy.all import sniff, TCP, UDP, IP, ARP
from collections import defaultdict, deque
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
import threading
import time
import csv
import os

# Configuration
INTERFACE = input("interface name eg wlan1mon : ") # Change to your monitor interface
CSV_FILE = "transportation_layer_attacks.csv"
TARGET_DEVICE = input("Enter IP address : ")  # Change to target mobile IP
# TARGET_MAC = "aa:bb:cc:dd:ee:ff"  # Alternative: use MAC address

# Detection parameters
WINDOW_SIZE = 50  # packets per analysis window
ANALYSIS_INTERVAL = 5  # seconds between analysis
MAX_BUFFER = 500

# Global data structures
packet_buffer = deque(maxlen=MAX_BUFFER)
flow_stats = defaultdict(lambda: {'count': 0, 'last_seen': time.time()})

# CSV headers
CSV_HEADERS = [
    'timestamp', 'src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port',
    'packet_count', 'syn_count', 'rst_count', 'fin_count', 'ack_count',
    'packet_size_avg', 'packet_rate', 'unique_ports', 'tcp_flags_variety',
    'attack_type', 'anomaly_score', 'is_anomaly'
]

def init_csv():
    """Initialize CSV file with headers if it doesn't exist"""
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADERS)
        print(f"✓ Created CSV file: {CSV_FILE}")

def is_target_device(packet):
    """Check if packet involves target device"""
    if IP not in packet:
        return False
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    # Check IP address
    return src_ip == TARGET_DEVICE or dst_ip == TARGET_DEVICE
    
    # Alternative: Check MAC address (uncomment if using MAC)
    # if hasattr(packet, 'src') and hasattr(packet, 'dst'):
    #     return packet.src == TARGET_MAC or packet.dst == TARGET_MAC
    # return False

def extract_features(packet):
    """Extract relevant features from packet"""
    features = {
        'timestamp': datetime.now(),
        'src_ip': packet[IP].src,
        'dst_ip': packet[IP].dst,
        'protocol': None,
        'src_port': 0,
        'dst_port': 0,
        'packet_size': len(packet),
        'tcp_flags': 0,
        'is_syn': 0,
        'is_ack': 0,
        'is_rst': 0,
        'is_fin': 0
    }
    
    if TCP in packet:
        features['protocol'] = 'TCP'
        features['src_port'] = packet[TCP].sport
        features['dst_port'] = packet[TCP].dport
        features['tcp_flags'] = packet[TCP].flags
        features['is_syn'] = 1 if packet[TCP].flags.S else 0
        features['is_ack'] = 1 if packet[TCP].flags.A else 0
        features['is_rst'] = 1 if packet[TCP].flags.R else 0
        features['is_fin'] = 1 if packet[TCP].flags.F else 0
        
    elif UDP in packet:
        features['protocol'] = 'UDP'
        features['src_port'] = packet[UDP].sport
        features['dst_port'] = packet[UDP].dport
    
    return features

def packet_handler(packet):
    """Process captured packets"""
    try:
        if not is_target_device(packet):
            return
        
        if IP in packet and (TCP in packet or UDP in packet):
            features = extract_features(packet)
            packet_buffer.append(features)
            
    except Exception as e:
        print(f"Error processing packet: {e}")

def detect_rule_based_attacks(df):
    """Rule-based attack detection"""
    attacks = []
    
    # TCP SYN Flood Detection
    syn_count = df['is_syn'].sum()
    ack_count = df['is_ack'].sum()
    if syn_count > 20 and ack_count < 5:
        attacks.append("SYN_FLOOD")
    
    # UDP Flood Detection
    udp_packets = df[df['protocol'] == 'UDP']
    if len(udp_packets) > 30:
        packet_rate = len(udp_packets) / max(1, (df['timestamp'].max() - df['timestamp'].min()).total_seconds())
        if packet_rate > 50:
            attacks.append("UDP_FLOOD")
    
    # Port Scan Detection
    unique_ports = df['dst_port'].nunique()
    if unique_ports > 10:
        attacks.append("PORT_SCAN")
    
    # RST Flood Detection
    rst_count = df['is_rst'].sum()
    if rst_count > 15:
        attacks.append("RST_FLOOD")
    
    # Connection Flood (TCP)
    tcp_packets = df[df['protocol'] == 'TCP']
    if len(tcp_packets) > 40:
        syn_fin_ratio = tcp_packets['is_syn'].sum() / max(1, tcp_packets['is_fin'].sum())
        if syn_fin_ratio > 5:
            attacks.append("CONNECTION_FLOOD")
    
    return attacks

def analyze_window():
    """Analyze packet window for attacks"""
    if len(packet_buffer) < 10:
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(list(packet_buffer))
    
    if df.empty:
        return
    
    # Calculate window statistics
    window_stats = {
        'timestamp': df['timestamp'].iloc[-1].strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip': df['src_ip'].mode().iloc[0] if not df['src_ip'].mode().empty else 'N/A',
        'dst_ip': df['dst_ip'].mode().iloc[0] if not df['dst_ip'].mode().empty else 'N/A',
        'protocol': df['protocol'].mode().iloc[0] if not df['protocol'].mode().empty else 'N/A',
        'src_port': int(df['src_port'].mode().iloc[0]) if not df['src_port'].mode().empty else 0,
        'dst_port': int(df['dst_port'].mode().iloc[0]) if not df['dst_port'].mode().empty else 0,
        'packet_count': len(df),
        'syn_count': df['is_syn'].sum(),
        'rst_count': df['is_rst'].sum(),
        'fin_count': df['is_fin'].sum(),
        'ack_count': df['is_ack'].sum(),
        'packet_size_avg': df['packet_size'].mean(),
        'unique_ports': df['dst_port'].nunique(),
        'tcp_flags_variety': df['tcp_flags'].nunique()
    }
    
    # Calculate packet rate
    time_span = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
    window_stats['packet_rate'] = len(df) / max(1, time_span)
    
    # Rule-based detection
    detected_attacks = detect_rule_based_attacks(df)
    attack_type = ','.join(detected_attacks) if detected_attacks else 'NORMAL'
    
    # ML-based anomaly detection
    feature_cols = ['packet_count', 'syn_count', 'rst_count', 'fin_count', 
                   'ack_count', 'packet_size_avg', 'packet_rate', 'unique_ports']
    
    ml_features = np.array([[window_stats[col] for col in feature_cols]])
    
    # Simple anomaly detection
    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    anomaly_score = iso_forest.fit(ml_features).decision_function(ml_features)[0]
    is_anomaly = iso_forest.predict(ml_features)[0] == -1
    
    # Prepare final result
    result = {
        **window_stats,
        'attack_type': attack_type,
        'anomaly_score': round(anomaly_score, 4),
        'is_anomaly': is_anomaly
    }
    
    # Save to CSV
    save_to_csv(result)
    
    # Print detection result
    status = "🚨 ATTACK DETECTED" if (detected_attacks or is_anomaly) else "✅ Normal"
    print(f"{status} | {attack_type} | Packets: {len(df)} | Rate: {window_stats['packet_rate']:.1f}/s")

def save_to_csv(result):
    """Save analysis result to CSV"""
    try:
        with open(CSV_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            row = [result.get(header, '') for header in CSV_HEADERS]
            writer.writerow(row)
    except Exception as e:
        print(f"Error saving to CSV: {e}")

def analysis_worker():
    """Background thread for packet analysis"""
    while True:
        try:
            analyze_window()
            time.sleep(ANALYSIS_INTERVAL)
        except Exception as e:
            print(f"Analysis error: {e}")
            time.sleep(1)

def main():
    """Main function"""
    print("🔍 Mobile Transport Layer Attack Detector")
    print(f"Target Device: {TARGET_DEVICE}")
    print(f"Interface: {INTERFACE}")
    print(f"Output: {CSV_FILE}")
    print("-" * 50)
    
    # Initialize CSV
    init_csv()
    
    # Start analysis thread
    analysis_thread = threading.Thread(target=analysis_worker, daemon=True)
    analysis_thread.start()
    
    try:
        print("Starting packet capture... Press Ctrl+C to stop")
        sniff(iface=INTERFACE, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n🛑 Stopping capture...")
    except Exception as e:
        print(f"❌ Capture error: {e}")
        print("Make sure:")
        print("1. Interface is in monitor mode")
        print("2. Running as root/sudo")
        print("3. Target device IP is correct")

if __name__ == "__main__":
    main()
