#!/usr/bin/env python3

from scapy.all import sniff, IP, ICMP, TCP, UDP, Dot11
from datetime import datetime
import csv
import pandas as pd
from sklearn.ensemble import IsolationForest
from collections import defaultdict, deque
import numpy as np

# Configuration
MONITOR_INTERFACE = input("interface name eg wlan1mon : ") # Change to your monitor interface
TARGET_MAC = input("Enter mac Id : ")  # Target device MAC address
DETECTION_WINDOW = 10  # seconds for rate-based detection

class WirelessAttackDetector:
    def __init__(self):
        # Create unique filename with timestamp
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_file = f"internet_layer_attacks.csv"
        
        # Attack detection data structures
        self.ip_ttl_map = {}
        self.ip_mac_map = {}
        self.ping_count = defaultdict(deque)
        self.syn_count = defaultdict(deque)
        self.udp_count = defaultdict(deque)
        self.packet_count = 0
        self.features = []
        
        # Initialize CSV
        self.init_csv()
    
    def init_csv(self):
        """Initialize CSV file with headers"""
        headers = [
            'timestamp', 'src_mac', 'src_ip', 'dst_ip', 'protocol', 'ttl', 
            'packet_size', 'sport', 'dport', 'tcp_flags', 'icmp_type',
            'ip_spoofing', 'ping_flood', 'syn_flood', 'udp_flood',
            'port_scan', 'anomaly_score', 'is_anomaly'
        ]
        
        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
    
    def detect_ip_spoofing(self, src_ip, src_mac, ttl):
        """Detect IP spoofing based on TTL and MAC inconsistencies"""
        spoofing_detected = False
        
        # TTL-based detection
        if src_ip in self.ip_ttl_map:
            if abs(self.ip_ttl_map[src_ip] - ttl) > 10:  # TTL variation threshold
                spoofing_detected = True
        else:
            self.ip_ttl_map[src_ip] = ttl
        
        # MAC-IP binding check
        if src_ip in self.ip_mac_map:
            if self.ip_mac_map[src_ip] != src_mac:
                spoofing_detected = True
        else:
            self.ip_mac_map[src_ip] = src_mac
        
        return spoofing_detected
    
    def detect_floods(self, src_ip, protocol):
        """Detect various flood attacks"""
        now = datetime.now().timestamp()
        ping_flood = syn_flood = udp_flood = False
        
        # Clean old entries
        for flood_type in [self.ping_count, self.syn_count, self.udp_count]:
            if src_ip in flood_type:
                while flood_type[src_ip] and now - flood_type[src_ip][0] > DETECTION_WINDOW:
                    flood_type[src_ip].popleft()
        
        if protocol == 'ICMP':
            self.ping_count[src_ip].append(now)
            if len(self.ping_count[src_ip]) > 50:  # 50 pings in 10 seconds
                ping_flood = True
        
        elif protocol == 'TCP-SYN':
            self.syn_count[src_ip].append(now)
            if len(self.syn_count[src_ip]) > 100:  # 100 SYN packets in 10 seconds
                syn_flood = True
        
        elif protocol == 'UDP':
            self.udp_count[src_ip].append(now)
            if len(self.udp_count[src_ip]) > 100:  # 100 UDP packets in 10 seconds
                udp_flood = True
        
        return ping_flood, syn_flood, udp_flood
    
    def detect_port_scan(self, src_ip, dst_ports):
        """Simple port scan detection based on unique destination ports"""
        if not hasattr(self, 'port_activity'):
            self.port_activity = defaultdict(set)
        
        self.port_activity[src_ip].add(dst_ports)
        
        # If accessing more than 20 different ports, likely a port scan
        return len(self.port_activity[src_ip]) > 20
    
    def extract_features(self, pkt):
        """Extract features from packet for ML analysis"""
        features = {
            'packet_size': len(pkt),
            'ttl': 0,
            'tcp_window': 0,
            'tcp_flags_count': 0,
            'payload_entropy': 0,
            'inter_arrival_time': 0
        }
        
        if IP in pkt:
            features['ttl'] = pkt[IP].ttl
        
        if TCP in pkt:
            features['tcp_window'] = pkt[TCP].window
            # Count set TCP flags
            tcp_flags = pkt[TCP].flags
            features['tcp_flags_count'] = bin(tcp_flags).count('1')
        
        # Calculate payload entropy (measure of randomness)
        if pkt.payload:
            payload_bytes = bytes(pkt.payload)
            if len(payload_bytes) > 0:
                entropy = 0
                for i in range(256):
                    p = payload_bytes.count(i) / len(payload_bytes)
                    if p > 0:
                        entropy -= p * np.log2(p)
                features['payload_entropy'] = entropy
        
        return features
    
    def process_packet(self, pkt):
        """Main packet processing function"""
        self.packet_count += 1
        
        if self.packet_count % 1000 == 0:
            print(f"[INFO] Processed {self.packet_count} packets...")
        
        # Only process packets with IP layer and from our target MAC
        if not (IP in pkt and Dot11 in pkt):
            return
        
        src_mac = pkt[Dot11].addr2
        if not src_mac or src_mac != TARGET_MAC:
            return
        
        # Extract basic packet info
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl = pkt[IP].ttl
        packet_size = len(pkt)
        
        # Determine protocol and extract relevant info
        protocol = "OTHER"
        sport = dport = tcp_flags = icmp_type = 0
        
        if ICMP in pkt:
            protocol = "ICMP"
            icmp_type = pkt[ICMP].type
        elif TCP in pkt:
            protocol = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            tcp_flags = pkt[TCP].flags
            if tcp_flags == 2:  # SYN flag
                protocol = "TCP-SYN"
        elif UDP in pkt:
            protocol = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        
        # Attack Detection
        ip_spoofing = self.detect_ip_spoofing(src_ip, src_mac, ttl)
        ping_flood, syn_flood, udp_flood = self.detect_floods(src_ip, protocol)
        port_scan = self.detect_port_scan(src_ip, dport)
        
        # Extract ML features
        ml_features = self.extract_features(pkt)
        
        # Prepare data for CSV and ML
        packet_data = {
            'timestamp': timestamp,
            'src_mac': src_mac,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'ttl': ttl,
            'packet_size': packet_size,
            'sport': sport,
            'dport': dport,
            'tcp_flags': tcp_flags,
            'icmp_type': icmp_type,
            'ip_spoofing': int(ip_spoofing),
            'ping_flood': int(ping_flood),
            'syn_flood': int(syn_flood),
            'udp_flood': int(udp_flood),
            'port_scan': int(port_scan),
            'anomaly_score': 0,  # Will be filled by ML
            'is_anomaly': 0      # Will be filled by ML
        }
        
        # Add ML features for analysis
        packet_data.update(ml_features)
        self.features.append(packet_data)
        
        # Print alerts
        if any([ip_spoofing, ping_flood, syn_flood, udp_flood, port_scan]):
            alerts = []
            if ip_spoofing: alerts.append("IP_SPOOFING")
            if ping_flood: alerts.append("PING_FLOOD")
            if syn_flood: alerts.append("SYN_FLOOD")
            if udp_flood: alerts.append("UDP_FLOOD")
            if port_scan: alerts.append("PORT_SCAN")
            
            print(f"[ALERT] {' | '.join(alerts)} from {src_ip} ({src_mac})")
    
    def run_ml_analysis(self):
        """Run unsupervised ML analysis on collected data"""
        if len(self.features) < 10:
            print("[INFO] Not enough data for ML analysis")
            return
        
        print("[INFO] Running anomaly detection...")
        
        # Prepare features for ML
        df = pd.DataFrame(self.features)
        
        # Select numerical features for ML analysis
        ml_features = ['ttl', 'packet_size', 'tcp_window', 'tcp_flags_count', 
                      'payload_entropy', 'sport', 'dport']
        
        # Handle missing values
        X = df[ml_features].fillna(0)
        
        # Run Isolation Forest
        clf = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        
        try:
            anomaly_labels = clf.fit_predict(X)
            anomaly_scores = clf.decision_function(X)
            
            # Update dataframe with results
            df['anomaly_score'] = anomaly_scores
            df['is_anomaly'] = (anomaly_labels == -1).astype(int)
            
            # Remove ML-specific columns before saving
            csv_columns = [col for col in df.columns if col not in 
                          ['tcp_window', 'tcp_flags_count', 'payload_entropy', 'inter_arrival_time']]
            
            # Save to CSV
            df[csv_columns].to_csv(self.csv_file, index=False)
            
            anomaly_count = sum(anomaly_labels == -1)
            print(f"[INFO] ML Analysis complete. Found {anomaly_count} anomalies out of {len(df)} packets")
            print(f"[INFO] Results saved to {self.csv_file}")
            
        except Exception as e:
            print(f"[ERROR] ML analysis failed: {e}")
            # Save without ML results
            csv_columns = [col for col in df.columns if col not in 
                          ['tcp_window', 'tcp_flags_count', 'payload_entropy', 'inter_arrival_time']]
            df[csv_columns].to_csv(self.csv_file, index=False)
    
    def start_detection(self):
        """Start the detection process"""
        print(f"[*] Starting wireless attack detection...")
        print(f"[*] Target MAC: {TARGET_MAC}")
        print(f"[*] Monitor Interface: {MONITOR_INTERFACE}")
        print(f"[*] Results will be saved to: {self.csv_file}")
        print("[*] Press Ctrl+C to stop and analyze data\n")
        
        try:
            sniff(iface=MONITOR_INTERFACE, prn=self.process_packet, store=0)
        except KeyboardInterrupt:
            print("\n[*] Stopping detection...")
            self.run_ml_analysis()
            print("[*] Detection completed successfully!")
        except Exception as e:
            print(f"[ERROR] Detection failed: {e}")

if __name__ == "__main__":
    detector = WirelessAttackDetector()
    detector.start_detection()
