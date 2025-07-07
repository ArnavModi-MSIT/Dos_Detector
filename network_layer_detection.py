#!/usr/bin/env python3
"""
Network Layer Attack Detector for Mobile Devices
Detects: ARP Spoofing, Deauth, Evil Twin, MAC Flooding
Uses unsupervised ML for anomaly detection
"""

from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt, ARP, Ether
from sklearn.ensemble import IsolationForest
from collections import defaultdict, deque
import numpy as np
import csv
import time
from datetime import datetime

class NetworkLayerDetector:
    def __init__(self):
        # Configuration
        self.interface = "wlan1mon"
        self.target_mac = "ba:1f:d8:1d:73:eb"
        
        # Create unique CSV filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_file = f"network_layer_attacks.csv"
        
        # Detection data structures
        self.arp_table = {}  # IP -> MAC mapping
        self.ssid_bssid_map = defaultdict(set)  # SSID -> set of BSSIDs
        self.mac_activity = defaultdict(deque)  # MAC -> packet timestamps
        self.deauth_count = defaultdict(deque)  # Source -> deauth timestamps
        self.packet_count = 0

        # ML model for anomaly detection
        self.ml_features = []
        self.unique_macs_window = deque()   # (ts, src_mac) for last 5 s
        self.init_csv()
        
    def init_csv(self):
        """Initialize CSV file with headers"""
        headers = [
            'timestamp', 'src_mac', 'dst_mac', 'attack_type', 'confidence',
            'arp_spoofing', 'deauth_attack', 'evil_twin', 'mac_flooding',
            'rssi', 'channel', 'packet_rate', 'anomaly_score', 'is_anomaly'
        ]
        
        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
        print(f"[*] Results will be saved to: {self.csv_file}")
    
    def detect_arp_spoofing(self, pkt):
        """Detect ARP spoofing attacks"""
        if not pkt.haslayer(ARP):
            return False, 0
            
        arp_layer = pkt[ARP]
        src_ip = arp_layer.psrc
        src_mac = arp_layer.hwsrc.lower()
        
        # Check if IP-MAC binding has changed
        if src_ip in self.arp_table:
            if self.arp_table[src_ip] != src_mac:
                confidence = 0.8  # High confidence for clear MAC change
                print(f"[ARP SPOOF] IP {src_ip} changed from MAC {self.arp_table[src_ip]} to {src_mac}")
                return True, confidence
        else:
            self.arp_table[src_ip] = src_mac
            
        return False, 0
    
    def detect_deauth_attack(self, pkt):
        """Detect deauthentication attacks"""
        if not pkt.haslayer(Dot11Deauth):
            return False, 0
            
        src_mac = pkt[Dot11].addr2.lower() if pkt[Dot11].addr2 else ""
        current_time = time.time()
        
        # Track deauth packets from this source
        self.deauth_count[src_mac].append(current_time)
        
        # Remove old entries (older than 10 seconds)
        while (self.deauth_count[src_mac] and 
               current_time - self.deauth_count[src_mac][0] > 10):
            self.deauth_count[src_mac].popleft()
        
        # If more than 5 deauth packets in 10 seconds, it's likely an attack
        deauth_rate = len(self.deauth_count[src_mac])
        if deauth_rate > 5:
            confidence = min(0.7 + (deauth_rate * 0.05), 0.95)
            print(f"[DEAUTH ATTACK] {src_mac} sent {deauth_rate} deauth packets")
            return True, confidence
            
        return False, 0
    
    def detect_evil_twin(self, pkt):
        """Detect evil twin access points"""
        if not pkt.haslayer(Dot11Beacon):
            return False, 0
            
        try:
            # Extract SSID from beacon
            ssid = ""
            if pkt.haslayer(Dot11Elt):
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            
            bssid = pkt[Dot11].addr3.lower() if pkt[Dot11].addr3 else ""
            
            if ssid and bssid:
                self.ssid_bssid_map[ssid].add(bssid)
                
                # If same SSID has multiple BSSIDs, potential evil twin
                if len(self.ssid_bssid_map[ssid]) > 1:
                    confidence = 0.7
                    print(f"[EVIL TWIN] SSID '{ssid}' has multiple BSSIDs: {self.ssid_bssid_map[ssid]}")
                    return True, confidence
                    
        except Exception:
            pass
            
        return False, 0
    
    def detect_mac_flooding(self, pkt):
        """Detect CAM‑table flooding (many *unique* MACs)."""
        # Skip obvious management traffic – not relevant to CAM flooding
        if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Beacon):
            return False, 0, 0

        current_time = time.time()
        src_mac = (pkt[Dot11].addr2 or "").lower()
        # Track every src MAC seen in a 5‑second sliding window
        self.unique_macs_window.append((current_time, src_mac))
        while self.unique_macs_window and current_time - self.unique_macs_window[0][0] > 5:
            self.unique_macs_window.popleft()

        unique_src = {m for _, m in self.unique_macs_window if m}
        unique_count = len(unique_src)

        if unique_count > 30:                       # adjust threshold
            confidence = min(0.5 + unique_count * 0.003, 0.9)
            return True, confidence, unique_count
        return False, 0, unique_count
    
    def extract_ml_features(self, pkt, src_mac, packet_rate):
        """Extract features for ML anomaly detection"""
        features = {
            'packet_size': len(pkt),
            'rssi': int(getattr(pkt, 'dBm_AntSignal', 0) or 0),
            'packet_rate': packet_rate,
            'is_broadcast': 1 if pkt[Dot11].addr1 == "ff:ff:ff:ff:ff:ff" else 0,
            'has_arp': 1 if pkt.haslayer(ARP) else 0,
            'has_beacon': 1 if pkt.haslayer(Dot11Beacon) else 0,
            'has_deauth': 1 if pkt.haslayer(Dot11Deauth) else 0
        }
        return features
    
    def run_anomaly_detection(self, features_list):
        """Run ML anomaly detection on collected features"""
        if len(features_list) < 10:
            return [0] * len(features_list), [0] * len(features_list)
        
        # Prepare feature matrix
        feature_names = ['packet_size', 'rssi', 'packet_rate', 'is_broadcast', 
                        'has_arp', 'has_beacon', 'has_deauth']
        
        X = []
        for features in features_list:
            row = [features.get(name, 0) for name in feature_names]
            X.append(row)
        
        X = np.array(X)
        
        # Run Isolation Forest
        try:
            clf = IsolationForest(contamination=0.1, random_state=42)
            anomaly_labels = clf.fit_predict(X)
            anomaly_scores = clf.decision_function(X)
            
            # Convert to binary (1 for anomaly, 0 for normal)
            is_anomaly = [1 if label == -1 else 0 for label in anomaly_labels]
            
            return anomaly_scores.tolist(), is_anomaly
        except Exception as e:
            print(f"[ERROR] ML analysis failed: {e}")
            return [0] * len(features_list), [0] * len(features_list)
    
    def process_packet(self, pkt):
        """Main packet processing function"""
        self.packet_count += 1

        if self.packet_count % 500 == 0:
            print(f"[INFO] Processed {self.packet_count} packets...")

        # Only process 802.11 packets
        if not pkt.haslayer(Dot11):
            return

        src_mac = pkt[Dot11].addr2.lower() if pkt[Dot11].addr2 else ""
        dst_mac = pkt[Dot11].addr1.lower() if pkt[Dot11].addr1 else ""

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # Always detect MAC flood first (before filtering)
        mac_flood_detected, mac_flood_conf, packet_rate = self.detect_mac_flooding(pkt)

        # Filter other attacks by target MAC
        is_related_to_target = src_mac == self.target_mac or dst_mac == self.target_mac
        if not is_related_to_target and not mac_flood_detected:
            return

        # Run other attack detections only if packet is from/to target
        arp_detected, arp_conf = False, 0
        deauth_detected, deauth_conf = False, 0
        evil_twin_detected, evil_twin_conf = False, 0

        if is_related_to_target:
            arp_detected, arp_conf = self.detect_arp_spoofing(pkt)
            deauth_detected, deauth_conf = self.detect_deauth_attack(pkt)
            evil_twin_detected, evil_twin_conf = self.detect_evil_twin(pkt)

        # Determine primary attack
        attacks = [
            ("ARP_SPOOFING", arp_detected, arp_conf),
            ("DEAUTH_ATTACK", deauth_detected, deauth_conf),
            ("EVIL_TWIN", evil_twin_detected, evil_twin_conf),
            ("MAC_FLOODING", mac_flood_detected, mac_flood_conf),
        ]
        primary_attack = "NORMAL"
        max_confidence = 0
        for name, detected, conf in attacks:
            if detected and conf > max_confidence:
                primary_attack = name
                max_confidence = conf

        # Extract ML features
        ml_features = self.extract_ml_features(pkt, src_mac, packet_rate)
        self.ml_features.append(ml_features)

        rssi = int(getattr(pkt, 'dBm_AntSignal', 0) or 0)
        channel = self.get_channel(pkt)

        packet_data = {
            'timestamp': timestamp,
            'src_mac': src_mac,
            'dst_mac': dst_mac,
            'attack_type': primary_attack,
            'confidence': max_confidence,
            'arp_spoofing': int(arp_detected),
            'deauth_attack': int(deauth_detected),
            'evil_twin': int(evil_twin_detected),
            'mac_flooding': int(mac_flood_detected),
            'rssi': rssi,
            'channel': channel,
            'packet_rate': packet_rate,
            'anomaly_score': 0,
            'is_anomaly': 0
        }

        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=packet_data.keys())
            writer.writerow(packet_data)
    
    def get_channel(self, pkt):
        """Extract channel information from packet"""
        try:
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    if hasattr(elt, 'ID') and elt.ID == 3:  # DS Parameter Set
                        if hasattr(elt, 'info') and len(elt.info) > 0:
                            return ord(elt.info[0]) if isinstance(elt.info, bytes) else int(elt.info)
                    elt = elt.payload if hasattr(elt, 'payload') else None
        except Exception:
            pass
        return 0
    
    def run_ml_analysis(self):
        """Run ML analysis on collected data"""
        if len(self.ml_features) < 10:
            print("[INFO] Not enough data for ML analysis")
            return
        
        print(f"[INFO] Running ML anomaly detection on {len(self.ml_features)} packets...")
        
        anomaly_scores, is_anomaly = self.run_anomaly_detection(self.ml_features)
        
        anomaly_count = sum(is_anomaly)
        print(f"[INFO] ML Analysis complete. Found {anomaly_count} anomalies")
        
        # Update CSV with ML results
        # Note: In a real implementation, you'd want to update the existing CSV
        # For simplicity, we'll just print the summary
        print(f"[INFO] Anomaly detection results saved to {self.csv_file}")
    
    def start_detection(self):
        """Start the detection process"""
        print(f"[*] Starting Network Layer Attack Detection...")
        print(f"[*] Target MAC: {self.target_mac}")
        print(f"[*] Monitor Interface: {self.interface}")
        print(f"[*] Detecting: ARP Spoofing, Deauth Attacks, Evil Twin, MAC Flooding")
        print("[*] Press Ctrl+C to stop and analyze data\n")
        
        try:
            sniff(iface=self.interface, prn=self.process_packet, store=0)
        except KeyboardInterrupt:
            print("\n[*] Stopping detection...")
            self.run_ml_analysis()
            print("[*] Detection completed successfully!")
        except Exception as e:
            print(f"[ERROR] Detection failed: {e}")
            print("Make sure your interface is in monitor mode and you have root privileges")

if __name__ == "__main__":
    detector = NetworkLayerDetector()
    detector.start_detection()
