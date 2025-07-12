#!/usr/bin/env python3
"""
Simplified Network Layer Attack Detector for Mobile Devices
Detects: ARP Spoofing, Deauth, Evil Twin, MAC Flooding
Uses simple heuristics and thresholds for detection
"""

from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt, Dot11ProbeReq, ARP, Ether
from collections import defaultdict, deque
import csv
import time
import os
from datetime import datetime

class NetworkLayerDetector:
    def __init__(self):
        # Configuration
        self.interface = "wlan0mon"
        self.target_mac = "MAC_ID"
        self.csv_file = "network_layer_attacks.csv"
        
        # Detection data structures
        self.arp_table = {}  # IP -> MAC mapping
        self.ssid_bssid_map = defaultdict(set)  # SSID -> set of BSSIDs
        self.mac_activity = defaultdict(deque)  # MAC -> packet timestamps
        self.deauth_count = defaultdict(deque)  # Source -> deauth timestamps
        self.packet_count = 0
        self.stored_packet_count = 0
        
        # MAC flooding detection
        self.unique_macs_window = deque()   # (timestamp, src_mac) for last 5 seconds
        
        # Sampling control
        self.packet_sampling_rate = 10  # Save every 10th normal packet to CSV
        
        self.init_csv()
        
    def init_csv(self):
        """Initialize CSV file with headers"""
        headers = [
            'timestamp', 'src_mac', 'dst_mac', 'attack_type', 'confidence',
            'arp_spoofing', 'deauth_attack', 'evil_twin', 'mac_flooding',
            'rssi', 'channel', 'packet_rate', 'packet_size', 'is_broadcast',
            'has_arp', 'has_beacon', 'has_deauth', 'has_probe_req', 'is_target_related'
        ]
        
        # Only write headers if file doesn't exist
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
            print(f"[*] Created new CSV file: {self.csv_file}")
        else:
            print(f"[*] Appending to existing CSV file: {self.csv_file}")
    
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
        """Detect CAM table flooding (many unique MACs)"""
        # Skip deauth/beacon packets for MAC flooding detection
        if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Beacon):
            return False, 0, 0

        current_time = time.time()
        src_mac = (pkt[Dot11].addr2 or "").lower()
        
        # Only track valid MAC addresses
        if not src_mac or src_mac == "":
            return False, 0, 0
        
        # Track every src MAC seen in a 5-second sliding window
        self.unique_macs_window.append((current_time, src_mac))
        while self.unique_macs_window and current_time - self.unique_macs_window[0][0] > 5:
            self.unique_macs_window.popleft()

        unique_src = {m for _, m in self.unique_macs_window if m}
        unique_count = len(unique_src)

        # Threshold for MAC flooding detection
        threshold = 30
        if unique_count > threshold:
            confidence = min(0.6 + unique_count * 0.01, 0.95)
            print(f"[MAC FLOOD] Detected {unique_count} unique MACs in 5s window")
            return True, confidence, unique_count
        return False, 0, unique_count
    
    def should_store_packet(self, is_attack, is_target_related):
        """Determine if packet should be stored"""
        # Always store attacks
        if is_attack:
            return True
        
        # Always store target-related packets
        if is_target_related:
            return True
        
        # Store sample of normal packets
        return self.packet_count % self.packet_sampling_rate == 0
    
    def get_channel(self, pkt):
        """Extract channel information from packet"""
        try:
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    if hasattr(elt, 'ID') and elt.ID == 3:
                        if hasattr(elt, 'info') and len(elt.info) > 0:
                            return ord(elt.info[0]) if isinstance(elt.info, bytes) else int(elt.info)
                    elt = elt.payload if hasattr(elt, 'payload') else None
        except Exception:
            pass
        return 0
    
    def process_packet(self, pkt):
        """Main packet processing function"""
        self.packet_count += 1

        if self.packet_count % 500 == 0:
            print(f"[*] Processed {self.packet_count} packets, stored {self.stored_packet_count} packets")

        # Only process 802.11 packets
        if not pkt.haslayer(Dot11):
            return

        src_mac = pkt[Dot11].addr2.lower() if pkt[Dot11].addr2 else ""
        dst_mac = pkt[Dot11].addr1.lower() if pkt[Dot11].addr1 else ""

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # Check if packet is related to target
        is_target_related = src_mac == self.target_mac or dst_mac == self.target_mac

        # Run attack detections
        arp_detected, arp_conf = self.detect_arp_spoofing(pkt)
        deauth_detected, deauth_conf = self.detect_deauth_attack(pkt)
        evil_twin_detected, evil_twin_conf = self.detect_evil_twin(pkt)
        mac_flood_detected, mac_flood_conf, packet_rate = self.detect_mac_flooding(pkt)

        # Determine if any attack was detected
        is_attack = any([arp_detected, deauth_detected, evil_twin_detected, mac_flood_detected])

        # Determine primary attack type
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

        # Decide whether to store this packet
        if self.should_store_packet(is_attack, is_target_related):
            self.stored_packet_count += 1
            
            rssi = int(getattr(pkt, 'dBm_AntSignal', 0) or 0)
            channel = self.get_channel(pkt)

            # Save packet data
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
                'packet_size': len(pkt),
                'is_broadcast': 1 if pkt[Dot11].addr1 == "ff:ff:ff:ff:ff:ff" else 0,
                'has_arp': 1 if pkt.haslayer(ARP) else 0,
                'has_beacon': 1 if pkt.haslayer(Dot11Beacon) else 0,
                'has_deauth': 1 if pkt.haslayer(Dot11Deauth) else 0,
                'has_probe_req': 1 if pkt.haslayer(Dot11ProbeReq) else 0,
                'is_target_related': int(is_target_related)
            }

            # Save to CSV
            with open(self.csv_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=packet_data.keys())
                writer.writerow(packet_data)

        # Show attack detections
        if is_attack:
            print(f"[ATTACK] {primary_attack} detected from {src_mac} (confidence: {max_confidence:.3f})")
    
    def start_detection(self):
        """Start the detection process"""
        print(f"[*] Starting Simplified Network Layer Attack Detection...")
        print(f"[*] Target MAC: {self.target_mac}")
        print(f"[*] Monitor Interface: {self.interface}")
        print(f"[*] CSV File: {self.csv_file}")
        print(f"[*] Detecting: ARP Spoofing, Deauth Attacks, Evil Twin, MAC Flooding")
        print("[*] Press Ctrl+C to stop detection\n")
        
        try:
            sniff(iface=self.interface, prn=self.process_packet, store=0)
        except KeyboardInterrupt:
            print(f"\n[*] Stopping detection...")
            print(f"[*] Total packets processed: {self.packet_count}")
            print(f"[*] Total packets stored: {self.stored_packet_count}")
            print(f"[*] All data saved to {self.csv_file}")
            print("[*] Detection completed successfully!")
        except Exception as e:
            print(f"[ERROR] Detection failed: {e}")
            print("Make sure your interface is in monitor mode and you have root privileges")

if __name__ == "__main__":
    detector = NetworkLayerDetector()
    detector.start_detection()
