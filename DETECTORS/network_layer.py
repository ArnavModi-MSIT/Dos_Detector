#!/usr/bin/env python3
"""
Simplified Network Layer Attack Detector for Mobile Devices
=========================================================

Detects common wireless network attacks using lightweight heuristics:
- ARP Spoofing: Detects IP-MAC binding inconsistencies
- Deauthentication Attacks: Identifies excessive deauth packets
- Evil Twin: Detects multiple APs with same SSID
- MAC Flooding: Identifies CAM table overflow attempts

Features:
- Real-time detection with configurable thresholds
- CSV logging for analysis and model training
- Packet sampling to reduce storage needs
- Target device focus for reduced false positives
"""

from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt, Dot11ProbeReq, ARP, Ether
from collections import defaultdict, deque
import csv
import time
import os
from datetime import datetime

class NetworkLayerDetector:
    def __init__(self):
        """Initialize detector with default configuration"""
        # Network configuration
        self.interface = "wlan0mon"  # Monitor mode interface
        self.target_mac = "MAC_ID"   # MAC of device to protect
        self.csv_file = "network_layer_attacks.csv"  # Log file
        
        # Detection data structures
        self.arp_table = {}  # Maps IP addresses to MAC addresses
        self.ssid_bssid_map = defaultdict(set)  # Tracks SSID to BSSID mappings
        self.mac_activity = defaultdict(deque)  # Tracks MAC activity timestamps
        self.deauth_count = defaultdict(deque)  # Counts deauth packets per source
        
        # Statistics
        self.packet_count = 0         # Total packets processed
        self.stored_packet_count = 0  # Packets saved to CSV
        
        # MAC flooding detection window (5 seconds)
        self.unique_macs_window = deque()  
        
        # Sampling configuration
        self.packet_sampling_rate = 10  # Store 1 in 10 normal packets
        
        # Initialize CSV log file
        self.init_csv()
        
    def init_csv(self):
        """Initialize CSV file with required headers"""
        headers = [
            'timestamp', 'src_mac', 'dst_mac', 'attack_type', 'confidence',
            'arp_spoofing', 'deauth_attack', 'evil_twin', 'mac_flooding',
            'rssi', 'channel', 'packet_rate', 'packet_size', 'is_broadcast',
            'has_arp', 'has_beacon', 'has_deauth', 'has_probe_req', 'is_target_related'
        ]
        
        # Create new file only if it doesn't exist
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
            print(f"[*] Created new CSV file: {self.csv_file}")
        else:
            print(f"[*] Appending to existing CSV file: {self.csv_file}")
    
    def detect_arp_spoofing(self, pkt):
        """
        Detect ARP spoofing attacks by checking for IP-MAC inconsistencies
        
        Args:
            pkt: Scapy packet object
            
        Returns:
            tuple: (detected: bool, confidence: float)
        """
        if not pkt.haslayer(ARP):
            return False, 0
            
        arp_layer = pkt[ARP]
        src_ip = arp_layer.psrc
        src_mac = arp_layer.hwsrc.lower()
        
        # Check if this IP was previously mapped to different MAC
        if src_ip in self.arp_table:
            if self.arp_table[src_ip] != src_mac:
                confidence = 0.8  # High confidence for changed MAC
                print(f"[ARP SPOOF] IP {src_ip} changed from MAC {self.arp_table[src_ip]} to {src_mac}")
                return True, confidence
        else:
            # Add new IP-MAC mapping
            self.arp_table[src_ip] = src_mac
            
        return False, 0
    
    def detect_deauth_attack(self, pkt):
        """
        Detect deauthentication flood attacks
        
        Args:
            pkt: Scapy packet object
            
        Returns:
            tuple: (detected: bool, confidence: float)
        """
        if not pkt.haslayer(Dot11Deauth):
            return False, 0
            
        src_mac = pkt[Dot11].addr2.lower() if pkt[Dot11].addr2 else ""
        current_time = time.time()
        
        # Track deauth packets in 10-second sliding window
        self.deauth_count[src_mac].append(current_time)
        
        # Remove old entries (>10 seconds)
        while (self.deauth_count[src_mac] and 
               current_time - self.deauth_count[src_mac][0] > 10):
            self.deauth_count[src_mac].popleft()
        
        # Trigger if >5 deauths in 10 seconds
        deauth_rate = len(self.deauth_count[src_mac])
        if deauth_rate > 5:
            confidence = min(0.7 + (deauth_rate * 0.05), 0.95)
            print(f"[DEAUTH ATTACK] {src_mac} sent {deauth_rate} deauth packets")
            return True, confidence
            
        return False, 0
    
    def detect_evil_twin(self, pkt):
        """
        Detect evil twin APs (multiple APs with same SSID)
        
        Args:
            pkt: Scapy packet object
            
        Returns:
            tuple: (detected: bool, confidence: float)
        """
        if not pkt.haslayer(Dot11Beacon):
            return False, 0
            
        try:
            # Extract SSID from beacon frame
            ssid = ""
            if pkt.haslayer(Dot11Elt):
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            
            bssid = pkt[Dot11].addr3.lower() if pkt[Dot11].addr3 else ""
            
            if ssid and bssid:
                self.ssid_bssid_map[ssid].add(bssid)
                
                # Evil twin detected if same SSID has multiple BSSIDs
                if len(self.ssid_bssid_map[ssid]) > 1:
                    confidence = 0.7
                    print(f"[EVIL TWIN] SSID '{ssid}' has multiple BSSIDs: {self.ssid_bssid_map[ssid]}")
                    return True, confidence
                    
        except Exception:
            pass
            
        return False, 0
    
    def detect_mac_flooding(self, pkt):
        """
        Detect MAC flooding attacks (CAM table overflow)
        
        Args:
            pkt: Scapy packet object
            
        Returns:
            tuple: (detected: bool, confidence: float, unique_count: int)
        """
        # Skip management frames for flooding detection
        if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Beacon):
            return False, 0, 0

        current_time = time.time()
        src_mac = (pkt[Dot11].addr2 or "").lower()
        
        # Skip invalid MACs
        if not src_mac:
            return False, 0, 0
        
        # Track MACs in 5-second window
        self.unique_macs_window.append((current_time, src_mac))
        while self.unique_macs_window and current_time - self.unique_macs_window[0][0] > 5:
            self.unique_macs_window.popleft()

        # Count unique MACs
        unique_src = {m for _, m in self.unique_macs_window if m}
        unique_count = len(unique_src)

        # Trigger if >30 unique MACs in 5 seconds
        threshold = 30
        if unique_count > threshold:
            confidence = min(0.6 + unique_count * 0.01, 0.95)
            print(f"[MAC FLOOD] Detected {unique_count} unique MACs in 5s window")
            return True, confidence, unique_count
        return False, 0, unique_count
    
    def should_store_packet(self, is_attack, is_target_related):
        """
        Determine if packet should be stored in CSV
        
        Args:
            is_attack: Whether attack was detected
            is_target_related: Whether packet involves target device
            
        Returns:
            bool: True if packet should be stored
        """
        # Always store attacks and target-related packets
        if is_attack or is_target_related:
            return True
        
        # Sample normal packets at configured rate
        return self.packet_count % self.packet_sampling_rate == 0
    
    def get_channel(self, pkt):
        """
        Extract channel number from 802.11 packet
        
        Args:
            pkt: Scapy packet object
            
        Returns:
            int: Channel number or 0 if not found
        """
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
    
    def process_packet(self, pkt):
        """Main packet processing handler"""
        self.packet_count += 1

        # Periodic status update
        if self.packet_count % 500 == 0:
            print(f"[*] Processed {self.packet_count} packets, stored {self.stored_packet_count} packets")

        # Only process 802.11 packets
        if not pkt.haslayer(Dot11):
            return

        # Extract MAC addresses
        src_mac = pkt[Dot11].addr2.lower() if pkt[Dot11].addr2 else ""
        dst_mac = pkt[Dot11].addr1.lower() if pkt[Dot11].addr1 else ""

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # Check if packet involves target device
        is_target_related = src_mac == self.target_mac or dst_mac == self.target_mac

        # Run all detection modules
        arp_detected, arp_conf = self.detect_arp_spoofing(pkt)
        deauth_detected, deauth_conf = self.detect_deauth_attack(pkt)
        evil_twin_detected, evil_twin_conf = self.detect_evil_twin(pkt)
        mac_flood_detected, mac_flood_conf, packet_rate = self.detect_mac_flooding(pkt)

        # Determine if any attack was detected
        is_attack = any([arp_detected, deauth_detected, evil_twin_detected, mac_flood_detected])

        # Identify primary attack type (highest confidence)
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

        # Store packet if it meets criteria
        if self.should_store_packet(is_attack, is_target_related):
            self.stored_packet_count += 1
            
            # Extract packet features
            rssi = int(getattr(pkt, 'dBm_AntSignal', 0) or 0)
            channel = self.get_channel(pkt)

            # Prepare CSV record
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

            # Append to CSV
            with open(self.csv_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=packet_data.keys())
                writer.writerow(packet_data)

        # Print attack alerts
        if is_attack:
            print(f"[ATTACK] {primary_attack} detected from {src_mac} (confidence: {max_confidence:.3f})")
    
    def start_detection(self):
        """Start the packet capture and detection process"""
        print(f"[*] Starting Simplified Network Layer Attack Detection...")
        print(f"[*] Target MAC: {self.target_mac}")
        print(f"[*] Monitor Interface: {self.interface}")
        print(f"[*] CSV File: {self.csv_file}")
        print(f"[*] Detecting: ARP Spoofing, Deauth Attacks, Evil Twin, MAC Flooding")
        print("[*] Press Ctrl+C to stop detection\n")
        
        try:
            # Start packet capture
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
    # Create and start detector
    detector = NetworkLayerDetector()
    detector.start_detection()
