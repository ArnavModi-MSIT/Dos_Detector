#!/usr/bin/env python3

"""
Drone Internet Layer Attack Detector - 5 Major Attacks
=====================================================

Detects Internet Protocol (Layer 3) attacks targeting drone systems:
- IP Spoofing, GPS Coordinate Injection, Routing Attacks, ICMP Flooding, IP Fragmentation

Requirements: Python 3.7+, Scapy, Root privileges
Usage: sudo python3 drone_internet_detector.py
Output: CSV file with Internet layer attack data

Educational/Research use only. Use responsibly.
"""

from scapy.all import sniff, IP, ICMP, UDP, TCP, Raw
from collections import defaultdict
import csv
import time
from datetime import datetime

class DroneInternetLayerDetector:
    """Internet Layer (Layer 3) attack detector for drone systems"""
    
    def __init__(self):
        """Initialize Internet Layer detector with IP-specific configurations"""
        # Output configuration
        self.csv_file = "drone_internet_attacks.csv"
        
        # Drone ecosystem IP addresses (configure for your environment)
        self.drone_ip = ""           # Main drone IP
        self.ground_station_ip = ""  # Ground control station
        self.controller_ip = ""      # Remote controller
        
        # Known legitimate network gateways (whitelist)
        self.legitimate_gateways = [""]
        
        # Attack pattern tracking (using defaultdict for automatic initialization)
        self.ip_sources = defaultdict(set)           # Track MAC-to-IP mappings for spoofing
        self.gps_injections = defaultdict(list)      # Track GPS injection frequency
        self.routing_anomalies = defaultdict(list)   # Track routing manipulation attempts
        self.icmp_counts = defaultdict(list)         # Track ICMP flood patterns
        self.fragment_attacks = defaultdict(list)    # Track fragmentation attacks
        
        # Detection thresholds (tune based on your network environment)
        self.ip_spoof_threshold = 3         # Max MACs per IP before flagging spoof
        self.gps_inject_limit = 10          # Max GPS injections per 10 seconds
        self.routing_anomaly_limit = 5      # Max routing anomalies per 10 seconds
        self.icmp_flood_limit = 20          # Max ICMP packets per 5 seconds
        self.fragment_limit = 15            # Max fragments per 5 seconds
        
        # Performance statistics
        self.packets_processed = 0
        self.attacks_detected = 0
        
        self.init_csv()
    
    def init_csv(self):
        """Initialize CSV file with Internet Layer specific headers"""
        headers = [
            'timestamp',      # When attack was detected
            'src_ip',         # Source IP address
            'dst_ip',         # Destination IP address
            'ttl',            # Time To Live (routing hops)
            'packet_id',      # IP packet identifier
            'protocol',       # IP protocol number
            'attack_type',    # Type of Layer 3 attack
            'severity',       # Attack severity (1-10)
            'attack_details', # Attack-specific information
            'is_fragmented'   # Whether packet is fragmented
        ]
        
        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
    
    def is_drone_internet_traffic(self, pkt):
        """
        Filter packets to identify drone-related IP traffic
        
        Focuses on Layer 3 communications between drone ecosystem components
        """
        if not pkt.haslayer(IP):
            return False
            
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Check if packet involves any drone ecosystem IP
        drone_ips = [self.drone_ip, self.ground_station_ip, self.controller_ip]
        return src_ip in drone_ips or dst_ip in drone_ips
    
    def detect_ip_spoofing(self, pkt):
        """
        Attack 1: IP Address Spoofing Detection
        
        Identifies when multiple MAC addresses claim the same IP address,
        indicating potential ARP poisoning or IP spoofing attacks
        """
        if not pkt.haslayer(IP):
            return False, 0, ""
            
        src_ip = pkt[IP].src
        # Extract source MAC address (if available at this layer)
        src_mac = pkt.src if hasattr(pkt, 'src') else "unknown"
        
        # Track unique MAC addresses for each IP
        self.ip_sources[src_ip].add(src_mac)
        unique_macs = len(self.ip_sources[src_ip])
        
        # Alert if too many MACs use same IP
        if unique_macs > self.ip_spoof_threshold:
            details = f"ip:{src_ip},macs:{unique_macs}"
            severity = min(unique_macs + 5, 10)  # Scale severity with MAC count
            return True, severity, details
            
        return False, 0, ""
    
    def detect_gps_injection(self, pkt):
        """
        Attack 2: GPS Coordinate Injection at IP Level
        
        Monitors MAVLink GPS messages for excessive injection attempts
        that could indicate GPS spoofing attacks
        """
        # Filter for MAVLink packets with payload
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(Raw)):
            return False, 0, ""
            
        # Check for MAVLink protocol port
        if pkt[UDP].dport != 5760:  # MAVLink standard port
            return False, 0, ""
            
        payload = bytes(pkt[Raw])
        current_time = time.time()
        src_ip = pkt[IP].src
        
        # Look for MAVLink GPS messages
        if len(payload) >= 20:
            try:
                # Check for MAVLink v2 magic byte (0xFD)
                if payload[0] == 0xFD:
                    # Track GPS injection rate using sliding window
                    self.gps_injections[src_ip].append(current_time)
                    
                    # Maintain 10-second sliding window
                    self.gps_injections[src_ip] = [
                        t for t in self.gps_injections[src_ip] 
                        if current_time - t <= 10
                    ]
                    
                    injection_rate = len(self.gps_injections[src_ip])
                    
                    # Alert on excessive GPS injection rate
                    if injection_rate > self.gps_inject_limit:
                        details = f"gps_rate:{injection_rate}/10s,from:{src_ip}"
                        return True, 8, details  # High severity for GPS attacks
                        
            except:
                pass  # Handle potential packet parsing errors
                
        return False, 0, ""
    
    def detect_routing_attack(self, pkt):
        """
        Attack 3: IP Routing Manipulation Detection
        
        Identifies suspicious routing behavior including:
        - Abnormal TTL values indicating route manipulation
        - Traffic from unexpected gateways
        """
        if not pkt.haslayer(IP):
            return False, 0, ""
            
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl = pkt[IP].ttl
        current_time = time.time()
        
        anomaly_detected = False
        details = ""
        
        # Check for suspicious TTL values
        # Normal TTL: Linux=64, Windows=128, network equipment varies
        if ttl > 128 or ttl < 10:
            anomaly_detected = True
            details += f"suspicious_ttl:{ttl},"
        
        # Check for traffic from unexpected sources to drone
        if (dst_ip == self.drone_ip and 
            src_ip not in self.legitimate_gateways and
            not src_ip.startswith("192.168.4.")):  # Not in expected subnet
            
            anomaly_detected = True
            details += f"unexpected_gateway:{src_ip},"
        
        if anomaly_detected:
            # Track routing anomaly frequency
            route_key = f"{src_ip}->{dst_ip}"
            self.routing_anomalies[route_key].append(current_time)
            
            # Maintain 10-second sliding window
            self.routing_anomalies[route_key] = [
                t for t in self.routing_anomalies[route_key] 
                if current_time - t <= 10
            ]
            
            anomaly_count = len(self.routing_anomalies[route_key])
            
            # Alert on persistent routing anomalies
            if anomaly_count > self.routing_anomaly_limit:
                details += f"anomaly_count:{anomaly_count}"
                return True, 7, details
                
        return False, 0, ""
    
    def detect_icmp_flood(self, pkt):
        """
        Attack 4: ICMP Flooding Detection
        
        Monitors for excessive ICMP traffic that could indicate:
        - Ping floods targeting drone systems
        - ICMP-based DoS attacks
        """
        # Filter for ICMP packets only
        if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
            return False, 0, ""
            
        current_time = time.time()
        src_ip = pkt[IP].src
        icmp_type = pkt[ICMP].type  # ICMP message type (ping=8, pong=0, etc.)
        
        # Track ICMP packet rate using sliding window
        self.icmp_counts[src_ip].append(current_time)
        
        # Maintain 5-second sliding window
        self.icmp_counts[src_ip] = [
            t for t in self.icmp_counts[src_ip] 
            if current_time - t <= 5
        ]
        
        icmp_rate = len(self.icmp_counts[src_ip])
        
        # Alert on excessive ICMP rate
        if icmp_rate > self.icmp_flood_limit:
            details = f"icmp_rate:{icmp_rate}/5s,type:{icmp_type}"
            severity = min(icmp_rate // 2, 10)  # Scale severity with rate
            return True, severity, details
            
        return False, 0, ""
    
    def detect_fragmentation_attack(self, pkt):
        """
        Attack 5: IP Fragmentation Attack Detection
        
        Identifies excessive IP fragmentation which can indicate:
        - Fragment flood DoS attacks
        - Attempts to evade intrusion detection
        - Malformed packet attacks
        """
        if not pkt.haslayer(IP):
            return False, 0, ""
            
        # Check IP fragmentation flags and offset
        flags = pkt[IP].flags      # Fragmentation control flags
        frag_offset = pkt[IP].frag # Fragment offset field
        
        # Detect fragmented packets (More Fragments flag or non-zero offset)
        if flags & 1 or frag_offset > 0:  # MF=1 or offset>0
            current_time = time.time()
            src_ip = pkt[IP].src
            
            # Track fragmentation rate using sliding window
            self.fragment_attacks[src_ip].append(current_time)
            
            # Maintain 5-second sliding window
            self.fragment_attacks[src_ip] = [
                t for t in self.fragment_attacks[src_ip] 
                if current_time - t <= 5
            ]
            
            fragment_rate = len(self.fragment_attacks[src_ip])
            
            # Alert on excessive fragmentation
            if fragment_rate > self.fragment_limit:
                details = f"frag_rate:{fragment_rate}/5s,flags:{flags},offset:{frag_offset}"
                return True, 6, details  # Medium severity
                
        return False, 0, ""
    
    def process_packet(self, pkt):
        """
        Main packet processing pipeline for Internet Layer attacks
        
        Runs all 5 attack detection modules and logs results
        """
        self.packets_processed += 1
        
        # Filter for drone-related traffic only
        if not self.is_drone_internet_traffic(pkt):
            return
            
        # Extract IP layer information for analysis
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl = pkt[IP].ttl
        packet_id = pkt[IP].id      # IP identification field
        protocol = pkt[IP].proto    # Protocol number (TCP=6, UDP=17, ICMP=1)
        is_fragmented = bool(pkt[IP].flags & 1 or pkt[IP].frag > 0)
        
        # Execute all Internet Layer attack detection modules
        attacks = [
            ("IP_SPOOFING", self.detect_ip_spoofing(pkt)),
            ("GPS_INJECTION", self.detect_gps_injection(pkt)),
            ("ROUTING_ATTACK", self.detect_routing_attack(pkt)),
            ("ICMP_FLOOD", self.detect_icmp_flood(pkt)),
            ("FRAG_ATTACK", self.detect_fragmentation_attack(pkt))
        ]
        
        # Determine highest severity attack
        attack_type = "NORMAL"
        severity = 0
        details = ""
        
        for attack_name, (detected, attack_severity, attack_details) in attacks:
            if detected and attack_severity > severity:
                attack_type = attack_name
                severity = attack_severity
                details = attack_details
        
        # Handle attack detection and alerting
        if attack_type != "NORMAL":
            self.attacks_detected += 1
            print(f"[{attack_type}] {src_ip} -> {dst_ip} (severity: {severity}) - {details}")
        
        # Log all drone Internet traffic to CSV
        packet_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'ttl': ttl,
            'packet_id': packet_id,
            'protocol': protocol,
            'attack_type': attack_type,
            'severity': severity,
            'attack_details': details,
            'is_fragmented': int(is_fragmented)
        }
        
        # Write to CSV file for ML analysis
        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=packet_data.keys())
            writer.writerow(packet_data)
        
        # Periodic progress updates
        if self.packets_processed % 500 == 0:
            print(f"[INFO] Processed: {self.packets_processed}, Attacks: {self.attacks_detected}")
    
    def start_detection(self):
        """Start Internet Layer attack detection with BPF filtering"""
        print("[*] Drone Internet Layer Attack Detector - 5 Attacks")
        print(f"[*] Target Drone: {self.drone_ip}")
        print(f"[*] Ground Station: {self.ground_station_ip}")
        print(f"[*] Controller: {self.controller_ip}")
        print("[*] Detecting:")
        print("    1. IP Address Spoofing")
        print("    2. GPS Coordinate Injection")
        print("    3. IP Routing Attacks")
        print("    4. ICMP Flooding")
        print("    5. IP Fragmentation Attacks")
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            # Create Berkeley Packet Filter for efficient capture
            # Only capture packets involving drone ecosystem IPs
            drone_filter = f"host {self.drone_ip} or host {self.ground_station_ip} or host {self.controller_ip}"
            
            # Start packet capture with filter
            sniff(filter=drone_filter, prn=self.process_packet, store=0)
            
        except KeyboardInterrupt:
            # Graceful shutdown with statistics
            print(f"\n[*] Internet Layer detection stopped")
            print(f"[*] Total packets processed: {self.packets_processed}")
            print(f"[*] Total attacks detected: {self.attacks_detected}")
            print(f"[*] Results saved to: {self.csv_file}")
            
        except Exception as e:
            print(f"[ERROR] Detection failed: {e}")

# Main execution block
if __name__ == "__main__":
    # Create and start Internet Layer detector
    detector = DroneInternetLayerDetector()
    detector.start_detection()

