#!/usr/bin/env python3

"""
Drone Transport Layer Attack Detector - 5 Major Attacks
======================================================

Detects Transport Protocol (Layer 4) attacks targeting drone systems:
- SYN Flooding, UDP Flooding, Port Scanning, Connection Hijacking, Session Replay

Requirements: Python 3.7+, Scapy, Root privileges
Usage: sudo python3 drone_transport_detector.py
Output: CSV file with Transport layer attack data

Educational/Research use only. Use responsibly.
"""

from scapy.all import sniff, IP, TCP, UDP, Raw
from collections import defaultdict
import csv
import time
import hashlib
from datetime import datetime

class DroneTransportLayerDetector:
    """Transport Layer (Layer 4) attack detector for drone systems"""
    
    def __init__(self):
        """Initialize Transport Layer detector with TCP/UDP specific configurations"""
        # Output configuration
        self.csv_file = "drone_transport_attacks.csv"
        
        # Drone ecosystem IP addresses (configure for your environment)
        self.drone_ip = ""           # Main drone IP
        self.ground_station_ip = ""  # Ground control station
        self.controller_ip = ""      # Remote controller
        
        # Critical drone service ports
        self.drone_ports = {
            5760: "MAVLink",     # MAVLink protocol
            14550: "MAVLink_GCS", # MAVLink Ground Control
            554: "RTSP",         # Video streaming
            1883: "MQTT",        # IoT messaging
            8080: "HTTP_ALT",    # Alternative HTTP
            22: "SSH",           # Secure shell
            23: "Telnet"         # Telnet access
        }
        
        # Attack pattern tracking structures
        self.syn_counts = defaultdict(list)          # Track SYN flood patterns
        self.udp_counts = defaultdict(list)          # Track UDP flood patterns  
        self.port_scans = defaultdict(set)           # Track port scanning attempts
        self.tcp_connections = defaultdict(dict)     # Track TCP connection states
        self.session_hashes = defaultdict(list)      # Track session replay attempts
        
        # Detection thresholds (tune based on network environment)
        self.syn_flood_limit = 30           # Max SYN packets per 5 seconds
        self.udp_flood_limit = 50           # Max UDP packets per 5 seconds
        self.port_scan_limit = 10           # Max ports scanned per 10 seconds
        self.hijack_sequence_threshold = 5   # Max out-of-sequence packets
        self.replay_time_threshold = 2       # Max seconds for replay detection
        
        # Performance statistics
        self.packets_processed = 0
        self.attacks_detected = 0
        
        self.init_csv()
    
    def init_csv(self):
        """Initialize CSV file with Transport Layer specific headers"""
        headers = [
            'timestamp',        # When attack was detected
            'src_ip',          # Source IP address
            'dst_ip',          # Destination IP address  
            'src_port',        # Source port number
            'dst_port',        # Destination port number
            'protocol',        # Transport protocol (TCP/UDP)
            'attack_type',     # Type of Layer 4 attack
            'severity',        # Attack severity (1-10)
            'attack_details',  # Attack-specific information
            'tcp_flags',       # TCP flags (if applicable)
            'sequence_num',    # TCP sequence number
            'payload_size'     # Size of transport payload
        ]
        
        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
    
    def is_drone_transport_traffic(self, pkt):
        """
        Filter packets to identify drone-related transport layer traffic
        
        Focuses on TCP/UDP communications involving drone ecosystem
        """
        if not pkt.haslayer(IP):
            return False
            
        # Must have transport layer (TCP or UDP)
        if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            return False
            
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Check if packet involves drone ecosystem IPs
        drone_ips = [self.drone_ip, self.ground_station_ip, self.controller_ip]
        involves_drone_ip = src_ip in drone_ips or dst_ip in drone_ips
        
        # Check if packet involves critical drone ports
        if pkt.haslayer(TCP):
            port = pkt[TCP].dport
        else:  # UDP
            port = pkt[UDP].dport
            
        involves_drone_port = port in self.drone_ports
        
        return involves_drone_ip or involves_drone_port
    
    def detect_syn_flood(self, pkt):
        """
        Attack 1: TCP SYN Flood Detection
        
        Identifies SYN flooding attacks that can overwhelm drone TCP services
        by exhausting connection state tables
        """
        # Filter for TCP packets only
        if not pkt.haslayer(TCP):
            return False, 0, ""
            
        tcp_flags = pkt[TCP].flags
        
        # Check for SYN packets (SYN=1, ACK=0)
        if tcp_flags & 0x02 and not (tcp_flags & 0x10):  # SYN flag set, ACK not set
            current_time = time.time()
            src_ip = pkt[IP].src
            dst_port = pkt[TCP].dport
            
            # Track SYN packet rate using sliding window
            self.syn_counts[src_ip].append(current_time)
            
            # Maintain 5-second sliding window
            self.syn_counts[src_ip] = [
                t for t in self.syn_counts[src_ip] 
                if current_time - t <= 5
            ]
            
            syn_rate = len(self.syn_counts[src_ip])
            
            # Alert on excessive SYN rate
            if syn_rate > self.syn_flood_limit:
                details = f"syn_rate:{syn_rate}/5s,target_port:{dst_port}"
                severity = min(syn_rate // 3, 10)  # Scale severity with rate
                return True, severity, details
                
        return False, 0, ""
    
    def detect_udp_flood(self, pkt):
        """
        Attack 2: UDP Flood Detection
        
        Monitors for excessive UDP traffic targeting drone services,
        particularly MAVLink and video streaming protocols
        """
        # Filter for UDP packets only
        if not pkt.haslayer(UDP):
            return False, 0, ""
            
        current_time = time.time()
        src_ip = pkt[IP].src
        dst_port = pkt[UDP].dport
        
        # Track UDP packet rate using sliding window
        self.udp_counts[src_ip].append(current_time)
        
        # Maintain 5-second sliding window
        self.udp_counts[src_ip] = [
            t for t in self.udp_counts[src_ip] 
            if current_time - t <= 5
        ]
        
        udp_rate = len(self.udp_counts[src_ip])
        
        # Alert on excessive UDP rate
        if udp_rate > self.udp_flood_limit:
            service = self.drone_ports.get(dst_port, "Unknown")
            details = f"udp_rate:{udp_rate}/5s,service:{service},port:{dst_port}"
            severity = min(udp_rate // 5, 10)  # Scale severity with rate
            return True, severity, details
            
        return False, 0, ""
    
    def detect_port_scan(self, pkt):
        """
        Attack 3: Port Scanning Detection
        
        Identifies reconnaissance attempts against drone services
        by monitoring connection attempts to multiple ports
        """
        # Works with both TCP and UDP
        if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
            return False, 0, ""
            
        current_time = time.time()
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Extract destination port
        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
            # Only count SYN packets for TCP scanning
            if not (pkt[TCP].flags & 0x02):  # Not a SYN packet
                return False, 0, ""
        else:  # UDP
            dst_port = pkt[UDP].dport
        
        # Track unique ports accessed per source IP
        scan_key = f"{src_ip}->{dst_ip}"
        self.port_scans[scan_key].add(dst_port)
        
        # Clean old scan data (older than 10 seconds)
        # Note: This is simplified - in production, you'd want time-based cleanup
        unique_ports = len(self.port_scans[scan_key])
        
        # Alert on scanning multiple ports
        if unique_ports > self.port_scan_limit:
            drone_ports_hit = [p for p in self.port_scans[scan_key] if p in self.drone_ports]
            details = f"ports_scanned:{unique_ports},drone_ports:{len(drone_ports_hit)}"
            severity = min(unique_ports // 2, 10)
            return True, severity, details
            
        return False, 0, ""
    
    def detect_connection_hijack(self, pkt):
        """
        Attack 4: TCP Connection Hijacking Detection
        
        Identifies attempts to hijack existing TCP connections
        by monitoring sequence number anomalies
        """
        # Only applicable to TCP
        if not pkt.haslayer(TCP):
            return False, 0, ""
            
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        seq_num = pkt[TCP].seq
        ack_num = pkt[TCP].ack
        tcp_flags = pkt[TCP].flags
        
        # Create connection identifier
        conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        
        # Track TCP connection state
        if conn_key not in self.tcp_connections:
            self.tcp_connections[conn_key] = {
                'expected_seq': seq_num + 1,
                'last_ack': ack_num,
                'out_of_sequence': 0,
                'established': False
            }
        
        conn = self.tcp_connections[conn_key]
        
        # Check if connection is established (has seen SYN-ACK)
        if tcp_flags & 0x12:  # SYN-ACK
            conn['established'] = True
            conn['expected_seq'] = seq_num + 1
            return False, 0, ""
        
        # Only check established connections
        if not conn['established']:
            return False, 0, ""
        
        # Check for sequence number anomalies
        if seq_num != conn['expected_seq']:
            conn['out_of_sequence'] += 1
            
            # Alert on excessive out-of-sequence packets (potential hijacking)
            if conn['out_of_sequence'] > self.hijack_sequence_threshold:
                details = f"seq_anomalies:{conn['out_of_sequence']},expected:{conn['expected_seq']},got:{seq_num}"
                return True, 8, details  # High severity for connection hijacking
        else:
            # Reset counter on valid sequence
            conn['out_of_sequence'] = max(0, conn['out_of_sequence'] - 1)
            
        # Update expected sequence number
        if pkt.haslayer(Raw):
            conn['expected_seq'] = seq_num + len(pkt[Raw])
        
        return False, 0, ""
    
    def detect_session_replay(self, pkt):
        """
        Attack 5: Session Replay Attack Detection
        
        Identifies replay attacks by detecting duplicate payloads
        within suspicious time windows
        """
        # Applicable to both TCP and UDP with payload
        if not pkt.haslayer(Raw):
            return False, 0, ""
            
        current_time = time.time()
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        payload = bytes(pkt[Raw])
        
        # Create payload hash for duplicate detection
        payload_hash = hashlib.md5(payload).hexdigest()
        
        # Track payload hashes with timestamps
        session_key = f"{src_ip}->{dst_ip}"
        
        # Look for recent identical payloads
        for timestamp, old_hash in self.session_hashes[session_key]:
            if current_time - timestamp <= self.replay_time_threshold:
                if payload_hash == old_hash:
                    # Found duplicate payload within suspicious timeframe
                    details = f"replay_detected,hash:{payload_hash[:8]},time_diff:{current_time-timestamp:.2f}s"
                    return True, 7, details  # Medium-high severity
        
        # Store current payload hash
        self.session_hashes[session_key].append((current_time, payload_hash))
        
        # Clean old hashes (keep only last 10 seconds)
        self.session_hashes[session_key] = [
            (t, h) for t, h in self.session_hashes[session_key]
            if current_time - t <= 10
        ]
        
        return False, 0, ""
    
    def process_packet(self, pkt):
        """
        Main packet processing pipeline for Transport Layer attacks
        
        Runs all 5 attack detection modules and logs results
        """
        self.packets_processed += 1
        
        # Filter for drone-related transport traffic only
        if not self.is_drone_transport_traffic(pkt):
            return
            
        # Extract transport layer information
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Initialize transport layer fields
        src_port = dst_port = 0
        protocol = "OTHER"
        tcp_flags = 0
        sequence_num = 0
        payload_size = 0
        
        # Extract protocol-specific information
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            protocol = "TCP"
            tcp_flags = pkt[TCP].flags
            sequence_num = pkt[TCP].seq
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "UDP"
            
        # Calculate payload size
        if pkt.haslayer(Raw):
            payload_size = len(pkt[Raw])
        
        # Execute all Transport Layer attack detection modules
        attacks = [
            ("SYN_FLOOD", self.detect_syn_flood(pkt)),
            ("UDP_FLOOD", self.detect_udp_flood(pkt)),
            ("PORT_SCAN", self.detect_port_scan(pkt)),
            ("CONNECTION_HIJACK", self.detect_connection_hijack(pkt)),
            ("SESSION_REPLAY", self.detect_session_replay(pkt))
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
            service = self.drone_ports.get(dst_port, "Unknown")
            print(f"[{attack_type}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                  f"({service}) severity:{severity} - {details}")
        
        # Log all drone transport traffic to CSV
        packet_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'attack_type': attack_type,
            'severity': severity,
            'attack_details': details,
            'tcp_flags': tcp_flags,
            'sequence_num': sequence_num,
            'payload_size': payload_size
        }
        
        # Write to CSV file for ML analysis
        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=packet_data.keys())
            writer.writerow(packet_data)
        
        # Periodic progress updates
        if self.packets_processed % 500 == 0:
            print(f"[INFO] Processed: {self.packets_processed}, Attacks: {self.attacks_detected}")
    
    def start_detection(self):
        """Start Transport Layer attack detection with protocol filtering"""
        print("[*] Drone Transport Layer Attack Detector - 5 Attacks")
        print(f"[*] Target Drone: {self.drone_ip}")
        print(f"[*] Ground Station: {self.ground_station_ip}")
        print(f"[*] Controller: {self.controller_ip}")
        print("[*] Detecting:")
        print("    1. TCP SYN Flooding")
        print("    2. UDP Flooding")  
        print("    3. Port Scanning")
        print("    4. TCP Connection Hijacking")
        print("    5. Session Replay Attacks")
        print("[*] Critical Ports:", list(self.drone_ports.keys()))
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            # Create BPF filter for TCP/UDP traffic involving drone IPs
            drone_filter = (f"(tcp or udp) and "
                          f"(host {self.drone_ip} or host {self.ground_station_ip} or "
                          f"host {self.controller_ip})")
            
            # Start packet capture with transport layer filter
            sniff(filter=drone_filter, prn=self.process_packet, store=0)
            
        except KeyboardInterrupt:
            # Graceful shutdown with statistics
            print(f"\n[*] Transport Layer detection stopped")
            print(f"[*] Total packets processed: {self.packets_processed}")
            print(f"[*] Total attacks detected: {self.attacks_detected}")
            print(f"[*] Results saved to: {self.csv_file}")
            
            # Display attack breakdown
            if self.attacks_detected > 0:
                print("\n[*] Attack Summary:")
                print(f"    - Connection state tracking: {len(self.tcp_connections)} TCP connections")
                print(f"    - Port scan sources: {len(self.port_scans)} unique scanners")
                print(f"    - Session replay tracking: {len(self.session_hashes)} sessions")
            
        except Exception as e:
            print(f"[ERROR] Detection failed: {e}")

# Main execution block
if __name__ == "__main__":
    # Create and start Transport Layer detector
    detector = DroneTransportLayerDetector()
    detector.start_detection()
