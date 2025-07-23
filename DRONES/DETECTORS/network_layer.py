#!/usr/bin/env python3

"""
Enhanced Basic Drone Attack Detector - 5 Major Attacks
=====================================================
Detects: Command Flooding, GPS Spoofing, Video Hijacking, MQTT Flooding, Wi-Fi Deauth
"""

from scapy.all import sniff, IP, UDP, TCP, Raw, Dot11
from collections import defaultdict
import csv
import time
from datetime import datetime

class Enhanced5AttackDetector:
    def __init__(self):
        """Initialize detector for 5 major drone attacks"""
        self.csv_file = "network_layer_attacks.csv"
        self.drone_ip = "IP"
        
        # Critical drone ports
        self.mavlink_port = 5760     # MAVLink commands
        self.video_port = 554        # Video stream  
        self.mqtt_port = 1883        # MQTT messages
        self.http_port = 8080        # Drone web interface
        
        # Attack counters
        self.command_counts = defaultdict(list)
        self.mqtt_counts = defaultdict(list)
        self.deauth_counts = defaultdict(list)
        self.gps_positions = []
        self.video_streams = defaultdict(dict)
        
        # Simple thresholds
        self.command_flood_limit = 15    # Commands per 5 seconds
        self.mqtt_flood_limit = 25       # MQTT messages per 5 seconds
        self.deauth_limit = 10           # Deauth frames per 5 seconds
        self.gps_jump_limit = 50         # Meters sudden change
        self.video_anomaly_size = 100    # Minimum video packet size
        
        # Stats
        self.packets_processed = 0
        self.attacks_found = 0
        
        self.init_csv()
    
    def init_csv(self):
        """Create CSV with features for 5 attacks"""
        headers = [
            'timestamp', 'src_ip', 'dst_ip', 'port', 'protocol',
            'attack_type', 'severity', 'packet_size', 'attack_details'
        ]
        
        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
    
    def is_drone_traffic(self, pkt):
        """Check if packet is drone-related"""
        # Check for IP layer
        if pkt.haslayer(IP):
            involves_drone = (pkt[IP].src == self.drone_ip or pkt[IP].dst == self.drone_ip)
            
            if pkt.haslayer(UDP) or pkt.haslayer(TCP):
                port = pkt[UDP].dport if pkt.haslayer(UDP) else pkt[TCP].dport
                critical_port = port in [self.mavlink_port, self.video_port, self.mqtt_port, self.http_port]
                return involves_drone or critical_port
        
        # Check for Wi-Fi frames (802.11)
        if pkt.haslayer(Dot11):
            return True
            
        return False
    
    def detect_command_flood(self, pkt):
        """Attack 1: MAVLink Command Flooding"""
        if not pkt.haslayer(UDP) or pkt[UDP].dport != self.mavlink_port:
            return False, 0, ""
            
        current_time = time.time()
        src_ip = pkt[IP].src
        
        # Track command rate
        self.command_counts[src_ip].append(current_time)
        
        # Keep only last 5 seconds
        self.command_counts[src_ip] = [
            t for t in self.command_counts[src_ip] 
            if current_time - t <= 5
        ]
        
        command_rate = len(self.command_counts[src_ip])
        
        if command_rate > self.command_flood_limit:
            details = f"rate:{command_rate}/5s"
            return True, min(command_rate, 10), details
            
        return False, 0, ""
    
    def detect_gps_spoof(self, pkt):
        """Attack 2: GPS Spoofing Detection"""
        if not (pkt.haslayer(UDP) and pkt.haslayer(Raw)):
            return False, 0, ""
            
        payload = bytes(pkt[Raw])
        
        # Simple GPS spoofing detection
        if len(payload) >= 20 and pkt[UDP].dport == self.mavlink_port:
            try:
                # Look for GPS-related MAVLink messages (simplified)
                if len(payload) > 30:
                    # Simulate GPS coordinate analysis
                    current_time = time.time()
                    
                    # Basic GPS anomaly detection
                    if len(self.gps_positions) > 0:
                        last_time = self.gps_positions[-1]
                        if current_time - last_time < 1:  # Rapid GPS updates
                            details = "rapid_gps_changes"
                            return True, 8, details
                    
                    self.gps_positions.append(current_time)
                    
                    # Keep only recent positions
                    self.gps_positions = [
                        t for t in self.gps_positions 
                        if current_time - t <= 10
                    ]
                    
            except:
                pass
                
        return False, 0, ""
    
    def detect_video_hijack(self, pkt):
        """Attack 3: Video Stream Hijacking"""
        if not pkt.haslayer(UDP) or pkt[UDP].dport != self.video_port:
            return False, 0, ""
            
        stream_key = f"{pkt[IP].src}:{pkt[UDP].sport}"
        packet_size = len(pkt)
        
        # Track stream characteristics
        if stream_key not in self.video_streams:
            self.video_streams[stream_key] = {
                'packet_count': 0,
                'avg_size': packet_size,
                'anomalies': 0
            }
        
        stream = self.video_streams[stream_key]
        stream['packet_count'] += 1
        
        # Update average packet size
        stream['avg_size'] = (stream['avg_size'] + packet_size) / 2
        
        # Detect anomalies
        if packet_size < self.video_anomaly_size:  # Too small for video
            stream['anomalies'] += 1
            
        # Check for video hijacking indicators
        if stream['packet_count'] > 10:
            anomaly_rate = stream['anomalies'] / stream['packet_count']
            if anomaly_rate > 0.3:  # 30% anomalous packets
                details = f"anomaly_rate:{anomaly_rate:.2f}"
                return True, 7, details
                
        return False, 0, ""
    
    def detect_mqtt_flood(self, pkt):
        """Attack 4: MQTT Message Flooding"""
        if not pkt.haslayer(TCP) or pkt[TCP].dport != self.mqtt_port:
            return False, 0, ""
            
        current_time = time.time()
        src_ip = pkt[IP].src
        
        # Track MQTT message rate
        self.mqtt_counts[src_ip].append(current_time)
        
        # Keep only last 5 seconds
        self.mqtt_counts[src_ip] = [
            t for t in self.mqtt_counts[src_ip] 
            if current_time - t <= 5
        ]
        
        mqtt_rate = len(self.mqtt_counts[src_ip])
        
        if mqtt_rate > self.mqtt_flood_limit:
            details = f"mqtt_rate:{mqtt_rate}/5s"
            return True, min(mqtt_rate // 3, 10), details
            
        return False, 0, ""
    
    def detect_wifi_deauth(self, pkt):
        """Attack 5: Wi-Fi Deauthentication Attack"""
        if not pkt.haslayer(Dot11):
            return False, 0, ""
            
        # Check for deauthentication frames
        if pkt.type == 0 and pkt.subtype == 12:  # Deauth frame
            current_time = time.time()
            src_mac = pkt.addr2 if pkt.addr2 else "unknown"
            
            # Track deauth rate
            self.deauth_counts[src_mac].append(current_time)
            
            # Keep only last 5 seconds
            self.deauth_counts[src_mac] = [
                t for t in self.deauth_counts[src_mac] 
                if current_time - t <= 5
            ]
            
            deauth_rate = len(self.deauth_counts[src_mac])
            
            if deauth_rate > self.deauth_limit:
                details = f"deauth_rate:{deauth_rate}/5s,mac:{src_mac}"
                return True, 9, details
                
        return False, 0, ""
    
    def process_packet(self, pkt):
        """Process packets for all 5 attacks"""
        self.packets_processed += 1
        
        if not self.is_drone_traffic(pkt):
            return
        
        # Extract basic info
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"
        
        port = 0
        protocol = "OTHER"
        
        if pkt.haslayer(UDP):
            port = pkt[UDP].dport
            protocol = "UDP"
        elif pkt.haslayer(TCP):
            port = pkt[TCP].dport
            protocol = "TCP"
        elif pkt.haslayer(Dot11):
            protocol = "802.11"
        
        # Run all 5 attack detections
        attacks = [
            ("COMMAND_FLOOD", self.detect_command_flood(pkt)),
            ("GPS_SPOOF", self.detect_gps_spoof(pkt)),
            ("VIDEO_HIJACK", self.detect_video_hijack(pkt)),
            ("MQTT_FLOOD", self.detect_mqtt_flood(pkt)),
            ("WIFI_DEAUTH", self.detect_wifi_deauth(pkt))
        ]
        
        # Find highest severity attack
        attack_type = "NORMAL"
        severity = 0
        details = ""
        
        for attack_name, (detected, attack_severity, attack_details) in attacks:
            if detected and attack_severity > severity:
                attack_type = attack_name
                severity = attack_severity
                details = attack_details
        
        # Count and report attacks
        if attack_type != "NORMAL":
            self.attacks_found += 1
            print(f"[{attack_type}] from {src_ip} (severity: {severity}) - {details}")
        
        # Save to CSV
        packet_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'port': port,
            'protocol': protocol,
            'attack_type': attack_type,
            'severity': severity,
            'packet_size': len(pkt),
            'attack_details': details
        }
        
        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=packet_data.keys())
            writer.writerow(packet_data)
        
        # Progress update
        if self.packets_processed % 500 == 0:
            print(f"[INFO] Processed: {self.packets_processed}, Attacks: {self.attacks_found}")
    
    def start_detection(self):
        """Start 5-attack detection"""
        print("[*] Enhanced Drone Attack Detector - 5 Attacks")
        print(f"[*] Target Drone: {self.drone_ip}")
        print("[*] Detecting:")
        print("    1. Command Flooding (MAVLink)")
        print("    2. GPS Spoofing")
        print("    3. Video Stream Hijacking")
        print("    4. MQTT Message Flooding")
        print("    5. Wi-Fi Deauthentication")
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            # Monitor both IP and Wi-Fi traffic
            sniff(prn=self.process_packet, store=0)
            
        except KeyboardInterrupt:
            print(f"\n[*] Detection stopped")
            print(f"[*] Total packets processed: {self.packets_processed}")
            print(f"[*] Total attacks detected: {self.attacks_found}")
            print(f"[*] Results saved to: {self.csv_file}")
            
        except Exception as e:
            print(f"[ERROR] Detection failed: {e}")

if __name__ == "__main__":
    detector = Enhanced5AttackDetector()
    detector.start_detection()

