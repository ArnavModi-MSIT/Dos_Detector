#!/usr/bin/env python3

"""
Drone Application Layer Attack Detector - 5 Major Attacks
========================================================

Detects Application Protocol (Layer 7) attacks targeting drone systems:
- MAVLink Command Injection, HTTP Web Interface Attacks, MQTT Topic Hijacking, 
  Video Stream Manipulation, SSH/Telnet Brute Force

Requirements: Python 3.7+, Scapy, Root privileges
Usage: sudo python3 drone_application_detector.py
Output: CSV file with Application layer attack data

Educational/Research use only. Use responsibly.
"""

from scapy.all import sniff, IP, TCP, UDP, Raw
from collections import defaultdict
import csv
import time
import re
import struct
import base64
from datetime import datetime

class DroneApplicationLayerDetector:
    """Application Layer (Layer 7) attack detector for drone systems"""
    
    def __init__(self):
        """Initialize Application Layer detector with protocol-specific configurations"""
        # Output configuration
        self.csv_file = "drone_application_attacks.csv"
        
        # Drone ecosystem IP addresses (configure for your environment)
        self.drone_ip = ""           # Main drone IP
        self.ground_station_ip = ""  # Ground control station
        self.controller_ip = ""      # Remote controller
        
        # Application layer service ports and protocols
        self.application_ports = {
            5760: "MAVLink",         # MAVLink flight control protocol
            14550: "MAVLink_GCS",    # MAVLink Ground Control Station
            80: "HTTP",              # HTTP web interface
            8080: "HTTP_ALT",        # Alternative HTTP port
            443: "HTTPS",            # HTTPS secure web interface
            1883: "MQTT",            # MQTT IoT messaging
            8883: "MQTTS",           # MQTT over SSL/TLS
            554: "RTSP",             # Real-Time Streaming Protocol
            22: "SSH",               # Secure Shell
            23: "Telnet"             # Telnet protocol
        }
        
        # Attack pattern tracking structures
        self.mavlink_commands = defaultdict(list)        # Track MAVLink command injection
        self.http_requests = defaultdict(list)           # Track HTTP attack patterns
        self.mqtt_topics = defaultdict(dict)             # Track MQTT topic manipulation
        self.video_streams = defaultdict(dict)           # Track video stream attacks
        self.login_attempts = defaultdict(list)          # Track brute force attempts
        
        # Protocol parsers and signatures
        self.malicious_http_patterns = [
            b"<script>",           # XSS attempts
            b"SELECT * FROM",      # SQL injection
            b"../../../",          # Directory traversal
            b"<iframe",            # Iframe injection
            b"javascript:",        # JavaScript injection
            b"cmd.exe",            # Command injection
            b"/etc/passwd"         # File access attempts
        ]
        
        self.suspicious_mqtt_topics = [
            "/admin/",             # Administrative topics
            "/config/",            # Configuration topics
            "/emergency/",         # Emergency control topics
            "/override/",          # Control override topics
            "/../",                # Path traversal in topics
        ]
        
        # Detection thresholds (tune based on application behavior)
        self.mavlink_injection_limit = 20      # Max MAVLink commands per 10 seconds
        self.http_attack_limit = 15            # Max suspicious HTTP requests per 5 seconds
        self.mqtt_hijack_limit = 10            # Max topic manipulation per 5 seconds
        self.video_manipulation_threshold = 0.4  # 40% stream quality degradation
        self.brute_force_limit = 8             # Max login attempts per 30 seconds
        
        # Performance statistics
        self.packets_processed = 0
        self.attacks_detected = 0
        
        self.init_csv()
    
    def init_csv(self):
        """Initialize CSV file with Application Layer specific headers"""
        headers = [
            'timestamp',            # When attack was detected
            'src_ip',              # Source IP address
            'dst_ip',              # Destination IP address
            'src_port',            # Source port number
            'dst_port',            # Destination port number
            'protocol',            # Application protocol
            'attack_type',         # Type of Layer 7 attack
            'severity',            # Attack severity (1-10)
            'attack_details',      # Attack-specific information
            'payload_sample',      # Sample of malicious payload
            'service_targeted',    # Drone service being attacked
        ]
        
        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
    
    def is_drone_application_traffic(self, pkt):
        """
        Filter packets to identify drone-related application layer traffic
        
        Focuses on application protocols used by drone systems
        """
        if not pkt.haslayer(IP):
            return False
            
        # Must have transport layer and payload
        if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)) or not pkt.haslayer(Raw):
            return False
            
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Check if packet involves drone ecosystem IPs
        drone_ips = [self.drone_ip, self.ground_station_ip, self.controller_ip]
        involves_drone_ip = src_ip in drone_ips or dst_ip in drone_ips
        
        # Check if packet involves application layer drone ports
        if pkt.haslayer(TCP):
            port = pkt[TCP].dport
        else:  # UDP
            port = pkt[UDP].dport
            
        involves_app_port = port in self.application_ports
        
        return involves_drone_ip or involves_app_port
    
    def detect_mavlink_injection(self, pkt):
        """
        Attack 1: MAVLink Command Injection Detection
        
        Identifies malicious flight control commands injected into MAVLink protocol
        including dangerous commands and command flooding
        """
        # Filter for MAVLink packets (UDP with payload)
        if not (pkt.haslayer(UDP) and pkt.haslayer(Raw)):
            return False, 0, ""
            
        # Check for MAVLink ports
        if pkt[UDP].dport not in [5760, 14550]:
            return False, 0, ""
            
        payload = bytes(pkt[Raw])
        if len(payload) < 8:
            return False, 0, ""
            
        try:
            # Parse MAVLink v2.0 packets (magic byte 0xFD)
            if payload[0] == 0xFD:
                msg_len = payload[1]
                system_id = payload[5]
                component_id = payload[6]
                msg_id = struct.unpack('<I', payload[7:11])[0] & 0xFFFFFF
                
                current_time = time.time()
                src_ip = pkt[IP].src
                
                # Track MAVLink command frequency
                self.mavlink_commands[src_ip].append((current_time, msg_id))
                
                # Remove old entries (older than 10 seconds)
                self.mavlink_commands[src_ip] = [
                    (t, mid) for t, mid in self.mavlink_commands[src_ip]
                    if current_time - t <= 10
                ]
                
                command_rate = len(self.mavlink_commands[src_ip])
                
                # Check for dangerous MAVLink commands
                dangerous_commands = {
                    76: "COMMAND_LONG",         # Generic command
                    11: "SET_MODE",             # Flight mode change
                    400: "COMPONENT_ARM_DISARM", # Arm/disarm motors
                    21: "PARAM_SET",            # Parameter modification
                    84: "SET_POSITION_TARGET",   # Position control
                }
                
                # Detect command injection based on rate and type
                if command_rate > self.mavlink_injection_limit:
                    cmd_name = dangerous_commands.get(msg_id, f"MSG_{msg_id}")
                    details = f"rate:{command_rate}/10s,cmd:{cmd_name},sys_id:{system_id}"
                    severity = min(8 + (command_rate // 10), 10)
                    return True, severity, details
                
                # Check for dangerous command types
                if msg_id in dangerous_commands:
                    recent_dangerous = sum(1 for t, mid in self.mavlink_commands[src_ip] 
                                         if mid in dangerous_commands and current_time - t <= 5)
                    if recent_dangerous > 5:  # Too many dangerous commands
                        cmd_name = dangerous_commands[msg_id]
                        details = f"dangerous_cmd:{cmd_name},count:{recent_dangerous}/5s"
                        return True, 9, details  # High severity
                        
        except Exception:
            pass  # Handle packet parsing errors
            
        return False, 0, ""
    
    def detect_http_attacks(self, pkt):
        """
        Attack 2: HTTP Web Interface Attacks Detection
        
        Identifies web-based attacks against drone HTTP interfaces including
        XSS, SQL injection, directory traversal, and command injection
        """
        # Filter for HTTP traffic (TCP with payload)
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return False, 0, ""
            
        # Check for HTTP ports
        if pkt[TCP].dport not in [80, 8080, 443]:
            return False, 0, ""
            
        payload = bytes(pkt[Raw])
        payload_str = payload.decode('utf-8', errors='ignore')
        
        # Look for HTTP request patterns
        if not (payload_str.startswith('GET ') or payload_str.startswith('POST ') or 
               payload_str.startswith('PUT ') or payload_str.startswith('DELETE ')):
            return False, 0, ""
            
        current_time = time.time()
        src_ip = pkt[IP].src
        
        # Check for malicious patterns in HTTP requests
        attack_patterns_found = []
        for pattern in self.malicious_http_patterns:
            if pattern in payload:
                attack_patterns_found.append(pattern.decode('utf-8', errors='ignore'))
        
        # Track HTTP attack attempts
        self.http_requests[src_ip].append(current_time)
        
        # Remove old entries (older than 5 seconds)
        self.http_requests[src_ip] = [
            t for t in self.http_requests[src_ip]
            if current_time - t <= 5
        ]
        
        request_rate = len(self.http_requests[src_ip])
        
        # Detect attacks based on malicious patterns or excessive requests
        if attack_patterns_found:
            attack_types = ','.join(attack_patterns_found[:3])  # Limit to first 3
            details = f"malicious_patterns:{attack_types},rate:{request_rate}/5s"
            severity = min(7 + len(attack_patterns_found), 10)
            return True, severity, details
            
        elif request_rate > self.http_attack_limit:
            details = f"http_flood:rate:{request_rate}/5s"
            severity = min(request_rate // 3, 10)
            return True, severity, details
            
        return False, 0, ""
    
    def detect_mqtt_hijacking(self, pkt):
        """
        Attack 3: MQTT Topic Hijacking Detection
        
        Identifies MQTT topic manipulation attacks including unauthorized
        topic access, malicious payloads, and topic flooding
        """
        # Filter for MQTT traffic (TCP with payload)
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return False, 0, ""
            
        # Check for MQTT ports
        if pkt[TCP].dport not in [1883, 8883]:
            return False, 0, ""
            
        payload = bytes(pkt[Raw])
        if len(payload) < 2:
            return False, 0, ""
            
        try:
            # Simple MQTT packet parsing (simplified)
            # MQTT fixed header: first byte contains message type
            mqtt_type = (payload[0] >> 4) & 0x0F
            
            current_time = time.time()
            src_ip = pkt[IP].src
            
            # Track MQTT message patterns
            if src_ip not in self.mqtt_topics:
                self.mqtt_topics[src_ip] = {
                    'messages': [],
                    'suspicious_topics': 0
                }
            
            self.mqtt_topics[src_ip]['messages'].append(current_time)
            
            # Remove old entries (older than 5 seconds)
            self.mqtt_topics[src_ip]['messages'] = [
                t for t in self.mqtt_topics[src_ip]['messages']
                if current_time - t <= 5
            ]
            
            message_rate = len(self.mqtt_topics[src_ip]['messages'])
            
            # Check for suspicious MQTT topics in payload
            payload_str = payload.decode('utf-8', errors='ignore')
            suspicious_found = []
            for topic_pattern in self.suspicious_mqtt_topics:
                if topic_pattern in payload_str:
                    suspicious_found.append(topic_pattern)
                    self.mqtt_topics[src_ip]['suspicious_topics'] += 1
            
            # Detect MQTT attacks
            if suspicious_found:
                topics = ','.join(suspicious_found)
                details = f"suspicious_topics:{topics},total_suspicious:{self.mqtt_topics[src_ip]['suspicious_topics']}"
                return True, 8, details
                
            elif message_rate > self.mqtt_hijack_limit:
                details = f"mqtt_flood:rate:{message_rate}/5s,type:{mqtt_type}"
                severity = min(message_rate // 2, 10)
                return True, severity, details
                
        except Exception:
            pass  # Handle MQTT parsing errors
            
        return False, 0, ""
    
    def detect_video_manipulation(self, pkt):
        """
        Attack 4: Video Stream Manipulation Detection
        
        Identifies attacks against video streams including stream injection,
        quality manipulation, and unauthorized stream access
        """
        # Filter for RTSP/video traffic
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return False, 0, ""
            
        # Check for video streaming ports
        if pkt[TCP].dport != 554:  # RTSP port
            return False, 0, ""
            
        payload = bytes(pkt[Raw])
        payload_str = payload.decode('utf-8', errors='ignore')
        
        # Look for RTSP protocol patterns
        if not any(method in payload_str for method in ['DESCRIBE', 'SETUP', 'PLAY', 'TEARDOWN', 'OPTIONS']):
            return False, 0, ""
            
        current_time = time.time()
        src_ip = pkt[IP].src
        stream_key = f"{src_ip}:{pkt[TCP].sport}"
        
        # Initialize stream tracking
        if stream_key not in self.video_streams:
            self.video_streams[stream_key] = {
                'requests': [],
                'suspicious_commands': 0,
                'last_quality_check': current_time
            }
        
        stream = self.video_streams[stream_key]
        stream['requests'].append(current_time)
        
        # Remove old requests (older than 10 seconds)
        stream['requests'] = [
            t for t in stream['requests']
            if current_time - t <= 10
        ]
        
        request_rate = len(stream['requests'])
        
        # Check for suspicious RTSP commands
        suspicious_rtsp_patterns = [
            'User-Agent: exploit',
            'Authorization: Basic',  # Brute force attempts
            'Range: bytes=',         # Unusual range requests
            'Transport: RTP/AVP/TCP' # TCP streaming (unusual)
        ]
        
        suspicious_found = []
        for pattern in suspicious_rtsp_patterns:
            if pattern in payload_str:
                suspicious_found.append(pattern)
                stream['suspicious_commands'] += 1
        
        # Detect video manipulation attacks
        if suspicious_found:
            patterns = ','.join(suspicious_found[:2])  # Limit output
            details = f"rtsp_attack:{patterns},total_suspicious:{stream['suspicious_commands']}"
            return True, 7, details
            
        elif request_rate > 20:  # Excessive RTSP requests
            details = f"rtsp_flood:rate:{request_rate}/10s"
            severity = min(request_rate // 5, 10)
            return True, severity, details
            
        return False, 0, ""
    
    def detect_brute_force(self, pkt):
        """
        Attack 5: SSH/Telnet Brute Force Detection
        
        Identifies brute force attacks against SSH and Telnet services
        by monitoring authentication attempt patterns
        """
        # Filter for SSH/Telnet traffic
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return False, 0, ""
            
        # Check for SSH/Telnet ports
        if pkt[TCP].dport not in [22, 23]:
            return False, 0, ""
            
        payload = bytes(pkt[Raw])
        current_time = time.time()
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        service = "SSH" if dst_port == 22 else "Telnet"
        
        # Track login attempts
        self.login_attempts[src_ip].append(current_time)
        
        # Remove old attempts (older than 30 seconds)
        self.login_attempts[src_ip] = [
            t for t in self.login_attempts[src_ip]
            if current_time - t <= 30
        ]
        
        attempt_count = len(self.login_attempts[src_ip])
        
        # Look for authentication-related patterns
        auth_patterns = []
        
        if dst_port == 22:  # SSH
            ssh_patterns = [b'SSH-2.0', b'diffie-hellman', b'password', b'publickey']
            auth_patterns = [p for p in ssh_patterns if p in payload]
        else:  # Telnet
            telnet_patterns = [b'login:', b'password:', b'Login incorrect']
            auth_patterns = [p for p in telnet_patterns if p in payload]
        
        # Detect brute force based on attempt frequency
        if attempt_count > self.brute_force_limit:
            patterns_str = ','.join([p.decode('utf-8', errors='ignore') for p in auth_patterns[:2]])
            details = f"brute_force:{service},attempts:{attempt_count}/30s,patterns:{patterns_str}"
            severity = min(6 + (attempt_count // 5), 10)
            return True, severity, details
            
        return False, 0, ""
    
    def process_packet(self, pkt):
        """
        Main packet processing pipeline for Application Layer attacks
        
        Runs all 5 attack detection modules and logs results
        """
        self.packets_processed += 1
        
        # Filter for drone-related application traffic only
        if not self.is_drone_application_traffic(pkt):
            return
            
        # Extract application layer information
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Initialize application layer fields
        src_port = dst_port = 0
        protocol = "OTHER"
        
        # Extract protocol information
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            protocol = "TCP"
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "UDP"
        
        # Get application service name
        service_targeted = self.application_ports.get(dst_port, "Unknown")
        
        # Extract payload sample for analysis
        payload_sample = ""
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            # Get first 50 characters of payload for logging
            payload_sample = payload[:50].decode('utf-8', errors='ignore').replace('\n', '\\n')
        
        # Execute all Application Layer attack detection modules
        attacks = [
            ("MAVLINK_INJECTION", self.detect_mavlink_injection(pkt)),
            ("HTTP_ATTACK", self.detect_http_attacks(pkt)),
            ("MQTT_HIJACKING", self.detect_mqtt_hijacking(pkt)),
            ("VIDEO_MANIPULATION", self.detect_video_manipulation(pkt)),
            ("BRUTE_FORCE", self.detect_brute_force(pkt))
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
            print(f"[{attack_type}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                  f"({service_targeted}) severity:{severity} - {details}")
        
        # Log all drone application traffic to CSV
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
            'payload_sample': payload_sample,
            'service_targeted': service_targeted
        }
        
        # Write to CSV file for ML analysis
        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=packet_data.keys())
            writer.writerow(packet_data)
        
        # Periodic progress updates
        if self.packets_processed % 500 == 0:
            print(f"[INFO] Processed: {self.packets_processed}, Attacks: {self.attacks_detected}")
    
    def start_detection(self):
        """Start Application Layer attack detection with protocol filtering"""
        print("[*] Drone Application Layer Attack Detector - 5 Attacks")
        print(f"[*] Target Drone: {self.drone_ip}")
        print(f"[*] Ground Station: {self.ground_station_ip}")
        print(f"[*] Controller: {self.controller_ip}")
        print("[*] Detecting:")
        print("    1. MAVLink Command Injection")
        print("    2. HTTP Web Interface Attacks")
        print("    3. MQTT Topic Hijacking")
        print("    4. Video Stream Manipulation")
        print("    5. SSH/Telnet Brute Force")
        print("[*] Application Ports:", list(self.application_ports.keys()))
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            # Create BPF filter for application layer protocols
            app_ports = ','.join(map(str, self.application_ports.keys()))
            drone_filter = (f"((tcp or udp) and (port {app_ports.replace(',', ' or port ')})) and "
                          f"(host {self.drone_ip} or host {self.ground_station_ip} or "
                          f"host {self.controller_ip})")
            
            # Start packet capture with application layer filter
            sniff(filter=drone_filter, prn=self.process_packet, store=0)
            
        except KeyboardInterrupt:
            # Graceful shutdown with statistics
            print(f"\n[*] Application Layer detection stopped")
            print(f"[*] Total packets processed: {self.packets_processed}")
            print(f"[*] Total attacks detected: {self.attacks_detected}")
            print(f"[*] Results saved to: {self.csv_file}")
            
            # Display application layer statistics
            if self.attacks_detected > 0:
                print("\n[*] Application Attack Summary:")
                print(f"    - MAVLink sources monitored: {len(self.mavlink_commands)}")
                print(f"    - HTTP attack sources: {len(self.http_requests)}")
                print(f"    - MQTT sessions tracked: {len(self.mqtt_topics)}")
                print(f"    - Video streams monitored: {len(self.video_streams)}")
                print(f"    - Brute force sources: {len(self.login_attempts)}")
            
        except Exception as e:
            print(f"[ERROR] Detection failed: {e}")

# Main execution block
if __name__ == "__main__":
    # Create and start Application Layer detector
    detector = DroneApplicationLayerDetector()
    detector.start_detection()
