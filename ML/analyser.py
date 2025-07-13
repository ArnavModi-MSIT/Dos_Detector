#!/usr/bin/env python3

"""
Simple Packet Analyzer with Machine Learning Detection
=====================================================

A lightweight network traffic analyzer that:
- Captures packets in real-time (both monitor and managed modes)
- Detects suspicious patterns using rule-based checks
- Uses machine learning models for advanced threat detection
- Provides real-time alerts and statistics

Key Features:
- Supports both wireless (monitor mode) and wired traffic
- Combines rule-based and ML detection for better accuracy
- Lightweight and easy to configure
- Real-time statistics and attack logging

Usage:
1. Configure target IP and interfaces
2. Choose monitor/managed mode
3. Run and view real-time detection results

Dependencies:
- scapy, pandas, numpy, joblib
"""

import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, Ether
import time
from datetime import datetime
import threading
import queue
from collections import defaultdict, deque
import json

class SimplePacketAnalyzer:
    def __init__(self, model_path="combined_rf_model.pkl"):
        """
        Initialize the packet analyzer with default settings
        
        Parameters:
        - model_path: Path to trained ML model file (default: "combined_rf_model.pkl")
        """
        self.model_path = model_path
        self.target_ip = "192.168.0.139"  # IP address to monitor
        self.monitor_interface = "wlan1"  # Interface for monitor mode (wireless)
        self.managed_interface = "wlan1"  # Interface for managed mode (normal traffic)
        
        # Initialize data structures
        self.packet_queue = queue.Queue()  # Thread-safe packet queue
        self.attack_count = 0             # Total attacks detected
        self.packet_count = 0             # Total packets processed
        self.start_time = time.time()     # Runtime tracking
        self.recent_attacks = deque(maxlen=50)  # Circular buffer for recent attacks
        
        # Load ML model on startup
        self.load_model()
        
        # Print startup banner
        print(f"🔍 Simple Packet Analyzer Ready")
        print(f"🎯 Target IP: {self.target_ip}")
        print(f"📡 Monitor Interface: {self.monitor_interface}")
        print(f"🌐 Managed Interface: {self.managed_interface}")
    
    def load_model(self):
        """Load the trained machine learning model from file"""
        try:
            self.models = joblib.load(self.model_path)
            print("✅ Model loaded successfully!")
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            self.models = {}  # Continue with rule-based detection only
    
    def extract_basic_features(self, packet):
        """
        Extract network features from a packet for ML analysis
        
        Parameters:
        - packet: Scapy packet object
        
        Returns:
        Dictionary of extracted features
        """
        features = {}
        
        # Basic packet characteristics
        features['packet_size'] = len(packet)
        
        # IP layer features
        if packet.haslayer(IP):
            ip = packet[IP]
            features['ip_len'] = ip.len      # IP packet length
            features['ttl'] = ip.ttl        # Time-to-live
            features['protocol'] = ip.proto  # Protocol number
            features['flags'] = ip.flags    # IP flags
        else:
            # Default values for non-IP packets
            features['ip_len'] = 0
            features['ttl'] = 64
            features['protocol'] = 0
            features['flags'] = 0
        
        # Transport layer features
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            features['src_port'] = tcp.sport  # Source port
            features['dst_port'] = tcp.dport  # Destination port
            features['tcp_flags'] = tcp.flags  # TCP flags (SYN, ACK, etc.)
            features['window'] = tcp.window    # TCP window size
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            features['src_port'] = udp.sport
            features['dst_port'] = udp.dport
            # UDP doesn't have flags/window
            features['tcp_flags'] = 0
            features['window'] = 0
        else:
            # Default values for non-TCP/UDP
            features['src_port'] = 0
            features['dst_port'] = 0
            features['tcp_flags'] = 0
            features['window'] = 0
        
        return features
    
    def is_suspicious(self, packet):
        """
        Rule-based detection for common attack patterns
        
        Parameters:
        - packet: Scapy packet object
        
        Returns:
        Tuple of (is_suspicious: bool, attack_type: str)
        """
        # Check for malformed packet sizes
        if len(packet) < 20 or len(packet) > 9000:
            return True, "unusual_packet_size"
        
        if packet.haslayer(IP):
            ip = packet[IP]
            
            # Suspicious TTL values (too low or invalid)
            if ip.ttl < 10 or ip.ttl > 255:
                return True, "unusual_ttl"
            
            # Fragmented packets (potential evasion technique)
            if ip.flags & 0x1:  # More fragments flag
                return True, "fragmented_packet"
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            
            # SYN flood detection (SYN without ACK)
            if tcp.flags == 0x02:  # SYN flag only
                return True, "potential_syn_flood"
            
            # Unusual same-port communication
            if tcp.sport == tcp.dport:
                return True, "same_port_attack"
        
        # If none of the rules matched
        return False, "normal"
    
    def analyze_packet(self, packet):
        """
        Analyze a network packet using both rule-based and ML detection
        
        Parameters:
        - packet: Scapy packet object
        
        Returns:
        Dictionary of attack details if detected, None otherwise
        """
        # Skip packets not related to our target IP
        if packet.haslayer(IP):
            ip = packet[IP]
            if ip.src != self.target_ip and ip.dst != self.target_ip:
                return None
        
        # First check with simple rules (fast)
        is_sus, attack_type = self.is_suspicious(packet)
        
        if is_sus:
            return {
                'attack_type': attack_type,
                'confidence': 0.8,  # High confidence for rule-based
                'src_ip': packet[IP].src if packet.haslayer(IP) else 'N/A',
                'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'N/A',
                'protocol': packet[IP].proto if packet.haslayer(IP) else 'N/A'
            }
        
        # If no rule matched, try ML model if available
        if self.models:
            try:
                features = self.extract_basic_features(packet)
                
                # Use first available model
                for layer_name, model_data in self.models.items():
                    if 'model' in model_data:
                        model = model_data['model']
                        
                        # Prepare DataFrame with features
                        df = pd.DataFrame([features])
                        
                        # Ensure all expected features are present
                        if hasattr(model, 'feature_names_in_'):
                            for feature in model.feature_names_in_:
                                if feature not in df.columns:
                                    df[feature] = 0  # Fill missing with default
                            df = df[model.feature_names_in_]  # Reorder columns
                        
                        # Get model prediction
                        prediction = model.predict(df)[0]
                        proba = model.predict_proba(df)[0]
                        confidence = max(proba)  # Highest class probability
                        
                        # Only report high-confidence attacks
                        if prediction == 1 and confidence > 0.7:
                            return {
                                'attack_type': f'{layer_name}_attack',
                                'confidence': confidence,
                                'src_ip': packet[IP].src if packet.haslayer(IP) else 'N/A',
                                'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'N/A',
                                'protocol': packet[IP].proto if packet.haslayer(IP) else 'N/A'
                            }
                        break  # Only use first model for now
            except Exception as e:
                print(f"⚠️ ML analysis error: {e}")
        
        return None  # No attack detected
    
    def packet_handler(self, packet):
        """
        Callback function for packet capture
        Adds packets to processing queue and counts them
        """
        self.packet_count += 1
        self.packet_queue.put(packet)
    
    def process_packets(self):
        """
        Worker thread function to process packets from queue
        Runs continuously in background
        """
        while True:
            try:
                packet = self.packet_queue.get(timeout=1)
                result = self.analyze_packet(packet)
                
                if result:
                    self.handle_attack(result)  # Take action if attack detected
                
                self.packet_queue.task_done()
                
            except queue.Empty:
                continue  # Normal timeout, check again
            except Exception as e:
                print(f"❌ Processing error: {e}")
    
    def handle_attack(self, result):
        """
        Handle a detected attack by logging and alerting
        
        Parameters:
        - result: Dictionary of attack details
        """
        self.attack_count += 1
        
        # Create attack record
        timestamp = datetime.now().strftime("%H:%M:%S")
        attack_info = {
            'time': timestamp,
            'type': result['attack_type'],
            'confidence': result['confidence'],
            'src': result['src_ip'],
            'dst': result['dst_ip']
        }
        
        # Add to recent attacks buffer
        self.recent_attacks.append(attack_info)
        
        # Print real-time alert
        print(f"🚨 ATTACK: {timestamp} | {result['attack_type']} | "
              f"{result['src_ip']} -> {result['dst_ip']} | "
              f"Confidence: {result['confidence']:.2f}")
    
    def print_stats(self):
        """Print summary statistics every 30 seconds"""
        runtime = time.time() - self.start_time
        
        print(f"\n📊 STATS: {self.packet_count} packets | "
              f"{self.attack_count} attacks | {runtime:.0f}s runtime")
        
        if self.recent_attacks:
            print("🕐 Recent attacks:")
            for attack in list(self.recent_attacks)[-3:]:  # Show last 3
                print(f"   {attack['time']} | {attack['type']} | "
                      f"{attack['src']} -> {attack['dst']}")
        print()
    
    def start_monitoring(self, use_monitor_mode=True):
        """
        Start the main monitoring loop
        
        Parameters:
        - use_monitor_mode: Whether to use wireless monitor mode (True)
                           or standard managed mode (False)
        """
        interface = self.monitor_interface if use_monitor_mode else self.managed_interface
        
        print(f"\n🚀 Starting monitoring on {interface}")
        print(f"🎯 Target: {self.target_ip}")
        print("Press Ctrl+C to stop\n")
        
        # Start background processing thread
        processing_thread = threading.Thread(target=self.process_packets, daemon=True)
        processing_thread.start()
        
        # Start periodic stats thread
        def stats_loop():
            while True:
                time.sleep(30)
                self.print_stats()
        
        stats_thread = threading.Thread(target=stats_loop, daemon=True)
        stats_thread.start()
        
        try:
            # Main capture loop (blocks until interrupted)
            sniff(iface=interface, prn=self.packet_handler, store=0)
            
        except KeyboardInterrupt:
            print("\n🛑 Stopping...")
            self.print_stats()
            self.save_results()
    
    def save_results(self):
        """Save analysis results to JSON file"""
        results = {
            'total_packets': self.packet_count,
            'total_attacks': self.attack_count,
            'runtime': time.time() - self.start_time,
            'target_ip': self.target_ip,
            'attacks': list(self.recent_attacks)
        }
        
        filename = f"analysis_{datetime.now().strftime('%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"💾 Saved to: {filename}")


def main():
    """
    Main function to run the packet analyzer
    Handles user input and starts monitoring
    """
    # Initialize analyzer with default settings
    analyzer = SimplePacketAnalyzer()
    
    # User interface for mode selection
    print("\nSelect interface mode:")
    print("1. Monitor mode (wlan1) - for wireless monitoring")
    print("2. Managed mode (wlan0) - for normal network traffic")
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    # Start monitoring in selected mode
    use_monitor = choice == "1"
    analyzer.start_monitoring(use_monitor_mode=use_monitor)


if __name__ == "__main__":
    main()
