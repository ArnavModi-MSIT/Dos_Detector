# Network Security Detection System

[![Network Security](https://img.shields.io/badge/Network-Security-blue)]() 
[![Python](https://img.shields.io/badge/Python-3.8+-yellow)]() 
[![Scapy](https://img.shields.io/badge/Scapy-Packet%20Analysis-green)]()
[![License](https://img.shields.io/badge/License-MIT-green)]()

A comprehensive multi-layer network security detection system that monitors and detects various types of attacks across OSI model layers. Combines rule-based detection with machine learning for advanced threat identification.

## Table of Contents
- Features
- Detection Modules
- Setup Instructions
- Usage
- Output
- Troubleshooting
- Contributing
- License

## Features

- Multi-layer detection: Covers attacks across all OSI model layers
- Real-time monitoring: Detects attacks as they occur
- Hybrid detection: Combines rule-based and machine learning approaches
- Comprehensive logging: Stores all detected attacks in structured CSV files
- Lightweight design: Efficient packet processing with minimal overhead
- Wireless support: Specialized detection for WiFi-specific attacks

## Detectors Overview

1. Network Layer Detector (network_layer_detection.py)
   - ARP Spoofing
   - Deauthentication Attacks
   - Evil Twin
   - MAC Flooding

2. Internet Layer Detector (internet_layer_detection.py)
   - IP Spoofing
   - Ping Flood
   - SYN Flood
   - UDP Flood
   - Port Scanning

3. Transport Layer Detector (transport_layer_detection.py)
   - SYN Flood
   - RST Flood
   - Connection Flood
   - Port Scanning

4. Application Layer Detector (application_layer_detection.py)
   - DNS Spoofing
   - DNS Tunneling
   - XSS Attacks
   - SQL Injection
   - SSL Stripping
   - Credential Theft

5. Analyzer (analyser.py)
   - Rule-based detection
   - Machine learning analysis
   - Real-time alerts
   - Dual mode support

## Setup Instructions

### Prerequisites
- Python 3.8+
- Linux system
- Root privileges
- Wireless card with monitor mode support
- Recommended: 4GB+ RAM

### Installation
1. Clone the repository:
   git clone https://github.com/yourusername/network-security-detection.git
   cd network-security-detection

2. Install dependencies:
   pip install -r requirements.txt

3. Configure monitor mode:
   sudo airmon-ng check kill
   sudo airmon-ng start wlan0

### Configuration
Edit configuration in each detector file:
- Set monitoring interface (e.g., wlan0mon)
- Configure target MAC/IP
- Adjust detection thresholds

## Usage

Basic commands:
sudo python3 network_layer_detection.py
sudo python3 internet_layer_detection.py
sudo python3 transport_layer_detection.py
sudo python3 application_layer_detection.py
sudo python3 analyser.py

Background operation:
nohup sudo python3 analyser.py > detection.log 2>&1 &

## Output

CSV output files:
- network_layer_attacks.csv
- internet_layer_attacks.csv
- transport_layer_attacks.csv
- application_layer_attacks.csv
- combined_analysis_report.csv

## Troubleshooting

Common Issues:
1. Permission denied → Use sudo
2. Interface not found → Check with iwconfig
3. No packets captured → Verify monitor mode
4. ML model errors → Retrain models
5. Dependency errors → Reinstall requirements

## Contributing

Contribution steps:
1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Open Pull Request

## License

MIT License
