# Network Security Detection System

![Network Security](https://img.shields.io/badge/Network-Security-blue) ![Python](https://img.shields.io/badge/Python-3.8+-yellow) ![Scapy](https://img.shields.io/badge/Scapy-Packet%20Analysis-green)

A multi-layer network security detection system that monitors and detects various types of attacks across network layers (Network, Internet, Transport, Application). Combines rule-based detection with machine learning for comprehensive threat identification.

## Features

- **Multi-layer detection**: Covers attacks across all OSI model layers
- **Real-time monitoring**: Detects attacks as they happen
- **Machine learning integration**: Uses trained models for advanced detection
- **Comprehensive logging**: Stores all detected attacks in CSV files
- **Lightweight**: Efficient packet processing with minimal overhead

## Detectors Overview

### 1. Network Layer Detector (`network_layer_detection.py`)
Detects wireless-specific attacks:
- **ARP Spoofing**: Identifies IP-MAC binding changes
- **Deauthentication Attacks**: Detects mass deauth packets
- **Evil Twin**: Finds multiple APs with same SSID
- **MAC Flooding**: Identifies CAM table overflow attempts

### 2. Internet Layer Detector (`internet_layer_detection.py`)
Detects IP/ICMP layer attacks:
- **IP Spoofing**: Identifies TTL/MAC inconsistencies
- **Ping Flood**: Detects ICMP flood attacks
- **SYN Flood**: Identifies TCP SYN floods
- **UDP Flood**: Detects UDP flood attacks
- **Port Scanning**: Identifies reconnaissance scans

### 3. Transport Layer Detector (`transport_layer_detection.py`)
Detects TCP/UDP layer attacks:
- **SYN Flood**: High SYN packet rate
- **RST Flood**: Excessive RST packets
- **Connection Flood**: High ACK rate
- **Port Scanning**: Multiple port probes

### 4. Application Layer Detector (`application_layer_detection.py`)
Detects application-specific attacks:
- **DNS Spoofing**: Low TTL DNS responses
- **DNS Tunneling**: Large TXT records
- **XSS Attacks**: Script tags in HTTP
- **SQL Injection**: SQL patterns in payloads
- **SSL Stripping**: HTTP redirects
- **Credential Theft**: Password fields in traffic

### 5. Analyzer (`analyser.py`)
Combines detection methods:
- Rule-based detection for known patterns
- Machine learning analysis using trained models
- Real-time alerts and statistics
- Supports both monitor/managed modes

## Setup Instructions

### Prerequisites
- Python 3.8+
- Linux system (for monitor mode)
- Root privileges (for packet capture)
- Wireless card supporting monitor mode (for wireless detection)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-security-detection.git
   cd network-security-detection

2. Install dependencies:
pip install -r requirements.txt

3. Put your wireless interface in monitor mode (for wireless detection):
sudo airmon-ng start wlan1

Configuration

Edit the following parameters in each detector file:

    interface: Set to your monitoring interface (typically wlan1mon for monitor mode)

    target_mac/target_ip: Set to your device's MAC/IP for focused monitoring

    Detection thresholds can be adjusted in each file's configuration section

Training the Models (Optional)

If you want to retrain the machine learning models:
python3 train_model.py
This requires collected attack data in the CSV files.

Usage

Run individual detectors:
# Network layer (wireless)
sudo python3 network_layer_detection.py

# Internet layer
sudo python3 internet_layer_detection.py

# Transport layer
sudo python3 transport_layer_detection.py

# Application layer
sudo python3 application_layer_detection.py

# Combined analyzer (with ML)
sudo python3 analyser.py

#Output
All detectors save results to CSV files:

    network_layer_attacks.csv

    internet_layer_attacks.csv

    transport_layer_attacks.csv

    application_layer_attacks.csv

The analyzer provides real-time console output and saves to.

Troubleshooting

Common Issues:

    Permission denied: Run with sudo

    Interface not found: Check interface name with iwconfig

    No packets captured: Verify monitor mode is enabled

    ML model errors: Retrain models with train_model.py

Contributing
Pull requests are welcome. For major changes, please open an issue first.

License

MIT
