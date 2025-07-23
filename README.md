# 🛡️ Drone & Network Security Detection System

A multi-layered intrusion detection system (IDS) designed for monitoring and detecting attacks on both **drone communication networks** and traditional network environments across the OSI model. This system combines rule-based heuristics and machine learning for real-time threat detection.

---

## 📚 Table of Contents

- [Features](#features)  
- [Detection Modules](#detection-modules)  
- [Installation & Setup](#installation--setup)  
- [Usage](#usage)  
- [Output](#output)  
- [Troubleshooting](#troubleshooting)  
- [Contributing](#contributing)  
- [License](#license)  

---

## 🚀 Features

- ✅ **Drone & Network Detection:** Monitors drone command, telemetry, and video streams alongside Wi-Fi and wired network traffic  
- 📡 **Multi-layer Coverage:** Network, Internet, Transport, Application layers plus drone-specific threats  
- 🧠 **Hybrid Approach:** Rule-based signatures combined with machine learning classification  
- 🗂️ **Structured CSV Logging:** Designed for easy post-analysis  
- 🧩 **Modular Design:** Independent scripts for each detection layer  
- 📶 **Wireless and Wired Support:** Works with Wi-Fi monitor mode and standard Ethernet interfaces  
- ⚡ **Lightweight & Extensible:** Easy to customize and extend  

---

## 🔍 Detection Modules

### Drone & Network Layer  
- Drone command flooding and GPS spoofing detections  
- Video hijacking attempts  
- ARP spoofing, Deauthentication, Evil Twin AP detection  
- MAC flooding  

### Internet Layer  
- IP spoofing, ICMP/UDP flooding, port scans  

### Transport Layer  
- TCP SYN, RST, ACK, FIN flood detection  
- Connection hijacking and session replay attacks  

### Application Layer  
- DNS spoofing and tunneling  
- Cross-site scripting (XSS) and SQL injection   
- SSL stripping and credential theft  

### Analyzer (`analyser.py`)  
- Real-time multi-layer ML classification  
- Rule-based fallback detection  
- Supports custom trained detection models  

---

## ⚙️ Installation & Setup

### Prerequisites

- Python 3.8+  
- Linux OS (Kali Linux or Ubuntu recommended)  
- Root permissions (`sudo`)  
- Wireless card with monitor mode support (for Wi-Fi detection)  
- Minimum 4GB RAM  

### Install dependencies

- git clone https://github.com/yourusername/drone-network-security.git
- cd drone-network-security
- pip install -r requirements.txt


### Enable monitor mode for wireless interface

- sudo airmon-ng check kill
- sudo airmon-ng start wlan0


### Configuration

- Set your monitoring interface (default: `wlan0mon`) in each detection script  
- Edit target MAC/IP addresses for drones or network devices if needed  
- Tune detection thresholds for your environment  

---

## 🧪 Usage

Run detection scripts individually or the unified analyzer:

- sudo python3 network_layer_detection.py
- sudo python3 internet_layer_detection.py
- sudo python3 transport_layer_detection.py
- sudo python3 application_layer_detection.py
- sudo python3 analyser.py


Run analyzer as background process:

nohup sudo python3 analyser.py > detection.log 2>&1 &


---

## 📁 Output

- Logs saved in CSV format:  
  - `drone_network_attacks.csv`  
  - `internet_layer_attacks.csv`  
  - `transport_layer_attacks.csv`  
  - `application_layer_attacks.csv`  
  - `combined_analysis_report.csv` (analyser output)  

- Trained model files:  
  - `combined_rf_model.pkl`  

---

## 🛠️ Troubleshooting Tips

| Problem                  | Solution                                       |
|--------------------------|------------------------------------------------|
| Permission errors        | Run scripts with `sudo`                          |
| Wireless interface issues | Verify interface name with `iwconfig`           |
| No captured packets      | Ensure monitor mode is enabled                    |
| ML model prediction errors| Retrain with `train.py` or check data formats    |
| Missing dependencies     | Reinstall with `pip install -r requirements.txt`|

---

## 🤝 Contributing

We welcome your contributions!

1. Fork the repo  
2. Create a new branch  
3. Make your changes  
4. Submit a pull request  

---

## 📄 License

This project is licensed under the **MIT License**
