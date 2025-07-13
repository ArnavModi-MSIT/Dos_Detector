# 🛡️ Network Security Detection System

[![Network Security](https://img.shields.io/badge/Network-Security-blue)]()  
[![Python](https://img.shields.io/badge/Python-3.8+-yellow)]()  
[![Scapy](https://img.shields.io/badge/Scapy-Packet%20Analysis-green)]()  
[![License](https://img.shields.io/badge/License-MIT-green)]()

A comprehensive, multi-layered intrusion detection system (IDS) designed to monitor and detect a wide range of network-based attacks across the OSI model. This hybrid system leverages both rule-based heuristics and machine learning models for real-time, high-confidence threat detection.

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

- ✅ **Multi-layered Detection:** Monitors attacks across Network, Internet, Transport, and Application layers  
- 📡 **Real-Time Monitoring:** Live packet inspection and attack detection  
- 🧠 **Hybrid Analysis:** Combines rule-based signatures with ML-based classification  
- 🗂️ **Structured Logging:** Stores detections in clean, CSV-formatted logs  
- 🧩 **Modular Design:** Independent detection modules for each layer  
- 📶 **Wi-Fi Support:** Specialized detection for wireless-specific attacks  
- ⚡ **Lightweight:** Optimized for low overhead and fast packet processing

---

## 🔍 Detection Modules

Each layer has a dedicated detection script designed to catch specific threats:

### 1. **Network Layer** (`network_layer_detection.py`)
- ARP Spoofing  
- Deauthentication Attacks  
- Evil Twin Access Points  
- MAC Flooding  

### 2. **Internet Layer** (`internet_layer_detection.py`)
- IP Spoofing  
- Ping Flooding  
- Port Scanning  

### 3. **Transport Layer** (`transport_layer_detection.py`)
- SYN Flood  
- RST Flood  
- UDP Flood  
- Connection Flood  
- TCP Port Scan  

### 4. **Application Layer** (`application_layer_detection.py`)
- DNS Spoofing  
- DNS Tunneling  
- SQL Injection  
- Cross-Site Scripting (XSS)  
- SSL Stripping  
- Credential Theft  

### 5. **Analyzer** (`analyser.py`)
- Real-time ML-based predictions  
- Rule-based fallback detection  
- Custom model support (`combined_rf_model.pkl`)  
- Dual-mode analysis (offline/online)

---

## ⚙️ Installation & Setup

### 🔧 Prerequisites

- Python 3.8+  
- Linux (recommended: Kali Linux or Ubuntu)  
- Root privileges (`sudo`)  
- Wireless card supporting **monitor mode**  
- Minimum 4GB RAM recommended

### 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/network-security-detection.git
cd network-security-detection

# Install Python dependencies
pip install -r requirements.txt
```

### 📡 Enable Monitor Mode

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

### 🔧 Configuration

Edit each detection script to:
- Set your **monitoring interface** (e.g., `wlan0mon`)  
- Add **target MAC/IP filters** if needed  
- Adjust thresholds and detection rules as needed  

---

## 🧪 Usage

### 🎮 Basic Commands

```bash
sudo python3 network_layer_detection.py
sudo python3 internet_layer_detection.py
sudo python3 transport_layer_detection.py
sudo python3 application_layer_detection.py
sudo python3 analyser.py
```

### 🧭 Run in Background

```bash
nohup sudo python3 analyser.py > detection.log 2>&1 &
```

---

## 📁 Output

All detection modules output CSV files for post-analysis and logging:

- `network_layer_attacks.csv`  
- `internet_layer_attacks.csv`  
- `transport_layer_attacks.csv`  
- `application_layer_attacks.csv`  
- `combined_analysis_report.csv` (from analyser)

Models and encoders are saved in:
- `combined_rf_model.pkl`

---

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| `Permission denied` | Run with `sudo` |
| `Interface not found` | Use `iwconfig` to confirm interface name |
| No packets captured | Ensure monitor mode is active |
| ML model error | Retrain model using `model_trainer.py` |
| Dependency errors | Reinstall using `pip install -r requirements.txt` |

---

## 🤝 Contributing

We welcome community contributions!

1. Fork the repository  
2. Create a feature branch  
3. Commit your changes  
4. Push to your fork  
5. Open a pull request


---

## 📄 License

This project is licensed under the **MIT License** 
