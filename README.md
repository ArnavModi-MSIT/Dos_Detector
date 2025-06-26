WiFi DoS Attack Detection with Machine Learning
===============================================

A Python-based toolkit that captures 802.11 WiFi packets, extracts features, and applies ML techniques to detect Denial-of-Service (DoS) attacks and spoofed packets in real-time.

--------------------------------------------------------
FEATURES
--------------------------------------------------------

- Real-time WiFi packet capture using Scapy and PyShark
- Feature extraction for DoS detection (Deauth, Beacon, Auth floods)
- Advanced metrics: sequence anomalies, timing irregularities, retry rates
- ML-based analysis using:
    • Isolation Forest (Unsupervised)
    • Random Forest Classifier (Supervised)
    • DBSCAN clustering
- Fake/spoofed packet detection
- Comprehensive threat reporting and CSV export

--------------------------------------------------------
SETUP
--------------------------------------------------------

1. Clone the Repository:
------------------------
    git clone https://github.com/yourusername/WiFi-DoS-Detector-ML.git
    cd WiFi-DoS-Detector-ML

2. Create a Python Virtual Environment:
---------------------------------------
    python3 -m venv .venv
    source .venv/bin/activate

3. Install Dependencies:
------------------------
    pip install -r requirements.txt

--------------------------------------------------------
USAGE INSTRUCTIONS
--------------------------------------------------------

Step 1: Prepare WiFi Interface for Monitoring
---------------------------------------------
    sudo airmon-ng check kill
    sudo airmon-ng start wlan1
    sudo airodump-ng wlan1mon
    sudo iwconfig wlan1mon channel 9

(Replace 'wlan1' with your wireless adapter name and channel 9 with your target AP's channel.)

Step 2: Start Packet Capture
----------------------------
    sudo .venv/bin/python collector.py

• Enter the number of packets to capture (e.g., 1000)
• Enter the MAC address to filter (or leave blank for all traffic)

Step 3: Run ML Analysis
-----------------------
    sudo .venv/bin/python analyse.py

• Produces threat levels like CRITICAL, HIGH, MEDIUM, etc.
• Outputs: ml_analysis_results.csv

Step 4: Restore Original Network Settings
-----------------------------------------
    sudo airmon-ng stop wlan1mon
    sudo service NetworkManager restart

--------------------------------------------------------
OUTPUT FILES
--------------------------------------------------------

• dos_capture.pcap         → Raw WiFi packets
• dos_features.csv         → Extracted features from packets
• ml_analysis_results.csv  → Final threat analysis results

--------------------------------------------------------
REQUIREMENTS
--------------------------------------------------------

• Linux system (Kali Linux recommended)
• External WiFi adapter supporting monitor mode
• Python 3.7+

Python Dependencies (in requirements.txt):
------------------------------------------
• scapy
• pyshark
• pandas
• numpy
• matplotlib
• seaborn
• scikit-learn

--------------------------------------------------------
LICENSE
--------------------------------------------------------

This project is licensed under the MIT License.

--------------------------------------------------------
CREDITS
--------------------------------------------------------

Developed for educational and research purposes in IoT and Cybersecurity.
