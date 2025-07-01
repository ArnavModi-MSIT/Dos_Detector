# 🛡️ Attack Detection Suite

This project contains a suite of Python tools to detect wireless attacks across different OSI layers targeting mobile devices. It uses a combination of **rule-based** and **unsupervised machine learning (Isolation Forest)** methods.

---

## 📦 Requirements

- Python 3.8+
- `scapy`
- `numpy`
- `pandas`
- `scikit-learn`

Install all dependencies in a virtual environment.

```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install required packages
pip install -r requirements.txt
```

Sample `requirements.txt`:
```text
scapy
numpy
pandas
scikit-learn
```

---

## 📡 Setup Monitor Mode for Wireless Interface

Before running the scripts, you must enable monitor mode:

```bash
sudo airmon-ng check kill              # Stop conflicting processes
sudo airmon-ng start wlan1             # Start monitor mode (creates wlan1mon , check your interface using iwconfig set accordingly)
sudo airodump-ng wlan1mon              # Confirm the interface is working
sudo iwconfig wlan1mon channel 9       # Set the correct WiFi channel (change '9' as needed)
```

---

## 📂 Navigate to Script Directory

```bash
cd /path/to/your/detection/scripts
```

---

## 🚀 Run Detectors (One by One)

Run each script using the virtual environment's Python binary.

```bash
sudo .venv/bin/python network_layer_detection.py
sudo .venv/bin/python internet_layer_detection.py
sudo .venv/bin/python transport_layer_detection.py
sudo .venv/bin/python application_layer_detection.py
```

> ⚠️ You will be prompted to enter:
> - Monitor interface name (e.g. `wlan1mon`)
> - Target mobile device's **MAC address** or **IP address** depending on the layer

---

## 🧹 Restore Network After Detection

Once you're done:

```bash
sudo airmon-ng stop wlan1mon
sudo service NetworkManager restart
```

---

## 🗃️ Output

Each script will generate its own `.csv` file logging:
- Detected attacks
- Timestamped features
- Anomaly scores
- Confidence levels

---

## ✅ Detection Capabilities Per Layer

| Layer              | Script                       | Detects |
|-------------------|------------------------------|---------|
| Network Layer      | `network_layer_detection.py`   | ARP Spoofing, Deauth, Evil Twin, MAC Flood |
| Internet Layer     | `internet_layer_detection.py`  | IP Spoofing, SYN Flood, UDP Flood, Ping Flood, Port Scan |
| Transport Layer    | `transport_layer_detection.py` | SYN Flood, RST Flood, Port Scan, Connection Flood |
| Application Layer  | `application_layer_detection.py` | DNS Spoofing, DNS Tunneling, XSS, SQLi, SSL Strip, Credential Theft, DoS |

---

## 📌 Notes

- Must be run as **root** (`sudo`) due to packet sniffing.
- Monitor interface must be enabled before script execution.
- Scripts auto-create CSV logs with analysis.
- Works best in isolated test environments (e.g., personal WiFi lab).

---

## 🤖 Author

Made for research & educational use. Ensure compliance with your local cybersecurity laws before deploying on public networks.
