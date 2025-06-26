#!/usr/bin/env python3
"""
DoS Attack Data Collector
Captures WiFi packets and extracts features for DoS attack detection
"""

import time
import signal
import pandas as pd
from datetime import datetime
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11Disas, Dot11Auth, Dot11AssoReq, Dot11AssoResp, wrpcap
import pyshark
import os
from collections import defaultdict, deque
import numpy as np

# === CONFIG ===
INTERFACE = "wlan1mon"
PCAP_FILE = "dos_capture.pcap"
CSV_FILE = "dos_features.csv"
CAPTURE_LIMIT = int(input("Enter Capturing Limit: "))
WINDOW_SIZE = 60  # seconds for rate calculations
PACKET_WINDOW = 100  # packets to keep in memory for pattern analysis
TIMEOUT = 60  # seconds to wait for packets

# === TARGET MAC (set to None to capture all traffic) ===
TARGET_MAC = input("Enter the MAC address of the target device (or leave blank for all traffic): ").strip()
if TARGET_MAC == "":
    TARGET_MAC = None
print(f"\n📡 WiFi DoS Attack Data Collector")
if TARGET_MAC:
    print(f"🎯 Targeting MAC: {TARGET_MAC}")
else:
    print("🌐 Capturing all WiFi traffic")
print(f"📊 Interface: {INTERFACE} | Limit: {CAPTURE_LIMIT} packets | Timeout: {TIMEOUT}s")

# Global data structures
scapy_data = []
scapy_raw_packets = []
stop_capture = False

# DoS Detection tracking
packet_times = defaultdict(deque)
packet_counts = defaultdict(int)
frame_type_counts = defaultdict(lambda: defaultdict(int))
sequence_numbers = defaultdict(deque)
retry_counts = defaultdict(int)
fragment_counts = defaultdict(int)

def signal_handler(sig, frame):
    global stop_capture
    stop_capture = True
    print("\n🛑 Stopping packet capture...")
signal.signal(signal.SIGINT, signal_handler)

def calculate_packet_rate(mac_addr, current_time):
    """Calculate packets per second for a MAC address"""
    if mac_addr not in packet_times:
        return 0
    
    # Remove old timestamps
    while packet_times[mac_addr] and current_time - packet_times[mac_addr][0] > WINDOW_SIZE:
        packet_times[mac_addr].popleft()
    
    return len(packet_times[mac_addr]) / WINDOW_SIZE if packet_times[mac_addr] else 0

def detect_sequence_anomalies(mac_addr, seq_num):
    """Detect sequence number anomalies"""
    if mac_addr not in sequence_numbers:
        sequence_numbers[mac_addr] = deque(maxlen=50)
    
    seq_list = list(sequence_numbers[mac_addr])
    if len(seq_list) < 2:
        return False, 0
    
    # Check for duplicates (replay attacks)
    duplicates = seq_list.count(seq_num)
    
    # Check for sequence gaps
    if len(seq_list) >= 2:
        expected_seq = (seq_list[-1] + 1) % 4096
        gap = abs(seq_num - expected_seq)
        return duplicates > 1, gap
    
    return False, 0

def analyze_packet_intervals(recent_times):
    """Analyze packet timing patterns"""
    if len(recent_times) < 3:
        return 0, 0, 0
    
    intervals = [recent_times[i] - recent_times[i-1] for i in range(1, len(recent_times))]
    
    avg_interval = sum(intervals) / len(intervals)
    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
    regularity_score = variance / (avg_interval ** 2) if avg_interval > 0 else 0
    
    return avg_interval, variance, regularity_score

def scapy_handler(pkt):
    global scapy_data

    if not pkt.haslayer(Dot11):
        return

    timestamp = time.time()
    frame_type = pkt.type
    subtype = pkt.subtype
    src_mac = (pkt.addr2 or "").lower()
    dst_mac = (pkt.addr1 or "").lower()
    
    # MAC filtering logic
    if TARGET_MAC:
        is_target_involved = (TARGET_MAC in [src_mac, dst_mac] or 
                             dst_mac in ["ff:ff:ff:ff:ff:ff", ""] or
                             dst_mac.startswith("01:00:5e") or
                             dst_mac.startswith("33:33"))
        if not is_target_involved:
            return

    # Basic packet info
    length = len(pkt)
    is_mgmt = 1 if frame_type == 0 else 0
    is_ctrl = 1 if frame_type == 1 else 0
    is_data = 1 if frame_type == 2 else 0
    
    # 802.11 specific fields with None checking
    retry_flag = 0
    more_frag = 0
    from_ds = 0
    to_ds = 0
    power_mgmt = 0
    
    if hasattr(pkt, 'FCfield') and pkt.FCfield is not None:
        retry_flag = 1 if pkt.FCfield & 0x08 else 0
        more_frag = 1 if pkt.FCfield & 0x04 else 0
        from_ds = 1 if pkt.FCfield & 0x02 else 0
        to_ds = 1 if pkt.FCfield & 0x01 else 0
        power_mgmt = 1 if pkt.FCfield & 0x10 else 0
    
    # Sequence number analysis with None checking
    seq_num = 0
    frag_num = 0
    if hasattr(pkt, 'SC') and pkt.SC is not None:
        seq_num = pkt.SC >> 4
        frag_num = pkt.SC & 0x0F
    
    # DoS-specific frame detection
    is_deauth = 1 if pkt.haslayer(Dot11Deauth) else 0
    is_disassoc = 1 if pkt.haslayer(Dot11Disas) else 0
    is_auth = 1 if pkt.haslayer(Dot11Auth) else 0
    is_assoc_req = 1 if pkt.haslayer(Dot11AssoReq) else 0
    is_assoc_resp = 1 if pkt.haslayer(Dot11AssoResp) else 0
    is_beacon = 1 if pkt.haslayer(Dot11Beacon) else 0
    
    # Beacon-specific info
    ssid = ""
    beacon_interval = 0
    if pkt.haslayer(Dot11Beacon):
        try:
            ssid = pkt[Dot11Elt].info.decode(errors="ignore")
            beacon_interval = pkt[Dot11Beacon].beacon_interval
        except:
            pass
    
    # Signal strength
    rssi = 0
    try:
        rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 0
    except:
        rssi = 0
    
    # Update tracking data structures
    active_mac = src_mac if src_mac else dst_mac
    if active_mac and active_mac != "":
        packet_times[active_mac].append(timestamp)
        packet_counts[active_mac] += 1
        frame_type_counts[active_mac][frame_type] += 1
        sequence_numbers[active_mac].append(seq_num)
        
        if retry_flag:
            retry_counts[active_mac] += 1
        if more_frag:
            fragment_counts[active_mac] += 1
    
    # Calculate DoS detection features
    packet_rate = calculate_packet_rate(active_mac, timestamp)
    has_seq_duplicate, seq_gap = detect_sequence_anomalies(active_mac, seq_num)
    
    # Recent packet timing analysis
    recent_times = list(packet_times[active_mac])[-10:]
    avg_interval, interval_variance, regularity_score = analyze_packet_intervals(recent_times)
    
    # Frame type distribution
    total_frames = sum(frame_type_counts[active_mac].values())
    mgmt_ratio = frame_type_counts[active_mac][0] / total_frames if total_frames > 0 else 0
    ctrl_ratio = frame_type_counts[active_mac][1] / total_frames if total_frames > 0 else 0
    data_ratio = frame_type_counts[active_mac][2] / total_frames if total_frames > 0 else 0
    
    # Suspicious behavior rates
    retry_rate = retry_counts[active_mac] / packet_counts[active_mac] if packet_counts[active_mac] > 0 else 0
    fragment_rate = fragment_counts[active_mac] / packet_counts[active_mac] if packet_counts[active_mac] > 0 else 0
    
    # DoS attack pattern indicators
    deauth_flood_indicator = 1 if is_deauth and packet_rate > 10 else 0
    beacon_flood_indicator = 1 if is_beacon and packet_rate > 5 else 0
    auth_flood_indicator = 1 if is_auth and packet_rate > 20 else 0
    assoc_flood_indicator = 1 if (is_assoc_req or is_assoc_resp) and packet_rate > 15 else 0
    
    # Broadcast/Multicast indicators
    is_broadcast = 1 if dst_mac == "ff:ff:ff:ff:ff:ff" else 0
    is_multicast = 1 if dst_mac.startswith(("01:00:5e", "33:33")) else 0
    
    # Time-based features
    hour = datetime.fromtimestamp(timestamp).hour
    minute = datetime.fromtimestamp(timestamp).minute
    
    # Create feature row
    row_data = {
        # Basic identifiers
        "timestamp": timestamp,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "hour": hour,
        "minute": minute,
        
        # Frame characteristics
        "frame_type": frame_type,
        "subtype": subtype,
        "length": length,
        "is_mgmt_frame": is_mgmt,
        "is_ctrl_frame": is_ctrl,
        "is_data_frame": is_data,
        
        # 802.11 flags
        "retry_flag": retry_flag,
        "more_fragments": more_frag,
        "from_ds": from_ds,
        "to_ds": to_ds,
        "power_mgmt": power_mgmt,
        
        # Sequence analysis
        "sequence_num": seq_num,
        "fragment_num": frag_num,
        "has_seq_duplicate": 1 if has_seq_duplicate else 0,
        "sequence_gap": seq_gap,
        
        # DoS-specific frames
        "is_deauth": is_deauth,
        "is_disassoc": is_disassoc,
        "is_auth": is_auth,
        "is_assoc_req": is_assoc_req,
        "is_assoc_resp": is_assoc_resp,
        "is_beacon": is_beacon,
        
        # Network info
        "ssid": ssid,
        "beacon_interval": beacon_interval,
        "signal_strength": rssi,
        "is_broadcast": is_broadcast,
        "is_multicast": is_multicast,
        
        # Rate and timing features
        "packet_rate_per_sec": packet_rate,
        "avg_packet_interval": avg_interval,
        "interval_variance": interval_variance,
        "timing_regularity_score": regularity_score,
        
        # Frame distribution features
        "mgmt_frame_ratio": mgmt_ratio,
        "ctrl_frame_ratio": ctrl_ratio,
        "data_frame_ratio": data_ratio,
        
        # Behavioral indicators
        "retry_rate": retry_rate,
        "fragment_rate": fragment_rate,
        "total_packets_from_mac": packet_counts[active_mac],
        
        # Attack indicators
        "deauth_flood_indicator": deauth_flood_indicator,
        "beacon_flood_indicator": beacon_flood_indicator,
        "auth_flood_indicator": auth_flood_indicator,
        "assoc_flood_indicator": assoc_flood_indicator,
        
        # Store raw packet for PCAP
        "raw_pkt": pkt
    }
    
    scapy_data.append(row_data)
    scapy_raw_packets.append(pkt)

    # Progress indicator
    if len(scapy_data) % 500 == 0:
        print(f"📊 Captured {len(scapy_data)} packets...")

    # Real-time attack detection alerts
    if any([deauth_flood_indicator, beacon_flood_indicator, auth_flood_indicator, assoc_flood_indicator]):
        attack_types = []
        if deauth_flood_indicator: attack_types.append("DEAUTH_FLOOD")
        if beacon_flood_indicator: attack_types.append("BEACON_FLOOD") 
        if auth_flood_indicator: attack_types.append("AUTH_FLOOD")
        if assoc_flood_indicator: attack_types.append("ASSOC_FLOOD")
        print(f"🚨 POTENTIAL ATTACK: {'/'.join(attack_types)} from {src_mac} (Rate: {packet_rate:.1f} pps)")

    if len(scapy_data) >= CAPTURE_LIMIT:
        global stop_capture
        stop_capture = True

# Start packet capture
print("\n🎯 Starting enhanced WiFi packet capture...")
print("   Press Ctrl+C to stop capture early")

start_time = time.time()
def timeout_check(pkt):
    return stop_capture or (time.time() - start_time > TIMEOUT and len(scapy_data) < 50)

try:
    sniff(iface=INTERFACE, prn=scapy_handler, store=0, stop_filter=timeout_check)
except Exception as e:
    print(f"⚠️  Capture error: {e}")
    if len(scapy_data) == 0:
        print("❌ No packets captured. Check interface and permissions.")
        exit(1)

# Save PCAP file
print(f"\n💾 Saving {len(scapy_data)} packets to {PCAP_FILE}...")
wrpcap(PCAP_FILE, scapy_raw_packets)

# Enrich with PyShark
print("🔍 Enriching packets with protocol analysis...")
try:
    cap = pyshark.FileCapture(PCAP_FILE, use_json=True, include_raw=False)
    final_data = []

    for idx, pkt in enumerate(cap):
        if idx >= len(scapy_data):
            break
            
        row = scapy_data[idx].copy()

        # Add protocol info
        try:
            row["highest_protocol"] = pkt.highest_layer.lower()
        except:
            row["highest_protocol"] = "unknown"

        # Add IP info if available
        try:
            row["src_ip"] = pkt.ip.src
            row["dst_ip"] = pkt.ip.dst
            row["ip_ttl"] = int(pkt.ip.ttl)
            row["ip_len"] = int(pkt.ip.len)
        except:
            row["src_ip"] = ""
            row["dst_ip"] = ""
            row["ip_ttl"] = 0
            row["ip_len"] = 0

        # Add TCP info if available
        try:
            if hasattr(pkt, 'tcp'):
                row["src_port"] = int(pkt.tcp.srcport)
                row["dst_port"] = int(pkt.tcp.dstport)
                row["tcp_flags"] = int(pkt.tcp.flags, 16) if isinstance(pkt.tcp.flags, str) else int(pkt.tcp.flags)
                row["tcp_window"] = int(pkt.tcp.window_size)
            else:
                row["src_port"] = 0
                row["dst_port"] = 0
                row["tcp_flags"] = 0
                row["tcp_window"] = 0
        except:
            row["src_port"] = 0
            row["dst_port"] = 0
            row["tcp_flags"] = 0
            row["tcp_window"] = 0

        # Remove raw packet data
        if "raw_pkt" in row:
            del row["raw_pkt"]
        
        final_data.append(row)

    cap.close()
    
except Exception as e:
    print(f"⚠️  PyShark enrichment failed: {e}")
    print("📝 Using basic Scapy data only...")
    final_data = []
    for row in scapy_data:
        row_copy = row.copy()
        if "raw_pkt" in row_copy:
            del row_copy["raw_pkt"]
        # Add missing fields with default values
        row_copy.update({
            "highest_protocol": "unknown",
            "src_ip": "",
            "dst_ip": "", 
            "ip_ttl": 0,
            "ip_len": 0,
            "src_port": 0,
            "dst_port": 0,
            "tcp_flags": 0,
            "tcp_window": 0
        })
        final_data.append(row_copy)

# Create DataFrame and add advanced features
print("📊 Calculating advanced DoS detection features...")
df = pd.DataFrame(final_data)

if not df.empty:
    # Convert timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], unit='s')
    df = df.sort_values('timestamp')
    
    # Add rolling window features
    if len(df) > 10:
        window_size = min(10, len(df) // 2)
        
        # Rolling counts per MAC
        for mac_group in df.groupby('src_mac'):
            mac = mac_group[0]
            mac_df = mac_group[1].copy()
            
            if len(mac_df) > 1:
                df.loc[mac_df.index, 'rolling_packet_count'] = range(1, len(mac_df) + 1)
                df.loc[mac_df.index, 'time_since_last'] = mac_df['timestamp'].diff().dt.total_seconds().fillna(0)
    
    # Calculate suspicious behavior scores
    df['suspicious_rate_score'] = (df['packet_rate_per_sec'] > 50).astype(int)
    df['suspicious_timing_score'] = (df['timing_regularity_score'] < 0.1).astype(int) 
    df['suspicious_sequence_score'] = (df['has_seq_duplicate'] + (df['sequence_gap'] > 100).astype(int))
    df['suspicious_frame_score'] = (df['mgmt_frame_ratio'] > 0.8).astype(int)
    
    # Overall suspicion score (0-10)
    df['overall_suspicion_score'] = (
        df['suspicious_rate_score'] * 3 +
        df['suspicious_timing_score'] * 2 +
        df['suspicious_sequence_score'] * 2 +
        df['suspicious_frame_score'] * 2 +
        df['deauth_flood_indicator'] * 1
    ).clip(0, 10)
    
    # Label potential attacks (for training)
    df['is_potential_attack'] = (df['overall_suspicion_score'] >= 5).astype(int)
    
    # Format timestamp for CSV
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S.%f")

# Save to CSV
print(f"💾 Saving feature dataset to {CSV_FILE}...")
if os.path.exists(CSV_FILE):
    df.to_csv(CSV_FILE, mode='a', header=False, index=False)
    print(f"📝 Appended {len(df)} new packets to existing dataset")
else:
    df.to_csv(CSV_FILE, index=False)
    print(f"📊 Created new dataset with {len(df)} packets")

# Summary statistics
print(f"\n📈 Dataset Summary:")
print(f"   • Total packets: {len(df)}")
print(f"   • Unique MAC addresses: {df['src_mac'].nunique()}")
print(f"   • Management frames: {df['is_mgmt_frame'].sum()}")
print(f"   • Deauth packets: {df['is_deauth'].sum()}")
print(f"   • Potential attacks detected: {df['is_potential_attack'].sum()}")
print(f"   • Average suspicion score: {df['overall_suspicion_score'].mean():.2f}/10")
print(f"   • High suspicion packets (≥7): {(df['overall_suspicion_score'] >= 7).sum()}")

print(f"\n✅ Data collection complete!")
print(f"📊 Features saved to: {CSV_FILE}")
print(f"📦 Raw packets saved to: {PCAP_FILE}")
print(f"🤖 Ready for ML analysis!")
