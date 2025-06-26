#!/usr/bin/env python3
"""
WiFi Packet ML Analyzer
Uses machine learning to detect DoS attacks and fake packets from captured WiFi data
"""

import pandas as pd
import numpy as np
import pickle
import os
import warnings
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter, defaultdict

warnings.filterwarnings('ignore')

class WiFiMLAnalyzer:
    def __init__(self, csv_file="dos_features.csv"):
        self.csv_file = csv_file
        self.df = None
        self.scaler = StandardScaler()
        self.isolation_forest = None
        self.rf_classifier = None
        self.dbscan = None
        self.label_encoders = {}
        self.feature_columns = []
        
    def load_data(self):
        """Load and preprocess the captured packet data"""
        print("📊 Loading packet data...")
        
        if not os.path.exists(self.csv_file):
            raise FileNotFoundError(f"❌ Dataset file {self.csv_file} not found!")
        
        self.df = pd.read_csv(self.csv_file)
        print(f"✅ Loaded {len(self.df)} packets")
        
        # Convert timestamp
        self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
        
        # Handle missing values
        self.df = self.df.fillna(0)
        
        return self.df
    
    def engineer_features(self):
        """Create additional features for better ML detection"""
        print("🔧 Engineering advanced features...")
        
        # Time-based features
        self.df['hour_sin'] = np.sin(2 * np.pi * self.df['hour'] / 24)
        self.df['hour_cos'] = np.cos(2 * np.pi * self.df['hour'] / 24)
        self.df['minute_sin'] = np.sin(2 * np.pi * self.df['minute'] / 60)
        self.df['minute_cos'] = np.cos(2 * np.pi * self.df['minute'] / 60)
        
        # Packet size anomalies
        self.df['length_zscore'] = np.abs((self.df['length'] - self.df['length'].mean()) / self.df['length'].std())
        
        # MAC address entropy (randomness indicator)
        def mac_entropy(mac):
            if not mac or mac == "":
                return 0
            # Remove colons and convert to hex values
            hex_chars = mac.replace(':', '')
            if len(hex_chars) != 12:
                return 0
            # Calculate entropy of hex characters
            char_counts = Counter(hex_chars)
            entropy = -sum((count/len(hex_chars)) * np.log2(count/len(hex_chars)) 
                          for count in char_counts.values())
            return entropy
        
        self.df['src_mac_entropy'] = self.df['src_mac'].apply(mac_entropy)
        self.df['dst_mac_entropy'] = self.df['dst_mac'].apply(mac_entropy)
        
        # Sequence number patterns
        self.df['seq_num_mod'] = self.df['sequence_num'] % 256
        
        # Protocol combinations (suspicious patterns)
        self.df['mgmt_with_data'] = ((self.df['is_mgmt_frame'] == 1) & 
                                   (self.df['length'] > 100)).astype(int)
        
        # Timing anomalies
        self.df['extreme_rate'] = (self.df['packet_rate_per_sec'] > 100).astype(int)
        self.df['zero_interval'] = (self.df['avg_packet_interval'] == 0).astype(int)
        
        # Frame type inconsistencies
        self.df['frame_type_mismatch'] = (
            ((self.df['frame_type'] == 0) & (self.df['is_mgmt_frame'] == 0)) |
            ((self.df['frame_type'] == 1) & (self.df['is_ctrl_frame'] == 0)) |
            ((self.df['frame_type'] == 2) & (self.df['is_data_frame'] == 0))
        ).astype(int)
        
        # Broadcast/multicast abuse
        self.df['broadcast_abuse'] = ((self.df['is_broadcast'] == 1) & 
                                    (self.df['packet_rate_per_sec'] > 20)).astype(int)
        
        print("✅ Feature engineering completed")
    
    def select_features(self):
        """Select relevant features for ML models"""
        # Exclude non-numeric and identifier columns
        exclude_cols = ['timestamp', 'src_mac', 'dst_mac', 'ssid', 'src_ip', 'dst_ip', 
                       'highest_protocol']
        
        # Select numeric columns
        numeric_cols = self.df.select_dtypes(include=[np.number]).columns.tolist()
        self.feature_columns = [col for col in numeric_cols if col not in exclude_cols]
        
        print(f"📋 Selected {len(self.feature_columns)} features for ML analysis")
        return self.feature_columns
    
    def detect_anomalies_unsupervised(self):
        """Use unsupervised learning to detect anomalies"""
        print("🤖 Training Isolation Forest for anomaly detection...")
        
        # Prepare features
        X = self.df[self.feature_columns].values
        X_scaled = self.scaler.fit_transform(X)
        
        # Isolation Forest for outlier detection
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_jobs=-1
        )
        
        anomaly_labels = self.isolation_forest.fit_predict(X_scaled)
        self.df['anomaly_score'] = self.isolation_forest.decision_function(X_scaled)
        self.df['is_anomaly'] = (anomaly_labels == -1).astype(int)
        
        print(f"✅ Detected {self.df['is_anomaly'].sum()} anomalous packets")
        
        # DBSCAN clustering for pattern detection
        print("🔍 Running DBSCAN clustering...")
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        cluster_labels = self.dbscan.fit_predict(X_scaled)
        self.df['cluster'] = cluster_labels
        
        # Identify outlier clusters
        cluster_sizes = Counter(cluster_labels)
        outlier_clusters = [cluster for cluster, size in cluster_sizes.items() 
                          if size < 10 and cluster != -1]
        self.df['is_outlier_cluster'] = self.df['cluster'].isin(outlier_clusters).astype(int)
        
        print(f"✅ Found {len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)} clusters")
        
    def train_supervised_model(self):
        """Train supervised model using existing labels"""
        print("🎓 Training supervised Random Forest classifier...")
        
        # Use existing suspicion scores as labels
        # Create binary labels based on multiple indicators
        self.df['attack_label'] = (
            (self.df['is_potential_attack'] == 1) |
            (self.df['overall_suspicion_score'] >= 6) |
            (self.df['deauth_flood_indicator'] == 1) |
            (self.df['beacon_flood_indicator'] == 1) |
            (self.df['auth_flood_indicator'] == 1) |
            (self.df['assoc_flood_indicator'] == 1)
        ).astype(int)
        
        if self.df['attack_label'].sum() < 5:
            print("⚠️  Not enough attack samples for supervised learning")
            return
        
        # Prepare training data
        X = self.df[self.feature_columns].values
        X_scaled = self.scaler.transform(X)
        y = self.df['attack_label'].values
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.3, random_state=42, stratify=y
        )
        
        # Train Random Forest
        self.rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1
        )
        
        self.rf_classifier.fit(X_train, y_train)
        
        # Predictions
        y_pred = self.rf_classifier.predict(X_test)
        self.df['rf_attack_prob'] = self.rf_classifier.predict_proba(X_scaled)[:, 1]
        self.df['rf_attack_pred'] = self.rf_classifier.predict(X_scaled)
        
        print("📊 Random Forest Performance:")
        print(classification_report(y_test, y_pred))
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.feature_columns,
            'importance': self.rf_classifier.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\n🎯 Top 10 Important Features:")
        print(feature_importance.head(10).to_string(index=False))
    
    def analyze_fake_packets(self):
        """Specific analysis for fake/spoofed packet detection"""
        print("🕵️ Analyzing for fake/spoofed packets...")
        
        fake_indicators = []
        
        # 1. MAC address analysis
        # Check for randomized MAC addresses (high entropy)
        high_entropy_macs = self.df['src_mac_entropy'] > 3.5
        fake_indicators.append(('high_entropy_mac', high_entropy_macs))
        
        # 2. Sequence number anomalies
        seq_anomalies = (self.df['has_seq_duplicate'] == 1) | (self.df['sequence_gap'] > 1000)
        fake_indicators.append(('sequence_anomaly', seq_anomalies))
        
        # 3. Timing patterns (too regular = fake)
        timing_anomalies = (self.df['timing_regularity_score'] < 0.01) & (self.df['packet_rate_per_sec'] > 10)
        fake_indicators.append(('suspicious_timing', timing_anomalies))
        
        # 4. Frame inconsistencies
        frame_inconsistencies = self.df['frame_type_mismatch'] == 1
        fake_indicators.append(('frame_inconsistency', frame_inconsistencies))
        
        # 5. Broadcast abuse
        broadcast_abuse = self.df['broadcast_abuse'] == 1
        fake_indicators.append(('broadcast_abuse', broadcast_abuse))
        
        # 6. Signal strength anomalies (if available)
        if 'signal_strength' in self.df.columns:
            signal_anomalies = (self.df['signal_strength'] == 0) | (self.df['signal_strength'] < -100)
            fake_indicators.append(('signal_anomaly', signal_anomalies))
        
        # Combine fake indicators
        self.df['fake_packet_score'] = sum(indicator.astype(int) for _, indicator in fake_indicators)
        self.df['is_likely_fake'] = (self.df['fake_packet_score'] >= 3).astype(int)
        
        print(f"✅ Identified {self.df['is_likely_fake'].sum()} likely fake packets")
    
    def generate_threat_assessment(self):
        """Generate comprehensive threat assessment"""
        print("🛡️ Generating threat assessment...")
        
        # Combine all detection methods
        self.df['combined_threat_score'] = (
            self.df['overall_suspicion_score'] * 0.3 +
            (self.df['is_anomaly'] * 5) * 0.25 +
            (self.df['rf_attack_prob'] * 10 if 'rf_attack_prob' in self.df.columns else 0) * 0.25 +
            self.df['fake_packet_score'] * 0.2
        )
        
        # Threat levels
        def threat_level(score):
            if score >= 8: return "CRITICAL"
            elif score >= 6: return "HIGH"
            elif score >= 4: return "MEDIUM"
            elif score >= 2: return "LOW"
            else: return "BENIGN"
        
        self.df['threat_level'] = self.df['combined_threat_score'].apply(threat_level)
        
        # Attack type classification
        def classify_attack_type(row):
            attack_types = []
            if row['deauth_flood_indicator']: attack_types.append("DEAUTH_FLOOD")
            if row['beacon_flood_indicator']: attack_types.append("BEACON_FLOOD")
            if row['auth_flood_indicator']: attack_types.append("AUTH_FLOOD")
            if row['assoc_flood_indicator']: attack_types.append("ASSOC_FLOOD")
            if row['is_likely_fake']: attack_types.append("PACKET_SPOOFING")
            if row['broadcast_abuse']: attack_types.append("BROADCAST_ABUSE")
            
            return "|".join(attack_types) if attack_types else "NONE"
        
        self.df['attack_type'] = self.df.apply(classify_attack_type, axis=1)
    
    def print_analysis_results(self):
        """Print comprehensive analysis results"""
        print("\n" + "="*60)
        print("🔍 WiFi PACKET ANALYSIS RESULTS")
        print("="*60)
        
        total_packets = len(self.df)
        
        # Overall statistics
        print(f"\n📊 OVERALL STATISTICS:")
        print(f"   • Total packets analyzed: {total_packets:,}")
        print(f"   • Unique source MACs: {self.df['src_mac'].nunique():,}")
        print(f"   • Time span: {self.df['timestamp'].min()} to {self.df['timestamp'].max()}")
        
        # Threat level distribution
        threat_counts = self.df['threat_level'].value_counts()
        print(f"\n🚨 THREAT LEVEL DISTRIBUTION:")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BENIGN']:
            count = threat_counts.get(level, 0)
            percentage = (count / total_packets) * 100
            print(f"   • {level:>8}: {count:>6,} packets ({percentage:>5.1f}%)")
        
        # Attack type distribution
        attack_types = self.df[self.df['attack_type'] != 'NONE']['attack_type'].value_counts()
        if not attack_types.empty:
            print(f"\n⚔️  DETECTED ATTACK TYPES:")
            for attack_type, count in attack_types.head(10).items():
                print(f"   • {attack_type}: {count:,} packets")
        
        # Top suspicious MACs
        high_threat = self.df[self.df['combined_threat_score'] >= 6]
        if not high_threat.empty:
            suspicious_macs = high_threat.groupby('src_mac').agg({
                'combined_threat_score': 'mean',
                'packet_rate_per_sec': 'max',
                'attack_type': lambda x: x.mode().iloc[0] if not x.mode().empty else 'UNKNOWN'
            }).sort_values('combined_threat_score', ascending=False)
            
            print(f"\n🎯 TOP SUSPICIOUS MAC ADDRESSES:")
            for mac, data in suspicious_macs.head(10).iterrows():
                print(f"   • {mac}: Threat={data['combined_threat_score']:.1f}, "
                      f"Max Rate={data['packet_rate_per_sec']:.1f}pps, "
                      f"Type={data['attack_type']}")
        
        # Real-time alerts for critical threats
        critical_packets = self.df[self.df['threat_level'] == 'CRITICAL']
        if not critical_packets.empty:
            print(f"\n🚨 CRITICAL ALERTS ({len(critical_packets)} packets):")
            for _, packet in critical_packets.head(5).iterrows():
                print(f"   • {packet['timestamp']}: {packet['src_mac']} -> {packet['dst_mac']}")
                print(f"     Threat Score: {packet['combined_threat_score']:.1f}, "
                      f"Type: {packet['attack_type']}")
        
        # Anomaly detection results
        anomalies = self.df[self.df['is_anomaly'] == 1]
        print(f"\n🔬 ANOMALY DETECTION:")
        print(f"   • Anomalous packets: {len(anomalies):,} ({(len(anomalies)/total_packets)*100:.1f}%)")
        print(f"   • Fake packets detected: {self.df['is_likely_fake'].sum():,}")
        
        # Time-based analysis
        hourly_threats = self.df.groupby('hour')['combined_threat_score'].mean()
        peak_hour = hourly_threats.idxmax()
        print(f"\n⏰ TIME-BASED ANALYSIS:")
        print(f"   • Peak threat hour: {peak_hour:02d}:00 (avg score: {hourly_threats[peak_hour]:.1f})")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        if threat_counts.get('CRITICAL', 0) > 0:
            print("   • IMMEDIATE ACTION REQUIRED: Critical threats detected!")
            print("   • Block suspicious MAC addresses immediately")
            print("   • Investigate potential DoS attacks")
        
        if self.df['is_likely_fake'].sum() > 0:
            print("   • Fake packets detected - check for spoofing attacks")
        
        if self.df['deauth_flood_indicator'].sum() > 10:
            print("   • Deauth flood detected - enable 802.11w (PMF) protection")
        
        if self.df['packet_rate_per_sec'].max() > 100:
            print("   • High packet rates detected - implement rate limiting")
    
    def save_results(self, output_file="ml_analysis_results.csv"):
        """Save analysis results to CSV"""
        print(f"\n💾 Saving analysis results to {output_file}...")
        
        # Select relevant columns for output
        output_columns = [
            'timestamp', 'src_mac', 'dst_mac', 'frame_type', 'length',
            'combined_threat_score', 'threat_level', 'attack_type',
            'is_anomaly', 'is_likely_fake', 'packet_rate_per_sec',
            'overall_suspicion_score'
        ]
        
        # Add ML prediction columns if they exist
        if 'rf_attack_prob' in self.df.columns:
            output_columns.extend(['rf_attack_prob', 'rf_attack_pred'])
        
        result_df = self.df[output_columns].copy()
        result_df.to_csv(output_file, index=False)
        print(f"✅ Results saved to {output_file}")
    
    def run_analysis(self):
        """Run complete ML analysis pipeline"""
        try:
            # Load and preprocess data
            self.load_data()
            
            # Feature engineering
            self.engineer_features()
            
            # Select features for ML
            self.select_features()
            
            # Run unsupervised anomaly detection
            self.detect_anomalies_unsupervised()
            
            # Train supervised model if possible
            self.train_supervised_model()
            
            # Analyze for fake packets
            self.analyze_fake_packets()
            
            # Generate threat assessment
            self.generate_threat_assessment()
            
            # Print results
            self.print_analysis_results()
            
            # Save results
            self.save_results()
            
            print(f"\n✅ Analysis complete! Check 'ml_analysis_results.csv' for detailed results.")
            
        except Exception as e:
            print(f"❌ Analysis failed: {e}")
            import traceback
            traceback.print_exc()

def main():
    print("🤖 WiFi Packet ML Analyzer")
    print("="*50)
    
    # Initialize analyzer
    analyzer = WiFiMLAnalyzer()
    
    # Run analysis
    analyzer.run_analysis()

if __name__ == "__main__":
    main()
