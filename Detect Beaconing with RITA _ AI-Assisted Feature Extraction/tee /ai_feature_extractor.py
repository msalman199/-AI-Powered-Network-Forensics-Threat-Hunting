#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import pyshark
import json
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class BeaconDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        
    def extract_features_from_pcap(self, pcap_file):
        """Extract network features from PCAP file"""
        print("Extracting features from PCAP...")
        
        try:
            cap = pyshark.FileCapture(pcap_file)
            connections = {}
            
            for packet in cap:
                if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    dst_port = packet.tcp.dstport
                    timestamp = float(packet.sniff_timestamp)
                    
                    conn_key = f"{src_ip}->{dst_ip}:{dst_port}"
                    
                    if conn_key not in connections:
                        connections[conn_key] = {
                            'timestamps': [],
                            'packet_sizes': [],
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'dst_port': dst_port
                        }
                    
                    connections[conn_key]['timestamps'].append(timestamp)
                    connections[conn_key]['packet_sizes'].append(int(packet.length))
            
            cap.close()
            return connections
            
        except Exception as e:
            print(f"Error processing PCAP: {e}")
            return {}
    
    def calculate_beacon_features(self, connections):
        """Calculate beaconing features for each connection"""
        features = []
        
        for conn_key, conn_data in connections.items():
            if len(conn_data['timestamps']) < 5:  # Need minimum connections
                continue
                
            timestamps = sorted(conn_data['timestamps'])
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            packet_sizes = conn_data['packet_sizes']
            
            if not intervals:
                continue
                
            # Calculate statistical features
            feature_vector = {
                'connection': conn_key,
                'src_ip': conn_data['src_ip'],
                'dst_ip': conn_data['dst_ip'],
                'dst_port': conn_data['dst_port'],
                'total_packets': len(timestamps),
                'duration': timestamps[-1] - timestamps[0],
                'avg_interval': np.mean(intervals),
                'std_interval': np.std(intervals),
                'min_interval': np.min(intervals),
                'max_interval': np.max(intervals),
                'interval_variance': np.var(intervals),
                'avg_packet_size': np.mean(packet_sizes),
                'std_packet_size': np.std(packet_sizes),
                'regularity_score': 1 / (1 + np.std(intervals)) if np.std(intervals) > 0 else 1,
                'beacon_score': 0
            }
            
            # Calculate beacon score based on regularity
            if feature_vector['std_interval'] < 10 and feature_vector['total_packets'] > 10:
                feature_vector['beacon_score'] = min(feature_vector['regularity_score'] * 100, 100)
            
            features.append(feature_vector)
        
        return features
    
    def detect_anomalies(self, features):
        """Use AI to detect anomalous beaconing patterns"""
        if not features:
            return []
            
        df = pd.DataFrame(features)
        
        # Select numerical features for ML
        ml_features = ['total_packets', 'avg_interval', 'std_interval', 
                      'interval_variance', 'avg_packet_size', 'regularity_score']
        
        X = df[ml_features].fillna(0)
        X_scaled = self.scaler.fit_transform(X)
        
        # Detect anomalies using Isolation Forest
        anomaly_labels = self.isolation_forest.fit_predict(X_scaled)
        df['anomaly'] = anomaly_labels
        
        # Use DBSCAN for clustering similar beacon patterns
        dbscan = DBSCAN(eps=0.5, min_samples=2)
        cluster_labels = dbscan.fit_predict(X_scaled)
        df['cluster'] = cluster_labels
        
        return df
    
    def generate_report(self, analyzed_data):
        """Generate comprehensive beaconing report"""
        if analyzed_data.empty:
            print("No data to analyze")
            return
            
        print("\n" + "="*60)
        print("AI-ENHANCED BEACON DETECTION REPORT")
        print("="*60)
        
        # Summary statistics
        total_connections = len(analyzed_data)
        potential_beacons = len(analyzed_data[analyzed_data['beacon_score'] > 50])
        anomalies = len(analyzed_data[analyzed_data['anomaly'] == -1])
        
        print(f"Total Connections Analyzed: {total_connections}")
        print(f"Potential Beacons Detected: {potential_beacons}")
        print(f"Anomalous Patterns: {anomalies}")
        print(f"Unique Clusters Found: {len(set(analyzed_data['cluster'])) - (1 if -1 in analyzed_data['cluster'].values else 0)}")
        
        # Top beacon candidates
        print("\nTOP BEACON CANDIDATES:")
        print("-" * 40)
        beacon_candidates = analyzed_data[analyzed_data['beacon_score'] > 30].sort_values('beacon_score', ascending=False)
        
        for idx, row in beacon_candidates.head(10).iterrows():
            print(f"Connection: {row['connection']}")
            print(f"  Beacon Score: {row['beacon_score']:.2f}")
            print(f"  Packets: {row['total_packets']}")
            print(f"  Avg Interval: {row['avg_interval']:.2f}s")
            print(f"  Regularity: {row['regularity_score']:.3f}")
            print(f"  Anomaly: {'Yes' if row['anomaly'] == -1 else 'No'}")
            print()
        
        # Save detailed results
        analyzed_data.to_csv('beacon_analysis_results.csv', index=False)
        print("Detailed results saved to: beacon_analysis_results.csv")

def main():
    detector = BeaconDetector()
    
    # Extract features from captured traffic
    connections = detector.extract_features_from_pcap('network_traffic.pcap')
    
    if not connections:
        print("No connections found in PCAP file")
        return
    
    # Calculate beacon features
    features = detector.calculate_beacon_features(connections)
    
    if not features:
        print("No features extracted")
        return
    
    # Apply AI analysis
    analyzed_data = detector.detect_anomalies(features)
    
    # Generate report
    detector.generate_report(analyzed_data)

if __name__ == "__main__":
    main()
