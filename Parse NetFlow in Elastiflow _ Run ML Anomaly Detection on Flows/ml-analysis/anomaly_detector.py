#!/usr/bin/env python3
import pandas as pd
import numpy as np
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import matplotlib.pyplot as plt
import seaborn as sns
import json
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

class NetFlowAnomalyDetector:
    def __init__(self, es_host='localhost:9200'):
        self.es = Elasticsearch([es_host])
        self.scaler = StandardScaler()
        
    def fetch_netflow_data(self, hours_back=1):
        """Fetch NetFlow data from Elasticsearch"""
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours_back)
        
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": start_time.isoformat(),
                        "lte": end_time.isoformat()
                    }
                }
            },
            "size": 1000,
            "_source": ["netflow.src_addr", "netflow.dst_addr", "netflow.src_port", 
                       "netflow.dst_port", "netflow.protocol", "netflow.in_bytes", 
                       "netflow.in_pkts", "netflow.flow_duration_milliseconds"]
        }
        
        try:
            response = self.es.search(index="elastiflow-*", body=query)
            return response['hits']['hits']
        except Exception as e:
            print(f"Error fetching data: {e}")
            return []
    
    def prepare_features(self, raw_data):
        """Prepare features for ML analysis"""
        features = []
        
        for hit in raw_data:
            source = hit['_source']
            netflow = source.get('netflow', {})
            
            feature_vector = [
                netflow.get('in_bytes', 0),
                netflow.get('in_pkts', 0),
                netflow.get('flow_duration_milliseconds', 0),
                netflow.get('src_port', 0),
                netflow.get('dst_port', 0),
                netflow.get('protocol', 0)
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    def detect_anomalies_isolation_forest(self, features):
        """Detect anomalies using Isolation Forest"""
        if len(features) == 0:
            return []
            
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Apply Isolation Forest
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomaly_labels = iso_forest.fit_predict(features_scaled)
        
        return anomaly_labels
    
    def detect_anomalies_dbscan(self, features):
        """Detect anomalies using DBSCAN clustering"""
        if len(features) == 0:
            return []
            
        features_scaled = self.scaler.fit_transform(features)
        
        # Apply DBSCAN
        dbscan = DBSCAN(eps=0.5, min_samples=5)
        cluster_labels = dbscan.fit_predict(features_scaled)
        
        # Points with label -1 are considered anomalies
        return cluster_labels
    
    def analyze_traffic_patterns(self):
        """Main analysis function"""
        print("Fetching NetFlow data...")
        raw_data = self.fetch_netflow_data()
        
        if not raw_data:
            print("No data found. Generating synthetic data for demonstration...")
            return self.generate_synthetic_analysis()
        
        print(f"Processing {len(raw_data)} flow records...")
        features = self.prepare_features(raw_data)
        
        if len(features) == 0:
            print("No valid features extracted")
            return
        
        # Detect anomalies using both methods
        iso_anomalies = self.detect_anomalies_isolation_forest(features)
        dbscan_anomalies = self.detect_anomalies_dbscan(features)
        
        # Analyze results
        iso_anomaly_count = np.sum(iso_anomalies == -1)
        dbscan_anomaly_count = np.sum(dbscan_anomalies == -1)
        
        print(f"\nAnomaly Detection Results:")
        print(f"Isolation Forest detected {iso_anomaly_count} anomalies out of {len(features)} flows")
        print(f"DBSCAN detected {dbscan_anomaly_count} anomalies out of {len(features)} flows")
        
        # Create visualizations
        self.create_visualizations(features, iso_anomalies, dbscan_anomalies)
        
        return {
            'total_flows': len(features),
            'isolation_forest_anomalies': iso_anomaly_count,
            'dbscan_anomalies': dbscan_anomaly_count,
            'features': features,
            'iso_labels': iso_anomalies,
            'dbscan_labels': dbscan_anomalies
        }
    
    def generate_synthetic_analysis(self):
        """Generate synthetic data for demonstration"""
        print("Generating synthetic NetFlow data for analysis...")
        
        # Create synthetic normal traffic
        normal_traffic = np.random.normal(0, 1, (200, 6))
        normal_traffic[:, 0] = np.random.exponential(1000, 200)  # bytes
        normal_traffic[:, 1] = np.random.exponential(10, 200)    # packets
        normal_traffic[:, 2] = np.random.exponential(5000, 200)  # duration
        normal_traffic[:, 3] = np.random.randint(1024, 65535, 200)  # src_port
        normal_traffic[:, 4] = np.random.choice([80, 443, 22, 53], 200)  # dst_port
        normal_traffic[:, 5] = np.random.choice([6, 17], 200)  # protocol
        
        # Create synthetic anomalous traffic
        anomalous_traffic = np.random.normal(0, 1, (20, 6))
        anomalous_traffic[:, 0] = np.random.exponential(10000, 20)  # high bytes
        anomalous_traffic[:, 1] = np.random.exponential(100, 20)   # high packets
        anomalous_traffic[:, 2] = np.random.exponential(50000, 20) # long duration
        anomalous_traffic[:, 3] = np.random.randint(1024, 65535, 20)
        anomalous_traffic[:, 4] = np.random.randint(1, 1024, 20)  # unusual ports
        anomalous_traffic[:, 5] = np.random.choice([6, 17], 20)
        
        # Combine data
        features = np.vstack([normal_traffic, anomalous_traffic])
        
        # Detect anomalies
        iso_anomalies = self.detect_anomalies_isolation_forest(features)
        dbscan_anomalies = self.detect_anomalies_dbscan(features)
        
        iso_anomaly_count = np.sum(iso_anomalies == -1)
        dbscan_anomaly_count = np.sum(dbscan_anomalies == -1)
        
        print(f"\nSynthetic Data Analysis Results:")
        print(f"Total flows: {len(features)}")
        print(f"Isolation Forest detected {iso_anomaly_count} anomalies")
        print(f"DBSCAN detected {dbscan_anomaly_count} anomalies")
        
        self.create_visualizations(features, iso_anomalies, dbscan_anomalies)
        
        return {
            'total_flows': len(features),
            'isolation_forest_anomalies': iso_anomaly_count,
            'dbscan_anomalies': dbscan_anomaly_count
        }
    
    def create_visualizations(self, features, iso_labels, dbscan_labels):
        """Create visualization plots"""
        plt.figure(figsize=(15, 10))
        
        # Plot 1: Bytes vs Packets with Isolation Forest results
        plt.subplot(2, 3, 1)
        normal_mask = iso_labels == 1
        anomaly_mask = iso_labels == -1
        
        plt.scatter(features[normal_mask, 0], features[normal_mask, 1], 
                   c='blue', alpha=0.6, label='Normal', s=20)
        plt.scatter(features[anomaly_mask, 0], features[anomaly_mask, 1], 
                   c='red', alpha=0.8, label='Anomaly', s=30)
        plt.xlabel('Bytes')
        plt.ylabel('Packets')
        plt.title('Isolation Forest: Bytes vs Packets')
        plt.legend()
        
        # Plot 2: Duration vs Bytes with DBSCAN results
        plt.subplot(2, 3, 2)
        normal_mask = dbscan_labels != -1
        anomaly_mask = dbscan_labels == -1
        
        plt.scatter(features[normal_mask, 2], features[normal_mask, 0], 
                   c='green', alpha=0.6, label='Normal', s=20)
        plt.scatter(features[anomaly_mask, 2], features[anomaly_mask, 0], 
                   c='red', alpha=0.8, label='Anomaly', s=30)
        plt.xlabel('Duration (ms)')
        plt.ylabel('Bytes')
        plt.title('DBSCAN: Duration vs Bytes')
        plt.legend()
        
        # Plot 3: Port distribution
        plt.subplot(2, 3, 3)
        plt.hist(features[:, 4], bins=20, alpha=0.7, color='skyblue')
        plt.xlabel('Destination Port')
        plt.ylabel('Frequency')
        plt.title('Destination Port Distribution')
        
        # Plot 4: Anomaly comparison
        plt.subplot(2, 3, 4)
        methods = ['Isolation Forest', 'DBSCAN']
        anomaly_counts = [np.sum(iso_labels == -1), np.sum(dbscan_labels == -1)]
        plt.bar(methods, anomaly_counts, color=['orange', 'purple'])
        plt.ylabel('Number of Anomalies')
        plt.title('Anomaly Detection Comparison')
        
        # Plot 5: Feature correlation heatmap
        plt.subplot(2, 3, 5)
        feature_names = ['Bytes', 'Packets', 'Duration', 'Src Port', 'Dst Port', 'Protocol']
        df = pd.DataFrame(features, columns=feature_names)
        correlation_matrix = df.corr()
        sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0)
        plt.title('Feature Correlation Matrix')
        
        # Plot 6: Anomaly score distribution
        plt.subplot(2, 3, 6)
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        features_scaled = self.scaler.fit_transform(features)
        anomaly_scores = iso_forest.fit(features_scaled).decision_function(features_scaled)
        plt.hist(anomaly_scores, bins=30, alpha=0.7, color='lightcoral')
        plt.xlabel('Anomaly Score')
        plt.ylabel('Frequency')
        plt.title('Isolation Forest Anomaly Scores')
        
        plt.tight_layout()
        plt.savefig('netflow_anomaly_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("\nVisualization saved as 'netflow_anomaly_analysis.png'")

def main():
    detector = NetFlowAnomalyDetector()
    results = detector.analyze_traffic_patterns()
    
    print("\n" + "="*50)
    print("NETWORK FLOW ANOMALY DETECTION COMPLETE")
    print("="*50)
    
    if results:
        print(f"Analysis Summary:")
        print(f"- Total flows analyzed: {results['total_flows']}")
        print(f"- Isolation Forest anomalies: {results['isolation_forest_anomalies']}")
        print(f"- DBSCAN anomalies: {results['dbscan_anomalies']}")
        
        anomaly_rate_iso = (results['isolation_forest_anomalies'] / results['total_flows']) * 100
        anomaly_rate_dbscan = (results['dbscan_anomalies'] / results['total_flows']) * 100
        
        print(f"- Isolation Forest anomaly rate: {anomaly_rate_iso:.2f}%")
        print(f"- DBSCAN anomaly rate: {anomaly_rate_dbscan:.2f}%")

if __name__ == "__main__":
    main()
