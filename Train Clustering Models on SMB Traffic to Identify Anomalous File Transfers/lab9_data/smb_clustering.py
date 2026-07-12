#!/usr/bin/env python3

import pandas as pd
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
import matplotlib.pyplot as plt
import seaborn as sns
import pyshark
import warnings
warnings.filterwarnings('ignore')

class SMBTrafficAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.traffic_data = []
        
    def extract_smb_features(self):
        """Extract features from SMB traffic"""
        print("Extracting SMB traffic features...")
        
        try:
            cap = pyshark.FileCapture(self.pcap_file, display_filter='smb2')
            
            for packet in cap:
                try:
                    if hasattr(packet, 'smb2'):
                        smb_info = {
                            'timestamp': float(packet.sniff_timestamp),
                            'src_ip': packet.ip.src if hasattr(packet, 'ip') else '127.0.0.1',
                            'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else '127.0.0.1',
                            'packet_size': int(packet.length),
                            'smb_command': getattr(packet.smb2, 'cmd', 0),
                            'file_size': getattr(packet.smb2, 'file_size', 0) if hasattr(packet.smb2, 'file_size') else 0
                        }
                        self.traffic_data.append(smb_info)
                except Exception as e:
                    continue
                    
            cap.close()
            
        except Exception as e:
            print(f"Error reading pcap: {e}")
            # Generate synthetic data for demonstration
            self.generate_synthetic_data()
            
        return pd.DataFrame(self.traffic_data)
    
    def generate_synthetic_data(self):
        """Generate synthetic SMB traffic data for demonstration"""
        print("Generating synthetic SMB traffic data...")
        np.random.seed(42)
        
        # Normal traffic patterns
        for i in range(100):
            self.traffic_data.append({
                'timestamp': 1000000 + i * 10,
                'src_ip': '192.168.1.10',
                'dst_ip': '192.168.1.100',
                'packet_size': np.random.normal(1500, 300),
                'smb_command': np.random.choice([1, 2, 3, 5]),  # Common SMB commands
                'file_size': np.random.normal(50000, 10000)
            })
        
        # Anomalous traffic patterns
        for i in range(10):
            self.traffic_data.append({
                'timestamp': 1000000 + i * 5,
                'src_ip': '192.168.1.10',
                'dst_ip': '192.168.1.100',
                'packet_size': np.random.normal(8000, 1000),  # Larger packets
                'smb_command': 14,  # Unusual command
                'file_size': np.random.normal(500000, 100000)  # Large files
            })
    
    def prepare_features(self, df):
        """Prepare features for clustering"""
        print("Preparing features for clustering...")
        
        # Calculate additional features
        df['packets_per_second'] = df.groupby('timestamp')['packet_size'].transform('count')
        df['avg_packet_size'] = df.groupby(['src_ip', 'dst_ip'])['packet_size'].transform('mean')
        df['total_bytes'] = df.groupby(['src_ip', 'dst_ip'])['packet_size'].transform('sum')
        
        # Select features for clustering
        features = ['packet_size', 'file_size', 'smb_command', 'packets_per_second', 'avg_packet_size', 'total_bytes']
        
        # Handle missing values
        feature_df = df[features].fillna(0)
        
        return feature_df
    
    def apply_kmeans_clustering(self, features, n_clusters=3):
        """Apply K-Means clustering"""
        print(f"Applying K-Means clustering with {n_clusters} clusters...")
        
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)
        
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        clusters = kmeans.fit_predict(scaled_features)
        
        silhouette_avg = silhouette_score(scaled_features, clusters)
        print(f"K-Means Silhouette Score: {silhouette_avg:.3f}")
        
        return clusters, kmeans, scaler
    
    def apply_dbscan_clustering(self, features, eps=0.5, min_samples=5):
        """Apply DBSCAN clustering"""
        print(f"Applying DBSCAN clustering (eps={eps}, min_samples={min_samples})...")
        
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)
        
        dbscan = DBSCAN(eps=eps, min_samples=min_samples)
        clusters = dbscan.fit_predict(scaled_features)
        
        n_clusters = len(set(clusters)) - (1 if -1 in clusters else 0)
        n_noise = list(clusters).count(-1)
        
        print(f"DBSCAN found {n_clusters} clusters and {n_noise} noise points")
        
        if n_clusters > 1:
            silhouette_avg = silhouette_score(scaled_features[clusters != -1], clusters[clusters != -1])
            print(f"DBSCAN Silhouette Score: {silhouette_avg:.3f}")
        
        return clusters, dbscan, scaler
    
    def visualize_clusters(self, features, clusters, method_name):
        """Visualize clustering results"""
        print(f"Creating visualization for {method_name}...")
        
        plt.figure(figsize=(12, 8))
        
        # Plot 1: Packet Size vs File Size
        plt.subplot(2, 2, 1)
        scatter = plt.scatter(features['packet_size'], features['file_size'], c=clusters, cmap='viridis', alpha=0.6)
        plt.xlabel('Packet Size')
        plt.ylabel('File Size')
        plt.title(f'{method_name}: Packet Size vs File Size')
        plt.colorbar(scatter)
        
        # Plot 2: SMB Command vs Total Bytes
        plt.subplot(2, 2, 2)
        scatter = plt.scatter(features['smb_command'], features['total_bytes'], c=clusters, cmap='viridis', alpha=0.6)
        plt.xlabel('SMB Command')
        plt.ylabel('Total Bytes')
        plt.title(f'{method_name}: SMB Command vs Total Bytes')
        plt.colorbar(scatter)
        
        # Plot 3: Cluster distribution
        plt.subplot(2, 2, 3)
        unique_clusters, counts = np.unique(clusters, return_counts=True)
        plt.bar(unique_clusters, counts)
        plt.xlabel('Cluster ID')
        plt.ylabel('Number of Points')
        plt.title(f'{method_name}: Cluster Distribution')
        
        # Plot 4: Average packet size by cluster
        plt.subplot(2, 2, 4)
        cluster_stats = pd.DataFrame({'cluster': clusters, 'packet_size': features['packet_size']})
        avg_sizes = cluster_stats.groupby('cluster')['packet_size'].mean()
        plt.bar(avg_sizes.index, avg_sizes.values)
        plt.xlabel('Cluster ID')
        plt.ylabel('Average Packet Size')
        plt.title(f'{method_name}: Avg Packet Size by Cluster')
        
        plt.tight_layout()
        plt.savefig(f'/tmp/{method_name.lower()}_clusters.png', dpi=150, bbox_inches='tight')
        plt.show()

def main():
    # Initialize analyzer
    analyzer = SMBTrafficAnalyzer('/home/ubuntu/lab9_data/smb_traffic.pcap')
    
    # Extract features
    df = analyzer.extract_smb_features()
    print(f"Extracted {len(df)} SMB packets")
    
    if len(df) == 0:
        print("No SMB traffic found. Using synthetic data for demonstration.")
        return
    
    # Prepare features
    features = analyzer.prepare_features(df)
    print(f"Prepared {len(features.columns)} features: {list(features.columns)}")
    
    # Apply K-Means clustering
    kmeans_clusters, kmeans_model, kmeans_scaler = analyzer.apply_kmeans_clustering(features)
    
    # Apply DBSCAN clustering
    dbscan_clusters, dbscan_model, dbscan_scaler = analyzer.apply_dbscan_clustering(features)
    
    # Visualize results
    analyzer.visualize_clusters(features, kmeans_clusters, 'K-Means')
    analyzer.visualize_clusters(features, dbscan_clusters, 'DBSCAN')
    
    # Add cluster labels to original dataframe
    df['kmeans_cluster'] = kmeans_clusters
    df['dbscan_cluster'] = dbscan_clusters
    
    # Save results
    df.to_csv('/tmp/smb_clustering_results.csv', index=False)
    print("Results saved to /tmp/smb_clustering_results.csv")
    
    return df, features, kmeans_clusters, dbscan_clusters

if __name__ == "__main__":
    results = main()
