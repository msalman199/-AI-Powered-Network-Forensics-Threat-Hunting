#!/usr/bin/env python3

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class AnomalyAnalyzer:
    def __init__(self, results_file):
        self.df = pd.read_csv(results_file)
        
    def analyze_cluster_characteristics(self):
        """Analyze characteristics of each cluster"""
        print("=== CLUSTER ANALYSIS ===")
        
        # K-Means cluster analysis
        print("\nK-Means Cluster Characteristics:")
        kmeans_stats = self.df.groupby('kmeans_cluster').agg({
            'packet_size': ['mean', 'std', 'min', 'max'],
            'file_size': ['mean', 'std', 'min', 'max'],
            'smb_command': ['mean', 'nunique'],
            'total_bytes': ['mean', 'std']
        }).round(2)
        
        print(kmeans_stats)
        
        # DBSCAN cluster analysis
        print("\nDBSCAN Cluster Characteristics:")
        dbscan_stats = self.df.groupby('dbscan_cluster').agg({
            'packet_size': ['mean', 'std', 'min', 'max'],
            'file_size': ['mean', 'std', 'min', 'max'],
            'smb_command': ['mean', 'nunique'],
            'total_bytes': ['mean', 'std']
        }).round(2)
        
        print(dbscan_stats)
        
        return kmeans_stats, dbscan_stats
    
    def identify_anomalous_clusters(self):
        """Identify potentially anomalous clusters"""
        print("\n=== ANOMALY IDENTIFICATION ===")
        
        # Calculate cluster sizes
        kmeans_sizes = self.df['kmeans_cluster'].value_counts().sort_index()
        dbscan_sizes = self.df['dbscan_cluster'].value_counts().sort_index()
        
        print(f"\nK-Means cluster sizes: {dict(kmeans_sizes)}")
        print(f"DBSCAN cluster sizes: {dict(dbscan_sizes)}")
        
        # Identify small clusters (potential anomalies)
        total_points = len(self.df)
        anomaly_threshold = 0.05  # 5% of total points
        
        kmeans_anomalies = kmeans_sizes[kmeans_sizes < total_points * anomaly_threshold]
        dbscan_anomalies = dbscan_sizes[dbscan_sizes < total_points * anomaly_threshold]
        
        print(f"\nPotential anomalous K-Means clusters: {list(kmeans_anomalies.index)}")
        print(f"Potential anomalous DBSCAN clusters: {list(dbscan_anomalies.index)}")
        
        # DBSCAN noise points (cluster -1) are automatically anomalies
        noise_points = len(self.df[self.df['dbscan_cluster'] == -1])
        print(f"DBSCAN noise points (definite anomalies): {noise_points}")
        
        return kmeans_anomalies.index.tolist(), dbscan_anomalies.index.tolist()
    
    def apply_isolation_forest(self):
        """Apply Isolation Forest for additional anomaly detection"""
        print("\n=== ISOLATION FOREST ANALYSIS ===")
        
        # Prepare features
        features = ['packet_size', 'file_size', 'smb_command', 'total_bytes']
        X = self.df[features].fillna(0)
        
        # Apply Isolation Forest
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomaly_labels = iso_forest.fit_predict(X)
        
        # Add results to dataframe
        self.df['isolation_forest_anomaly'] = anomaly_labels
        
        n_anomalies = len(self.df[self.df['isolation_forest_anomaly'] == -1])
        print(f"Isolation Forest detected {n_anomalies} anomalies")
        
        return anomaly_labels
    
    def generate_anomaly_report(self, kmeans_anomalies, dbscan_anomalies):
        """Generate comprehensive anomaly report"""
        print("\n=== COMPREHENSIVE ANOMALY REPORT ===")
        
        # Combine all anomaly detection methods
        anomaly_mask = (
            self.df['kmeans_cluster'].isin(kmeans_anomalies) |
            self.df['dbscan_cluster'].isin(dbscan_anomalies) |
            (self.df['dbscan_cluster'] == -1) |
            (self.df['isolation_forest_anomaly'] == -1)
        )
        
        anomalous_traffic = self.df[anomaly_mask]
        normal_traffic = self.df[~anomaly_mask]
        
        print(f"\nTotal anomalous transfers detected: {len(anomalous_traffic)}")
        print(f"Total normal transfers: {len(normal_traffic)}")
        print(f"Anomaly rate: {len(anomalous_traffic)/len(self.df)*100:.2f}%")
        
        if len(anomalous_traffic) > 0:
            print("\nAnomalous Transfer Characteristics:")
            print(f"Average packet size: {anomalous_traffic['packet_size'].mean():.2f}")
            print(f"Average file size: {anomalous_traffic['file_size'].mean():.2f}")
            print(f"Most common SMB commands: {anomalous_traffic['smb_command'].mode().values}")
            print(f"Average total bytes: {anomalous_traffic['total_bytes'].mean():.2f}")
            
            print("\nNormal Transfer Characteristics:")
            print(f"Average packet size: {normal_traffic['packet_size'].mean():.2f}")
            print(f"Average file size: {normal_traffic['file_size'].mean():.2f}")
            print(f"Most common SMB commands: {normal_traffic['smb_command'].mode().values}")
            print(f"Average total bytes: {normal_traffic['total_bytes'].mean():.2f}")
        
        # Save anomaly report
        anomalous_traffic.to_csv('/tmp/anomalous_smb_transfers.csv', index=False)
        print(f"\nAnomalous transfers saved to /tmp/anomalous_smb_transfers.csv")
        
        return anomalous_traffic
    
    def create_anomaly_visualizations(self):
        """Create visualizations for anomaly analysis"""
        print("\nCreating anomaly visualizations...")
        
        plt.figure(figsize=(15, 10))
        
        # Plot 1: Anomaly detection comparison
        plt.subplot(2, 3, 1)
        methods = ['K-Means', 'DBSCAN', 'Isolation Forest']
        anomaly_counts = [
            len(self.df[self.df['kmeans_cluster'].isin([0])]),  # Assuming cluster 0 is anomalous
            len(self.df[self.df['dbscan_cluster'] == -1]),
            len(self.df[self.df['isolation_forest_anomaly'] == -1])
        ]
        plt.bar(methods, anomaly_counts)
        plt.title('Anomalies Detected by Method')
        plt.ylabel('Number of Anomalies')
        plt.xticks(rotation=45)
        
        # Plot 2: File size distribution
        plt.subplot(2, 3, 2)
        plt.hist(self.df['file_size'], bins=30, alpha=0.7, label='All')
        if 'isolation_forest_anomaly' in self.df.columns:
            anomalies = self.df[self.df['isolation_forest_anomaly'] == -1]
            if len(anomalies) > 0:
                plt.hist(anomalies['file_size'], bins=30, alpha=0.7, label='Anomalies')
        plt.xlabel('File Size')
        plt.ylabel('Frequency')
        plt.title('File Size Distribution')
        plt.legend()
        
        # Plot 3: Packet size vs File size with anomalies
        plt.subplot(2, 3, 3)
        normal = self.df[self.df['isolation_forest_anomaly'] == 1] if 'isolation_forest_anomaly' in self.df.columns else self.df
        anomalies = self.df[self.df['isolation_forest_anomaly'] == -1] if 'isolation_forest_anomaly' in self.df.columns else pd.DataFrame()
        
        plt.scatter(normal['packet_size'], normal['file_size'], alpha=0.6, label='Normal', s=20)
        if len(anomalies) > 0:
            plt.scatter(anomalies['packet_size'], anomalies['file_size'], alpha=0.8, label='Anomalies', s=50, color='red')
        plt.xlabel('Packet Size')
        plt.ylabel('File Size')
        plt.title('Packet Size vs File Size')
        plt.legend()
        
        # Plot 4: SMB Command frequency
        plt.subplot(2, 3, 4)
        cmd_counts = self.df['smb_command'].value_counts()
        plt.bar(cmd_counts.index, cmd_counts.values)
        plt.xlabel('SMB Command')
        plt.ylabel('Frequency')
        plt.title('SMB Command Distribution')
        
        # Plot 5: Time series of anomalies
        plt.subplot(2, 3, 5)
        if 'timestamp' in self.df.columns:
            self.df['datetime'] = pd.to_datetime(self.df['timestamp'], unit='s')
            normal_ts = self.df[self.df['isolation_forest_anomaly'] == 1] if 'isolation_forest_anomaly' in self.df.columns else self.df
            anomaly_ts = self.df[self.df['isolation_forest_anomaly'] == -1] if 'isolation_forest_anomaly' in self.df.columns else pd.DataFrame()
            
            plt.scatter(normal_ts['datetime'], normal_ts['packet_size'], alpha=0.6, label='Normal', s=20)
            if len(anomaly_ts) > 0:
                plt.scatter(anomaly_ts['datetime'], anomaly_ts['packet_size'], alpha=0.8, label='Anomalies', s=50, color='red')
            plt.xlabel('Time')
            plt.ylabel('Packet Size')
            plt.title('Anomalies Over Time')
            plt.legend()
            plt.xticks(rotation=45)
        
        # Plot 6: Cluster comparison
        plt.subplot(2, 3, 6)
        if len(self.df['kmeans_cluster'].unique()) > 1:
            for cluster in self.df['kmeans_cluster'].unique():
                cluster_data = self.df[self.df['kmeans_cluster'] == cluster]
                plt.scatter(cluster_data['packet_size'], cluster_data['total_bytes'], 
                           label=f'Cluster {cluster}', alpha=0.6)
        plt.xlabel('Packet Size')
        plt.ylabel('Total Bytes')
        plt.title('K-Means Clusters')
        plt.legend()
        
        plt.tight_layout()
        plt.savefig('/tmp/anomaly_analysis.png', dpi=150, bbox_inches='tight')
        plt.show()

def main():
    try:
        analyzer = AnomalyAnalyzer('/tmp/smb_clustering_results.csv')
        
        # Analyze cluster characteristics
        kmeans_stats, dbscan_stats = analyzer.analyze_cluster_characteristics()
        
        # Identify anomalous clusters
        kmeans_anomalies, dbscan_anomalies = analyzer.identify_anomalous_clusters()
        
        # Apply Isolation Forest
        isolation_results = analyzer.apply_isolation_forest()
        
        # Generate comprehensive report
        anomalous_transfers = analyzer.generate_anomaly_report(kmeans_anomalies, dbscan_anomalies)
        
        # Create visualizations
        analyzer.create_anomaly_visualizations()
        
        print("\n=== LAB COMPLETED SUCCESSFULLY ===")
        print("Check /tmp/ directory for output files:")
        print("- anomalous_smb_transfers.csv: Detected anomalous transfers")
        print("- anomaly_analysis.png: Visualization of results")
        
    except FileNotFoundError:
        print("Results file not found. Please run the clustering analysis first.")
    except Exception as e:
        print(f"Error during analysis: {e}")

if __name__ == "__main__":
    main()
