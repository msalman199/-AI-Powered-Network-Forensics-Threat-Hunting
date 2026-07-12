#!/usr/bin/env python3

import pandas as pd
import os

def validate_results():
    print("=== VALIDATION REPORT ===")
    
    # Check if main results file exists
    results_file = '/tmp/smb_clustering_results.csv'
    if os.path.exists(results_file):
        df = pd.read_csv(results_file)
        print(f"✓ Main results file found with {len(df)} records")
        
        # Check required columns
        required_cols = ['packet_size', 'file_size', 'smb_command', 'kmeans_cluster', 'dbscan_cluster']
        missing_cols = [col for col in required_cols if col not in df.columns]
        
        if not missing_cols:
            print("✓ All required columns present")
        else:
            print(f"✗ Missing columns: {missing_cols}")
        
        # Check cluster assignments
        kmeans_clusters = df['kmeans_cluster'].nunique()
        dbscan_clusters = df['dbscan_cluster'].nunique()
        
        print(f"✓ K-Means found {kmeans_clusters} clusters")
        print(f"✓ DBSCAN found {dbscan_clusters} clusters")
        
    else:
        print("✗ Main results file not found")
    
    # Check anomaly results
    anomaly_file = '/tmp/anomalous_smb_transfers.csv'
    if os.path.exists(anomaly_file):
        anomaly_df = pd.read_csv(anomaly_file)
        print(f"✓ Anomaly results file found with {len(anomaly_df)} anomalous transfers")
    else:
        print("✗ Anomaly results file not found")
    
    # Check visualizations
    viz_files = ['/tmp/k-means_clusters.png', '/tmp/dbscan_clusters.png', '/tmp/anomaly_analysis.png']
    for viz_file in viz_files:
        if os.path.exists(viz_file):
            print(f"✓ Visualization found: {os.path.basename(viz_file)}")
        else:
            print(f"✗ Visualization missing: {os.path.basename(viz_file)}")

if __name__ == "__main__":
    validate_results()
