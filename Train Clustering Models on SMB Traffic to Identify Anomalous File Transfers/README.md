<div align="center">

# 🕵️ Train Clustering Models on SMB Traffic to Identify Anomalous File Transfers

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scikit Learn](https://img.shields.io/badge/Scikit--Learn-ML-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data%20Analysis-150458?style=for-the-badge&logo=pandas&logoColor=white)
![NumPy](https://img.shields.io/badge/NumPy-Numerical%20Computing-013243?style=for-the-badge&logo=numpy&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-tshark%2Fpyshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![tcpdump](https://img.shields.io/badge/tcpdump-Packet%20Capture-002B5C?style=for-the-badge&logo=linux&logoColor=white)
![Samba](https://img.shields.io/badge/Samba-SMB%2FCIFS-0078D4?style=for-the-badge&logo=samba&logoColor=white)
![Matplotlib](https://img.shields.io/badge/Matplotlib-Visualization-11557C?style=for-the-badge&logo=plotly&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Environment-FCC624?style=for-the-badge&logo=linux&logoColor=black)

**Difficulty:** Intermediate | **Category:** Blue Team — Network Security & Machine Learning | **Est. Time:** 90–120 minutes

</div>

---

## 📚 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🧩 Task 1: Collect SMB Traffic Data](#-task-1-collect-smb-traffic-data)
- [🤖 Task 2: Apply Clustering Algorithms for Anomaly Detection](#-task-2-apply-clustering-algorithms-for-anomaly-detection)
- [🔎 Task 3: Analyze Results for Abnormal File Transfer Patterns](#-task-3-analyze-results-for-abnormal-file-transfer-patterns)
- [✅ Verification and Testing](#-verification-and-testing)
- [🛡️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🧯 Troubleshooting](#-troubleshooting)
- [📝 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Capture and analyze SMB network traffic data |
| 2 | Implement clustering algorithms to detect anomalous file transfer patterns |
| 3 | Build machine learning models for network security anomaly detection |
| 4 | Interpret clustering results to identify suspicious SMB activities |

## 📋 Prerequisites

| # | Requirement |
|---|-------------|
| 1 | Basic understanding of networking protocols (SMB/CIFS) |
| 2 | Familiarity with Python programming |
| 3 | Knowledge of machine learning clustering concepts |
| 4 | Understanding of Linux command line operations |

## 🖥️ Lab Environment

> **☁️ Al Nafi Cloud Lab**
> Al Nafi provides Linux-based cloud machines for this lab. Simply click **Start Lab** to access your dedicated environment. The provided Linux machine is bare metal with no pre-installed tools, so you will install all required software during the lab.

---

## 🧩 Task 1: Collect SMB Traffic Data

### 🛠️ Subtask 1.1: Install Required Tools

Update the system and install the necessary packages:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip tcpdump wireshark-common tshark samba samba-common-bin
pip3 install pandas numpy scikit-learn matplotlib seaborn pyshark scapy
```

### 📡 Subtask 1.2: Generate SMB Traffic

Create a local SMB share to generate realistic traffic:

```bash
# 📁 Create shared directory
sudo mkdir -p /srv/samba/testshare
sudo chmod 777 /srv/samba/testshare

# ⚙️ Configure Samba
sudo tee /etc/samba/smb.conf > /dev/null << EOF
[global]
workgroup = WORKGROUP
security = user
map to guest = bad user

[testshare]
path = /srv/samba/testshare
browseable = yes
writable = yes
guest ok = yes
read only = no
EOF

# ▶️ Start Samba service
sudo systemctl restart smbd
sudo systemctl enable smbd

# TODO: Change the workgroup name and share path to match your own lab naming convention
```

### 🎯 Subtask 1.3: Capture SMB Traffic

Start a packet capture in the background:

```bash
# 🗂️ Create capture directory
mkdir -p ~/lab9_data

# 🎥 Start tcpdump for SMB traffic (port 445)
sudo tcpdump -i lo -w ~/lab9_data/smb_traffic.pcap port 445 &
TCPDUMP_PID=$!
echo "Capture started with PID: $TCPDUMP_PID"
```

Generate a mix of normal and anomalous SMB activity:

```bash
# 📄 Create test files with different sizes
cd /srv/samba/testshare
echo "Normal small file" > small_file.txt
dd if=/dev/zero of=medium_file.dat bs=1M count=5
dd if=/dev/zero of=large_file.dat bs=1M count=50

# 🔁 Simulate normal file operations
for i in {1..10}; do
    cp small_file.txt "copy_${i}.txt"
    sleep 1
done

# 🚨 Simulate anomalous large transfers
for i in {1..3}; do
    cp large_file.dat "anomaly_${i}.dat"
    sleep 2
done

# ⏹️ Stop capture after 30 seconds
sleep 30
sudo kill $TCPDUMP_PID

# TODO: Adjust file counts, sizes, and sleep intervals to build a richer, more varied traffic sample
```

---

## 🤖 Task 2: Apply Clustering Algorithms for Anomaly Detection

### 🐍 Subtask 2.1: Create Traffic Analysis Script

Create the main analysis script:

```python
#!/usr/bin/env python3
# 📊 smb_clustering.py — extracts SMB traffic features and clusters them

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
        """🔍 Extract features from SMB traffic"""
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
                except Exception:
                    continue

            cap.close()

        except Exception as e:
            print(f"Error reading pcap: {e}")
            # 🧪 Fall back to synthetic data for demonstration
            self.generate_synthetic_data()

        return pd.DataFrame(self.traffic_data)

    def generate_synthetic_data(self):
        """🧪 Generate synthetic SMB traffic data for demonstration"""
        print("Generating synthetic SMB traffic data...")
        np.random.seed(42)

        # ✅ Normal traffic patterns
        for i in range(100):
            self.traffic_data.append({
                'timestamp': 1000000 + i * 10,
                'src_ip': '192.168.1.10',
                'dst_ip': '192.168.1.100',
                'packet_size': np.random.normal(1500, 300),
                'smb_command': np.random.choice([1, 2, 3, 5]),  # Common SMB commands
                'file_size': np.random.normal(50000, 10000)
            })

        # 🚨 Anomalous traffic patterns
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
        """🧮 Prepare features for clustering"""
        print("Preparing features for clustering...")

        df['packets_per_second'] = df.groupby('timestamp')['packet_size'].transform('count')
        df['avg_packet_size'] = df.groupby(['src_ip', 'dst_ip'])['packet_size'].transform('mean')
        df['total_bytes'] = df.groupby(['src_ip', 'dst_ip'])['packet_size'].transform('sum')

        features = ['packet_size', 'file_size', 'smb_command', 'packets_per_second', 'avg_packet_size', 'total_bytes']
        feature_df = df[features].fillna(0)

        return feature_df

    def apply_kmeans_clustering(self, features, n_clusters=3):
        """🎯 Apply K-Means clustering"""
        print(f"Applying K-Means clustering with {n_clusters} clusters...")

        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)

        # TODO: Tune n_clusters based on the diversity of your own captured traffic
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        clusters = kmeans.fit_predict(scaled_features)

        silhouette_avg = silhouette_score(scaled_features, clusters)
        print(f"K-Means Silhouette Score: {silhouette_avg:.3f}")

        return clusters, kmeans, scaler

    def apply_dbscan_clustering(self, features, eps=0.5, min_samples=5):
        """🌐 Apply DBSCAN clustering"""
        print(f"Applying DBSCAN clustering (eps={eps}, min_samples={min_samples})...")

        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)

        # TODO: Tune eps and min_samples for your own traffic density
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
        """📈 Visualize clustering results"""
        print(f"Creating visualization for {method_name}...")

        plt.figure(figsize=(12, 8))

        # 📦 Plot 1: Packet Size vs File Size
        plt.subplot(2, 2, 1)
        scatter = plt.scatter(features['packet_size'], features['file_size'], c=clusters, cmap='viridis', alpha=0.6)
        plt.xlabel('Packet Size')
        plt.ylabel('File Size')
        plt.title(f'{method_name}: Packet Size vs File Size')
        plt.colorbar(scatter)

        # 📦 Plot 2: SMB Command vs Total Bytes
        plt.subplot(2, 2, 2)
        scatter = plt.scatter(features['smb_command'], features['total_bytes'], c=clusters, cmap='viridis', alpha=0.6)
        plt.xlabel('SMB Command')
        plt.ylabel('Total Bytes')
        plt.title(f'{method_name}: SMB Command vs Total Bytes')
        plt.colorbar(scatter)

        # 📦 Plot 3: Cluster distribution
        plt.subplot(2, 2, 3)
        unique_clusters, counts = np.unique(clusters, return_counts=True)
        plt.bar(unique_clusters, counts)
        plt.xlabel('Cluster ID')
        plt.ylabel('Number of Points')
        plt.title(f'{method_name}: Cluster Distribution')

        # 📦 Plot 4: Average packet size by cluster
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
    # 🚀 Initialize analyzer
    analyzer = SMBTrafficAnalyzer('/home/ubuntu/lab9_data/smb_traffic.pcap')

    # 🔍 Extract features
    df = analyzer.extract_smb_features()
    print(f"Extracted {len(df)} SMB packets")

    if len(df) == 0:
        print("No SMB traffic found. Using synthetic data for demonstration.")
        return

    # 🧮 Prepare features
    features = analyzer.prepare_features(df)
    print(f"Prepared {len(features.columns)} features: {list(features.columns)}")

    # 🎯 Apply K-Means clustering
    kmeans_clusters, kmeans_model, kmeans_scaler = analyzer.apply_kmeans_clustering(features)

    # 🌐 Apply DBSCAN clustering
    dbscan_clusters, dbscan_model, dbscan_scaler = analyzer.apply_dbscan_clustering(features)

    # 📈 Visualize results
    analyzer.visualize_clusters(features, kmeans_clusters, 'K-Means')
    analyzer.visualize_clusters(features, dbscan_clusters, 'DBSCAN')

    # 🏷️ Add cluster labels to original dataframe
    df['kmeans_cluster'] = kmeans_clusters
    df['dbscan_cluster'] = dbscan_clusters

    # 💾 Save results
    df.to_csv('/tmp/smb_clustering_results.csv', index=False)
    print("Results saved to /tmp/smb_clustering_results.csv")

    return df, features, kmeans_clusters, dbscan_clusters

if __name__ == "__main__":
    results = main()
```

Save and make it executable:

```bash
chmod +x ~/lab9_data/smb_clustering.py
```

### ▶️ Subtask 2.2: Run Clustering Analysis

Execute the clustering analysis:

```bash
cd ~/lab9_data
python3 smb_clustering.py
```

---

## 🔎 Task 3: Analyze Results for Abnormal File Transfer Patterns

### 🧬 Subtask 3.1: Create Anomaly Detection Script

Create a detailed anomaly analysis script:

```python
#!/usr/bin/env python3
# 🚨 anomaly_analysis.py — combines clustering + Isolation Forest to flag anomalies

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
        """📊 Analyze characteristics of each cluster"""
        print("=== CLUSTER ANALYSIS ===")

        print("\nK-Means Cluster Characteristics:")
        kmeans_stats = self.df.groupby('kmeans_cluster').agg({
            'packet_size': ['mean', 'std', 'min', 'max'],
            'file_size': ['mean', 'std', 'min', 'max'],
            'smb_command': ['mean', 'nunique'],
            'total_bytes': ['mean', 'std']
        }).round(2)

        print(kmeans_stats)

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
        """🚩 Identify potentially anomalous clusters"""
        print("\n=== ANOMALY IDENTIFICATION ===")

        kmeans_sizes = self.df['kmeans_cluster'].value_counts().sort_index()
        dbscan_sizes = self.df['dbscan_cluster'].value_counts().sort_index()

        print(f"\nK-Means cluster sizes: {dict(kmeans_sizes)}")
        print(f"DBSCAN cluster sizes: {dict(dbscan_sizes)}")

        total_points = len(self.df)
        anomaly_threshold = 0.05  # TODO: Tune this % threshold for what counts as a "small" cluster

        kmeans_anomalies = kmeans_sizes[kmeans_sizes < total_points * anomaly_threshold]
        dbscan_anomalies = dbscan_sizes[dbscan_sizes < total_points * anomaly_threshold]

        print(f"\nPotential anomalous K-Means clusters: {list(kmeans_anomalies.index)}")
        print(f"Potential anomalous DBSCAN clusters: {list(dbscan_anomalies.index)}")

        noise_points = len(self.df[self.df['dbscan_cluster'] == -1])
        print(f"DBSCAN noise points (definite anomalies): {noise_points}")

        return kmeans_anomalies.index.tolist(), dbscan_anomalies.index.tolist()

    def apply_isolation_forest(self):
        """🌲 Apply Isolation Forest for additional anomaly detection"""
        print("\n=== ISOLATION FOREST ANALYSIS ===")

        features = ['packet_size', 'file_size', 'smb_command', 'total_bytes']
        X = self.df[features].fillna(0)

        # TODO: Adjust contamination to match the expected anomaly rate in your environment
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomaly_labels = iso_forest.fit_predict(X)

        self.df['isolation_forest_anomaly'] = anomaly_labels

        n_anomalies = len(self.df[self.df['isolation_forest_anomaly'] == -1])
        print(f"Isolation Forest detected {n_anomalies} anomalies")

        return anomaly_labels

    def generate_anomaly_report(self, kmeans_anomalies, dbscan_anomalies):
        """📝 Generate comprehensive anomaly report"""
        print("\n=== COMPREHENSIVE ANOMALY REPORT ===")

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

        anomalous_traffic.to_csv('/tmp/anomalous_smb_transfers.csv', index=False)
        print(f"\nAnomalous transfers saved to /tmp/anomalous_smb_transfers.csv")

        return anomalous_traffic

    def create_anomaly_visualizations(self):
        """📈 Create visualizations for anomaly analysis"""
        print("\nCreating anomaly visualizations...")

        plt.figure(figsize=(15, 10))

        # 📦 Plot 1: Anomaly detection comparison
        plt.subplot(2, 3, 1)
        methods = ['K-Means', 'DBSCAN', 'Isolation Forest']
        anomaly_counts = [
            len(self.df[self.df['kmeans_cluster'].isin([0])]),
            len(self.df[self.df['dbscan_cluster'] == -1]),
            len(self.df[self.df['isolation_forest_anomaly'] == -1])
        ]
        plt.bar(methods, anomaly_counts)
        plt.title('Anomalies Detected by Method')
        plt.ylabel('Number of Anomalies')
        plt.xticks(rotation=45)

        # 📦 Plot 2: File size distribution
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

        # 📦 Plot 3: Packet size vs File size with anomalies
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

        # 📦 Plot 4: SMB Command frequency
        plt.subplot(2, 3, 4)
        cmd_counts = self.df['smb_command'].value_counts()
        plt.bar(cmd_counts.index, cmd_counts.values)
        plt.xlabel('SMB Command')
        plt.ylabel('Frequency')
        plt.title('SMB Command Distribution')

        # 📦 Plot 5: Time series of anomalies
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

        # 📦 Plot 6: Cluster comparison
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

        kmeans_stats, dbscan_stats = analyzer.analyze_cluster_characteristics()
        kmeans_anomalies, dbscan_anomalies = analyzer.identify_anomalous_clusters()
        isolation_results = analyzer.apply_isolation_forest()
        anomalous_transfers = analyzer.generate_anomaly_report(kmeans_anomalies, dbscan_anomalies)
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
```

```bash
chmod +x ~/lab9_data/anomaly_analysis.py
```

### ▶️ Subtask 3.2: Execute Anomaly Analysis

Run the comprehensive anomaly analysis:

```bash
cd ~/lab9_data
python3 anomaly_analysis.py
```

### 📋 Subtask 3.3: Review Results

Examine the generated reports and visualizations:

```bash
# 📊 View anomaly summary
echo "=== ANOMALY DETECTION SUMMARY ==="
if [ -f "/tmp/anomalous_smb_transfers.csv" ]; then
    echo "Number of anomalous transfers detected:"
    wc -l /tmp/anomalous_smb_transfers.csv

    echo -e "\nFirst 5 anomalous transfers:"
    head -6 /tmp/anomalous_smb_transfers.csv
else
    echo "No anomaly results file found."
fi

# 📂 List all generated files
echo -e "\n=== GENERATED FILES ==="
ls -la /tmp/*.csv /tmp/*.png 2>/dev/null || echo "No output files found."
```

---

## ✅ Verification and Testing

Validate that your clustering models produced complete, usable output:

```python
#!/usr/bin/env python3
# ✅ validate_results.py — sanity-checks generated files and columns

import pandas as pd
import os

def validate_results():
    print("=== VALIDATION REPORT ===")

    results_file = '/tmp/smb_clustering_results.csv'
    if os.path.exists(results_file):
        df = pd.read_csv(results_file)
        print(f"✓ Main results file found with {len(df)} records")

        required_cols = ['packet_size', 'file_size', 'smb_command', 'kmeans_cluster', 'dbscan_cluster']
        missing_cols = [col for col in required_cols if col not in df.columns]

        if not missing_cols:
            print("✓ All required columns present")
        else:
            print(f"✗ Missing columns: {missing_cols}")

        kmeans_clusters = df['kmeans_cluster'].nunique()
        dbscan_clusters = df['dbscan_cluster'].nunique()

        print(f"✓ K-Means found {kmeans_clusters} clusters")
        print(f"✓ DBSCAN found {dbscan_clusters} clusters")

    else:
        print("✗ Main results file not found")

    anomaly_file = '/tmp/anomalous_smb_transfers.csv'
    if os.path.exists(anomaly_file):
        anomaly_df = pd.read_csv(anomaly_file)
        print(f"✓ Anomaly results file found with {len(anomaly_df)} anomalous transfers")
    else:
        print("✗ Anomaly results file not found")

    viz_files = ['/tmp/k-means_clusters.png', '/tmp/dbscan_clusters.png', '/tmp/anomaly_analysis.png']
    for viz_file in viz_files:
        if os.path.exists(viz_file):
            print(f"✓ Visualization found: {os.path.basename(viz_file)}")
        else:
            print(f"✗ Visualization missing: {os.path.basename(viz_file)}")

if __name__ == "__main__":
    validate_results()
```

```bash
python3 ~/lab9_data/validate_results.py
```

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Relevance to This Lab |
|--------|-----------|-----|------------------------|
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 | Large anomalous SMB transfers can indicate data leaving the network over a non-standard exfiltration channel |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | Unusual SMB command patterns and destinations may reflect an attacker moving between hosts via SMB shares |
| Collection | Data Staged | T1074 | Sudden spikes in file copy activity to a share can indicate data being staged before exfiltration |
| Collection | Data from Network Shared Drive | T1039 | Clustering flags abnormal access/transfer volume from shared drives consistent with bulk data collection |
| Discovery | Network Share Discovery | T1135 | Repeated or scripted SMB command sequences preceding large transfers can point to share enumeration |

---

## 🧯 Troubleshooting

<details>
<summary>🔴 pyshark fails to read the pcap file or hangs</summary>

- Confirm `tshark` is installed and on `PATH`: `tshark --version`
- Ensure the pcap file path passed to `SMBTrafficAnalyzer` matches where `tcpdump` actually saved it
- Run `sudo chmod +r ~/lab9_data/smb_traffic.pcap` if pyshark reports a permission error
- If pyshark still fails, the script automatically falls back to `generate_synthetic_data()` so the pipeline can still be demonstrated

</details>

<details>
<summary>🔴 No SMB2 packets found in the capture</summary>

- Confirm Samba is running: `sudo systemctl status smbd`
- Verify the capture interface matches where traffic actually flows — loopback (`lo`) only works if the client and share are on the same machine
- Re-run the traffic generation subtask while the `tcpdump` capture is active, not before or after it
- Check the capture filter is `port 445` and not blocked by a host firewall (`sudo ufw status`)

</details>

<details>
<summary>🔴 "Permission denied" running tcpdump</summary>

- `tcpdump` requires elevated privileges to capture packets; always invoke it with `sudo`
- Alternatively, grant capture capabilities: `sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)`

</details>

<details>
<summary>🔴 Silhouette score error: "Number of labels is 1"</summary>

- This occurs when K-Means or DBSCAN produces only a single cluster
- For K-Means, increase `n_clusters` or check your feature scaling
- For DBSCAN, reduce `eps` or lower `min_samples` so the algorithm can separate distinct groups

</details>

<details>
<summary>🔴 matplotlib window doesn't appear on a headless cloud machine</summary>

- The scripts already save figures to `/tmp/*.png` via `plt.savefig()`, so `plt.show()` failing silently is expected on headless servers
- Set the backend explicitly before importing pyplot if needed: `matplotlib.use('Agg')`
- Download or `scp` the generated `.png` files locally to view them

</details>

<details>
<summary>🔴 Empty or near-empty results DataFrame</summary>

- Confirm the traffic generation subtask actually ran while the capture was active
- Check `~/lab9_data/smb_traffic.pcap` file size — if it's near 0 bytes, the capture didn't record anything
- Re-run Task 1 end-to-end before re-running the clustering scripts

</details>

---

## 📝 Conclusion

### 🏆 Key Accomplishments

- Captured SMB network traffic using `tcpdump` and generated realistic file transfer patterns
- Implemented multiple clustering algorithms (K-Means and DBSCAN) to identify patterns in SMB traffic
- Applied machine learning techniques including Isolation Forest for anomaly detection
- Analyzed clustering results to identify suspicious file transfer behaviors
- Created comprehensive visualizations to interpret anomalous network activities

### 🌍 Real-World Applications

This hands-on experience demonstrates how clustering algorithms can be effectively used for network security monitoring, specifically for detecting unusual SMB file transfer patterns that might indicate data exfiltration, malware activity, or other security threats. The techniques learned here are directly applicable to real-world SOC workflows and threat detection pipelines, where the combination of multiple clustering approaches provides robust anomaly detection capabilities while visualizations help security analysts quickly identify and investigate suspicious network behaviors.

---

<div align="center">

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cybersecurity%20Training-blueviolet?style=for-the-badge)

</div>
