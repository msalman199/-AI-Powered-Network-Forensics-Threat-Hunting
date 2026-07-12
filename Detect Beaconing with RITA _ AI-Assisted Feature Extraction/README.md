<div align="center">

# 📡 Detect Beaconing with RITA + AI-Assisted Feature Extraction

### Advanced C2 Beacon Detection using Network Traffic Analysis and Machine Learning

![RITA](https://img.shields.io/badge/RITA-v4.8.0-FF4500?style=for-the-badge&logo=data:image/png;base64,&logoColor=white)
![Zeek](https://img.shields.io/badge/Zeek-Network%20Monitor-00758F?style=for-the-badge&logo=wireshark&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scikit--learn](https://img.shields.io/badge/Scikit--learn-ML-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-Database-47A248?style=for-the-badge&logo=mongodb&logoColor=white)
![tcpdump](https://img.shields.io/badge/tcpdump-Packet%20Capture-4A4A4A?style=for-the-badge&logo=linux&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data%20Analysis-150458?style=for-the-badge&logo=pandas&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Ubuntu-FCC624?style=for-the-badge&logo=linux&logoColor=black)

</div>

---

## 📋 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [✅ Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🛠️ Task 1: Set up RITA to Detect Beaconing Activity](#️-task-1-set-up-rita-to-detect-beaconing-activity)
- [🤖 Task 2: Use AI for Feature Extraction and Enhancement](#-task-2-use-ai-for-feature-extraction-and-enhancement)
- [🔍 Task 3: Analyze Network Traffic for C2 Communication](#-task-3-analyze-network-traffic-for-c2-communication)
- [🧪 Verification and Testing](#-verification-and-testing)
- [🎯 MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [🐛 Troubleshooting](#-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

By completing this lab, you will:

| # | Objective |
|---|-----------|
| 1 | Install and configure RITA for network traffic analysis |
| 2 | Detect C2 beaconing patterns in network communications |
| 3 | Implement AI-assisted feature extraction using Python and scikit-learn |
| 4 | Analyze network traffic for command and control communication indicators |
| 5 | Generate comprehensive beaconing reports with enhanced detection capabilities |

---

## ✅ Prerequisites

| Requirement | Details |
|---|---|
| 🐧 Linux CLI | Basic command line knowledge |
| 🌐 Networking | Understanding of TCP/IP and HTTP protocols |
| 🔐 Security Concepts | Familiarity with network security fundamentals |
| 🐍 Python | Basic Python programming knowledge |

---

## 🖥️ Lab Environment

> **☁️ Cloud Lab Notice**
> Al Nafi provides a Linux-based cloud machine for this lab. Click **Start Lab** to access your dedicated environment. The machine comes as bare metal with no pre-installed tools — you will install all required components during the lab.

---

## 🛠️ Task 1: Set up RITA to Detect Beaconing Activity

### 📦 Subtask 1.1: Install Dependencies

Update the system and install required packages:

```bash
# 🔄 Update package lists and upgrade existing packages
sudo apt update && sudo apt upgrade -y

# 📥 Install core dependencies
sudo apt install -y wget curl git build-essential mongodb docker.io python3 python3-pip

# ▶️ Start and enable MongoDB service
sudo systemctl start mongodb
sudo systemctl enable mongodb
```

### 🧩 Subtask 1.2: Install RITA

Download and install RITA:

```bash
# ⬇️ Download RITA binary release
wget https://github.com/activecm/rita/releases/download/v4.8.0/rita

# 🔑 Make binary executable
chmod +x rita

# 📂 Move binary into PATH
sudo mv rita /usr/local/bin/
```

Create RITA configuration directory:

```bash
# 📁 Create config and log directories
sudo mkdir -p /etc/rita
sudo mkdir -p /var/lib/rita/logs
```

### ⚙️ Subtask 1.3: Configure RITA

Create the RITA configuration file:

```yaml
# 🗄️ /etc/rita/config.yaml
MongoDB:
    ConnectionString: mongodb://localhost:27017
    AuthenticationMechanism: ""
    SocketTimeout: 2
    TLS:
        Enable: false
        VerifyCertificate: false
        CAFile: ""

LogLevel: 2
LogPath: /var/lib/rita/logs

Rolling:
    DefaultChunks: 24

Filtering:
    AlwaysInclude: []
    NeverInclude: ["224.0.0.0/4", "255.255.255.255/32"]
    InternalSubnets: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

Beacon:
    DefaultConnectionThresh: 20

DNS:
    DefaultConnectionThresh: 10

Blacklisted:
    feodotracker.abuse.ch: true
    malwaredomainlist.com: true
```

```bash
# 🧾 Write config file to disk
sudo tee /etc/rita/config.yaml > /dev/null << 'EOF'
# ... (paste YAML content above)
EOF
```

### 🚦 Subtask 1.4: Generate Sample Network Traffic

Create a script to generate beaconing traffic for analysis:

```python
#!/usr/bin/env python3
# 📡 beacon_generator.py — simulates periodic C2-style beacon traffic
import time
import requests
import threading
import random

def generate_beacon_traffic():
    """Generate periodic HTTP requests to simulate C2 beaconing"""
    # 🎯 Target endpoints for simulated beacon traffic
    targets = [
        "http://httpbin.org/get",
        "http://httpbin.org/user-agent",
        "http://httpbin.org/headers"
    ]

    for i in range(50):
        try:
            target = random.choice(targets)
            response = requests.get(target, timeout=5)
            print(f"Beacon {i+1}: {response.status_code} - {target}")  # ✅ log success
            time.sleep(random.uniform(58, 62))  # ⏱️ ~60 second beacon interval
        except Exception as e:
            print(f"Error in beacon {i+1}: {e}")  # ⚠️ log failure
            time.sleep(60)

if __name__ == "__main__":
    generate_beacon_traffic()

# TODO: Adjust beacon interval and jitter to simulate different C2 profiles
```

```bash
# 🔑 Make script executable
chmod +x beacon_generator.py
```

### 📼 Subtask 1.5: Capture Network Traffic

Install tcpdump and capture traffic:

```bash
# 📥 Install packet capture tool
sudo apt install -y tcpdump
```

Start traffic capture in background:

```bash
# 🎥 Begin capturing all interface traffic to file
sudo tcpdump -i any -w network_traffic.pcap &
TCPDUMP_PID=$!
echo "TCPDump PID: $TCPDUMP_PID"
```

Generate beacon traffic:

```bash
# 🚀 Launch beacon simulator in background
python3 beacon_generator.py &
BEACON_PID=$!

# ⏳ Let it run for 5 minutes
sleep 300

# 🛑 Stop beacon generator and capture
kill $BEACON_PID
sudo kill $TCPDUMP_PID
```

---

## 🤖 Task 2: Use AI for Feature Extraction and Enhancement

### 🧠 Subtask 2.1: Install Python AI Libraries

Install required Python packages:

```bash
# 📦 Install ML and packet-parsing libraries
pip3 install pandas numpy scikit-learn matplotlib seaborn pyshark
```

### 🧬 Subtask 2.2: Create AI Feature Extraction Script

Create an AI-powered traffic analysis script:

```python
#!/usr/bin/env python3
# 🤖 ai_feature_extractor.py — ML-based beacon feature extraction & scoring
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
        # 🌲 Isolation Forest flags statistically anomalous connections
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)

    def extract_features_from_pcap(self, pcap_file):
        """Extract network features from PCAP file"""
        print("Extracting features from PCAP...")  # 🔍 status update

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
            print(f"Error processing PCAP: {e}")  # ⚠️ capture parse failure
            return {}

    def calculate_beacon_features(self, connections):
        """Calculate beaconing features for each connection"""
        features = []

        for conn_key, conn_data in connections.items():
            if len(conn_data['timestamps']) < 5:  # ⛔ need minimum connections
                continue

            timestamps = sorted(conn_data['timestamps'])
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            packet_sizes = conn_data['packet_sizes']

            if not intervals:
                continue

            # 📊 Calculate statistical features
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

            # 🎯 Score connections with low jitter and high packet count as likely beacons
            if feature_vector['std_interval'] < 10 and feature_vector['total_packets'] > 10:
                feature_vector['beacon_score'] = min(feature_vector['regularity_score'] * 100, 100)

            features.append(feature_vector)

        return features

    def detect_anomalies(self, features):
        """Use AI to detect anomalous beaconing patterns"""
        if not features:
            return []

        df = pd.DataFrame(features)

        # 🧮 Select numerical features for ML
        ml_features = ['total_packets', 'avg_interval', 'std_interval',
                      'interval_variance', 'avg_packet_size', 'regularity_score']

        X = df[ml_features].fillna(0)
        X_scaled = self.scaler.fit_transform(X)

        # 🚨 Detect anomalies using Isolation Forest
        anomaly_labels = self.isolation_forest.fit_predict(X_scaled)
        df['anomaly'] = anomaly_labels

        # 🧩 Use DBSCAN for clustering similar beacon patterns
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

        # 📈 Summary statistics
        total_connections = len(analyzed_data)
        potential_beacons = len(analyzed_data[analyzed_data['beacon_score'] > 50])
        anomalies = len(analyzed_data[analyzed_data['anomaly'] == -1])

        print(f"Total Connections Analyzed: {total_connections}")
        print(f"Potential Beacons Detected: {potential_beacons}")
        print(f"Anomalous Patterns: {anomalies}")
        print(f"Unique Clusters Found: {len(set(analyzed_data['cluster'])) - (1 if -1 in analyzed_data['cluster'].values else 0)}")

        # 🏆 Top beacon candidates
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

        # 💾 Save detailed results
        analyzed_data.to_csv('beacon_analysis_results.csv', index=False)
        print("Detailed results saved to: beacon_analysis_results.csv")

def main():
    detector = BeaconDetector()

    # 📼 Extract features from captured traffic
    connections = detector.extract_features_from_pcap('network_traffic.pcap')

    if not connections:
        print("No connections found in PCAP file")
        return

    # 📊 Calculate beacon features
    features = detector.calculate_beacon_features(connections)

    if not features:
        print("No features extracted")
        return

    # 🤖 Apply AI analysis
    analyzed_data = detector.detect_anomalies(features)

    # 📝 Generate report
    detector.generate_report(analyzed_data)

if __name__ == "__main__":
    main()

# TODO: Tune IsolationForest contamination and DBSCAN eps for your traffic volume
```

```bash
# 🔑 Make script executable
chmod +x ai_feature_extractor.py
```

### ▶️ Subtask 2.3: Run AI Feature Extraction

Execute the AI-powered analysis:

```bash
# 🚀 Run feature extraction and anomaly scoring
python3 ai_feature_extractor.py
```

---

## 🔍 Task 3: Analyze Network Traffic for C2 Communication

### 🦉 Subtask 3.1: Convert PCAP to Zeek Logs

Install Zeek for log generation:

```bash
# 📥 Install Zeek network security monitor
sudo apt install -y zeek
```

Convert PCAP to Zeek logs:

```bash
# 🔄 Parse pcap into Zeek log format
zeek -r network_traffic.pcap
ls -la *.log
```

### 📥 Subtask 3.2: Import Data into RITA

Import Zeek logs into RITA:

```bash
# 📤 Import Zeek logs into RITA dataset
rita import . beacon_analysis_db
```

### 🧪 Subtask 3.3: Run RITA Analysis

Execute RITA analysis:

```bash
# ⚙️ Analyze imported dataset
rita analyze beacon_analysis_db
```

Generate beacon report:

```bash
# 📡 Display detected beacon candidates
rita show-beacons beacon_analysis_db
```

### 🔗 Subtask 3.4: Create Comprehensive Analysis Script

Create a script that combines RITA and AI results:

```python
#!/usr/bin/env python3
# 🔗 comprehensive_analysis.py — correlates RITA + AI findings
import subprocess
import json
import pandas as pd
from datetime import datetime

def run_rita_analysis():
    """Run RITA beacon analysis and capture results"""
    print("Running RITA beacon analysis...")  # ⚙️ status update

    try:
        result = subprocess.run(['rita', 'show-beacons', 'beacon_analysis_db', '--human-readable'],
                              capture_output=True, text=True)

        if result.returncode == 0:
            print("RITA Analysis Results:")
            print("-" * 40)
            print(result.stdout)
            return result.stdout
        else:
            print(f"RITA error: {result.stderr}")  # ⚠️ RITA failure
            return None
    except Exception as e:
        print(f"Error running RITA: {e}")
        return None

def correlate_results():
    """Correlate RITA and AI analysis results"""
    print("\nCORRELATING RITA AND AI RESULTS:")
    print("=" * 50)

    # 📂 Load AI results if available
    try:
        ai_results = pd.read_csv('beacon_analysis_results.csv')
        print(f"AI Analysis found {len(ai_results)} connections")

        high_confidence_beacons = ai_results[ai_results['beacon_score'] > 70]
        print(f"High confidence beacons: {len(high_confidence_beacons)}")

        for idx, beacon in high_confidence_beacons.iterrows():
            print(f"  {beacon['connection']} - Score: {beacon['beacon_score']:.2f}")

    except FileNotFoundError:
        print("AI results not found. Run ai_feature_extractor.py first.")  # ⚠️ missing dependency

    # 🧪 Run RITA analysis
    rita_output = run_rita_analysis()

    return rita_output

def generate_final_report():
    """Generate final comprehensive report"""
    print("\n" + "="*60)
    print("COMPREHENSIVE C2 BEACON DETECTION REPORT")
    print("="*60)
    print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    correlate_results()

    print("\nRECOMMENDATIONS:")
    print("-" * 20)
    print("1. Investigate high-scoring beacon connections")
    print("2. Check destination IPs against threat intelligence")
    print("3. Monitor identified patterns for persistence")
    print("4. Implement network segmentation for suspicious hosts")
    print("5. Set up continuous monitoring for detected patterns")

if __name__ == "__main__":
    generate_final_report()

# TODO: Export correlated high-confidence beacons to your SIEM or ticketing system
```

```bash
# 🔑 Make script executable
chmod +x comprehensive_analysis.py
```

### ▶️ Subtask 3.5: Run Comprehensive Analysis

Execute the final analysis:

```bash
# 🚀 Run correlated RITA + AI report
python3 comprehensive_analysis.py
```

### ✔️ Subtask 3.6: Verify Results

Check all generated files:

```bash
# 📂 List generated analysis artifacts
echo "Generated Analysis Files:"
ls -la *.csv *.log *.pcap

echo ""
echo "RITA Database Status:"
rita list
```

---

## 🧪 Verification and Testing

Verify your beacon detection setup:

```bash
# ✅ Check RITA installation
rita --version

# ✅ Verify MongoDB connection
mongo --eval "db.stats()"

# ✅ Check Python dependencies
python3 -c "import pandas, sklearn, pyshark; print('All Python dependencies installed')"

# ✅ Verify analysis results
if [ -f "beacon_analysis_results.csv" ]; then
    echo "AI analysis completed successfully"
    wc -l beacon_analysis_results.csv
else
    echo "AI analysis file not found"
fi
```

---

## 🎯 MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Detection Focus in This Lab |
|---|---|---|---|
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | Command and Control | HTTP-based beacon traffic to external endpoints |
| [T1090](https://attack.mitre.org/techniques/T1090/) | Proxy | Command and Control | Regular outbound connections that may traverse redirectors |
| [T1568](https://attack.mitre.org/techniques/T1568/) | Dynamic Resolution | Command and Control | Detecting rotating or dynamic C2 destinations |
| [T1571](https://attack.mitre.org/techniques/T1571/) | Non-Standard Port | Command and Control | Beacon connections on unexpected destination ports |
| [T1029](https://attack.mitre.org/techniques/T1029/) | Scheduled Transfer | Exfiltration | Fixed-interval timing patterns identified via regularity scoring |

---

## 🐛 Troubleshooting

<details>
<summary><strong>🔴 MongoDB Connection Error</strong></summary>

Ensure MongoDB is running:

```bash
sudo systemctl status mongodb
```

</details>

<details>
<summary><strong>🔴 PCAP Processing Error</strong></summary>

Check file permissions and ensure tcpdump actually captured data:

```bash
ls -la network_traffic.pcap
file network_traffic.pcap
```

</details>

<details>
<summary><strong>🔴 Python Import Errors</strong></summary>

Reinstall the affected package:

```bash
pip3 install --upgrade package_name
```

</details>

<details>
<summary><strong>🔴 RITA Import Failure</strong></summary>

Verify Zeek logs are properly formatted and present in the working directory:

```bash
ls -la *.log
zeek -r network_traffic.pcap
```

</details>

---

## 🏁 Conclusion

You have successfully implemented an advanced beacon detection system combining RITA's network analysis capabilities with AI-powered feature extraction.

### 🌟 Key Accomplishments

- ✅ Configured RITA for automated beacon detection in network traffic
- ✅ Implemented machine learning algorithms for enhanced pattern recognition
- ✅ Correlated multiple analysis techniques for comprehensive threat detection
- ✅ Generated actionable intelligence reports for security operations

### 🌍 Real-World Applications

This integrated approach provides security analysts with powerful tools to identify sophisticated command and control communications that might evade traditional detection methods. The combination of statistical analysis, machine learning, and network behavior analysis creates a robust defense against advanced persistent threats — enabling SOC teams to prioritize investigation of the connections most likely to represent active C2 channels.

---

<div align="center">

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cybersecurity%20Training-1E3A8A?style=for-the-badge&logo=readthedocs&logoColor=white)

</div>
