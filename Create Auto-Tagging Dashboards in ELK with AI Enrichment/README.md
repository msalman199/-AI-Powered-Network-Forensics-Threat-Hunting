<div align="center">

# 🏷️ Create Auto-Tagging Dashboards in ELK with AI Enrichment

![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Logstash](https://img.shields.io/badge/Logstash-Data%20Pipeline-005571?style=for-the-badge&logo=elasticstack&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-Dashboards-005571?style=for-the-badge&logo=kibana&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scikit Learn](https://img.shields.io/badge/Scikit--Learn-Random%20Forest-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![Java](https://img.shields.io/badge/Java-11-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Environment-FCC624?style=for-the-badge&logo=linux&logoColor=black)

**Difficulty:** Intermediate–Advanced | **Category:** Blue Team — Network Security & Machine Learning | **Est. Time:** 120–150 minutes

</div>

---

## 📚 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🧩 Task 1: Set Up ELK Stack for Network Traffic Analysis](#-task-1-set-up-elk-stack-for-network-traffic-analysis)
- [🤖 Task 2: Integrate AI Models for Auto-Tagging](#-task-2-integrate-ai-models-for-auto-tagging)
- [📊 Task 3: Build Real-Time Dashboards in Kibana](#-task-3-build-real-time-dashboards-in-kibana)
- [✅ Verification and Testing](#-verification-and-testing)
- [🛡️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🧯 Troubleshooting](#-troubleshooting)
- [📝 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Deploy and configure the complete ELK stack (Elasticsearch, Logstash, Kibana) for network traffic analysis |
| 2 | Integrate machine learning models for automated traffic classification and tagging |
| 3 | Build real-time dashboards in Kibana with AI-enhanced visualizations |
| 4 | Implement automated anomaly detection for network security monitoring |

## 📋 Prerequisites

| # | Requirement |
|---|-------------|
| 1 | Basic Linux command line knowledge |
| 2 | Understanding of network protocols (TCP/IP, HTTP) |
| 3 | Familiarity with JSON data structures |
| 4 | Basic knowledge of log analysis concepts |

## 🖥️ Lab Environment

> **☁️ Al Nafi Cloud Lab**
> Al Nafi provides a Linux-based cloud machine for this lab. Simply click **Start Lab** to access your dedicated environment. The machine comes as bare metal with no pre-installed tools, so you'll install all required components during the lab.

---

## 🧩 Task 1: Set Up ELK Stack for Network Traffic Analysis

### ☕ Subtask 1.1: Install Java and System Dependencies

```bash
# 🔄 Update system packages
sudo apt update && sudo apt upgrade -y

# ☕ Install Java 11 (required for ELK stack)
sudo apt install openjdk-11-jdk curl wget gnupg2 -y

# ✅ Verify Java installation
java -version
```

### 🔎 Subtask 1.2: Install Elasticsearch

```bash
# 📦 Add Elasticsearch repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# 📥 Install Elasticsearch
sudo apt update
sudo apt install elasticsearch -y

# ⚙️ Configure Elasticsearch for single-node setup
sudo tee /etc/elasticsearch/elasticsearch.yml > /dev/null <<EOF
cluster.name: network-analysis
node.name: node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: localhost
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
EOF

# ▶️ Start and enable Elasticsearch
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# ✅ Verify Elasticsearch is running
sleep 30
curl -X GET "localhost:9200/"

# TODO: Set a real cluster.name if you plan to join additional nodes later
```

### 🔀 Subtask 1.3: Install Logstash

```bash
# 📥 Install Logstash
sudo apt install logstash -y

# 🧩 Create network traffic processing configuration
sudo tee /etc/logstash/conf.d/network-traffic.conf > /dev/null <<'EOF'
input {
  file {
    path => "/var/log/network-traffic.log"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}

filter {
  if [message] =~ /^{/ {
    json {
      source => "message"
    }
  }

  # 🌍 Extract IP geolocation
  if [src_ip] {
    geoip {
      source => "src_ip"
      target => "src_geoip"
    }
  }

  if [dst_ip] {
    geoip {
      source => "dst_ip"
      target => "dst_geoip"
    }
  }

  # ⏱️ Add timestamp
  date {
    match => [ "timestamp", "ISO8601" ]
  }

  # 📏 Calculate traffic volume categories
  if [bytes] {
    if [bytes] < 1024 {
      mutate { add_field => { "traffic_size" => "small" } }
    } else if [bytes] < 1048576 {
      mutate { add_field => { "traffic_size" => "medium" } }
    } else {
      mutate { add_field => { "traffic_size" => "large" } }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "network-traffic-%{+YYYY.MM.dd}"
  }
  stdout { codec => rubydebug }
}
EOF

# ▶️ Start and enable Logstash
sudo systemctl enable logstash
sudo systemctl start logstash

# TODO: Add your own filter stage here for any custom fields you log upstream
```

### 📊 Subtask 1.4: Install Kibana

```bash
# 📥 Install Kibana
sudo apt install kibana -y

# ⚙️ Configure Kibana
sudo tee /etc/kibana/kibana.yml > /dev/null <<EOF
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
EOF

# ▶️ Start and enable Kibana
sudo systemctl enable kibana
sudo systemctl start kibana

# ⏳ Wait for Kibana to start
sleep 60
echo "Kibana should be accessible at http://localhost:5601"
```

---

## 🤖 Task 2: Integrate AI Models for Auto-Tagging

### 🐍 Subtask 2.1: Install Python and ML Dependencies

```bash
# 📥 Install Python and pip
sudo apt install python3 python3-pip python3-venv -y

# 🧪 Create virtual environment for ML components
python3 -m venv ~/ml-env
source ~/ml-env/bin/activate

# 📦 Install required Python packages
pip install scikit-learn pandas numpy requests elasticsearch joblib
```

### 🌲 Subtask 2.2: Create AI Traffic Classification Model

```python
# 🤖 train_traffic_classifier.py — trains a Random Forest to tag traffic types

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
import json

# 🧪 Generate synthetic network traffic data for training
np.random.seed(42)
n_samples = 10000

# 🧬 Create synthetic features
data = {
    'src_port': np.random.randint(1, 65536, n_samples),
    'dst_port': np.random.randint(1, 65536, n_samples),
    'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n_samples),
    'bytes': np.random.exponential(1000, n_samples),
    'packets': np.random.poisson(10, n_samples),
    'duration': np.random.exponential(5, n_samples)
}

df = pd.DataFrame(data)

# 🏷️ Create labels based on port patterns (simplified classification)
def classify_traffic(row):
    if row['dst_port'] in [80, 443, 8080, 8443]:
        return 'web'
    elif row['dst_port'] in [22, 23, 3389]:
        return 'remote_access'
    elif row['dst_port'] in [25, 110, 143, 993, 995]:
        return 'email'
    elif row['dst_port'] in [53]:
        return 'dns'
    elif row['dst_port'] in [21, 22]:
        return 'file_transfer'
    elif row['bytes'] > 10000 and row['packets'] > 100:
        return 'bulk_transfer'
    elif row['packets'] < 5 and row['duration'] < 1:
        return 'scan'
    else:
        return 'other'

df['traffic_type'] = df.apply(classify_traffic, axis=1)

# 🔢 Encode categorical variables
le_protocol = LabelEncoder()
df['protocol_encoded'] = le_protocol.fit_transform(df['protocol'])

# 🎯 Prepare features and target
features = ['src_port', 'dst_port', 'protocol_encoded', 'bytes', 'packets', 'duration']
X = df[features]
y = df['traffic_type']

# ✂️ Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 🌲 Train model
# TODO: Tune n_estimators or swap in GradientBoostingClassifier for higher accuracy
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# 💾 Save model and encoders
joblib.dump(rf_model, 'traffic_classifier.pkl')
joblib.dump(le_protocol, 'protocol_encoder.pkl')

print(f"Model trained with accuracy: {rf_model.score(X_test, y_test):.3f}")
print("Model saved as traffic_classifier.pkl")
```

```bash
# ▶️ Run the training script
source ~/ml-env/bin/activate
python3 ~/train_traffic_classifier.py
```

### 🧠 Subtask 2.3: Create AI Enrichment Service

```python
# 🧠 ai_enrichment_service.py — classifies and flags Elasticsearch documents in near real-time

import json
import time
import joblib
import pandas as pd
from elasticsearch import Elasticsearch
import numpy as np
from datetime import datetime

class TrafficEnrichmentService:
    def __init__(self):
        self.es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
        self.model = joblib.load('traffic_classifier.pkl')
        self.protocol_encoder = joblib.load('protocol_encoder.pkl')

    def classify_traffic(self, traffic_data):
        """🏷️ Classify traffic using trained ML model"""
        try:
            # 🎯 Prepare features
            features = pd.DataFrame([{
                'src_port': traffic_data.get('src_port', 0),
                'dst_port': traffic_data.get('dst_port', 0),
                'protocol_encoded': self.encode_protocol(traffic_data.get('protocol', 'TCP')),
                'bytes': traffic_data.get('bytes', 0),
                'packets': traffic_data.get('packets', 1),
                'duration': traffic_data.get('duration', 1)
            }])

            # 🔮 Predict
            prediction = self.model.predict(features)[0]
            confidence = np.max(self.model.predict_proba(features))

            return {
                'ai_classification': prediction,
                'confidence_score': float(confidence),
                'classification_timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'ai_classification': 'unknown',
                'confidence_score': 0.0,
                'error': str(e)
            }

    def encode_protocol(self, protocol):
        """🔢 Encode protocol string to numeric value"""
        try:
            return self.protocol_encoder.transform([protocol])[0]
        except Exception:
            return 0  # Default for unknown protocols

    def detect_anomalies(self, traffic_data):
        """🚨 Simple anomaly detection based on traffic patterns"""
        anomalies = []

        # 🚪 Check for unusual port combinations
        src_port = traffic_data.get('src_port', 0)
        dst_port = traffic_data.get('dst_port', 0)

        if src_port > 60000 and dst_port < 1024:
            anomalies.append('high_source_port_to_system_port')

        # 📦 Check for unusual traffic volume
        bytes_count = traffic_data.get('bytes', 0)
        if bytes_count > 100000000:  # 100MB
            # TODO: Lower this threshold if your environment expects smaller baseline transfers
            anomalies.append('large_data_transfer')

        # ⚡ Check for rapid connections
        packets = traffic_data.get('packets', 0)
        duration = traffic_data.get('duration', 1)
        if packets > 1000 and duration < 1:
            anomalies.append('rapid_packet_burst')

        return {
            'anomalies_detected': anomalies,
            'anomaly_count': len(anomalies),
            'risk_level': 'high' if len(anomalies) > 1 else 'medium' if len(anomalies) == 1 else 'low'
        }

    def enrich_traffic_data(self, traffic_data):
        """✨ Main enrichment function"""
        enriched_data = traffic_data.copy()

        # 🏷️ Add AI classification
        classification = self.classify_traffic(traffic_data)
        enriched_data.update(classification)

        # 🚨 Add anomaly detection
        anomaly_info = self.detect_anomalies(traffic_data)
        enriched_data.update(anomaly_info)

        # 🗒️ Add processing metadata
        enriched_data['ai_processed'] = True
        enriched_data['processing_timestamp'] = datetime.now().isoformat()

        return enriched_data

# ▶️ Service runner
if __name__ == "__main__":
    service = TrafficEnrichmentService()
    print("AI Enrichment Service started...")

    # 🔁 Monitor for new documents and enrich them
    while True:
        try:
            # 🔍 Query for recent unprocessed documents
            query = {
                "query": {
                    "bool": {
                        "must_not": {
                            "exists": {
                                "field": "ai_processed"
                            }
                        },
                        "filter": {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-1m"
                                }
                            }
                        }
                    }
                },
                "size": 100
            }

            response = service.es.search(index="network-traffic-*", body=query)

            for hit in response['hits']['hits']:
                doc_id = hit['_id']
                index = hit['_index']
                source_data = hit['_source']

                # ✨ Enrich the data
                enriched_data = service.enrich_traffic_data(source_data)

                # 💾 Update document in Elasticsearch
                service.es.update(
                    index=index,
                    id=doc_id,
                    body={"doc": enriched_data}
                )

                print(f"Enriched document {doc_id} with classification: {enriched_data.get('ai_classification')}")

            time.sleep(10)  # Check every 10 seconds

        except Exception as e:
            print(f"Error in enrichment service: {e}")
            time.sleep(30)
```

```bash
# ▶️ Start the AI enrichment service in background
source ~/ml-env/bin/activate
nohup python3 ~/ai_enrichment_service.py > ~/ai_service.log 2>&1 &
echo "AI enrichment service started in background"
```

---

## 📊 Task 3: Build Real-Time Dashboards in Kibana

### 🚦 Subtask 3.1: Generate Sample Network Traffic Data

```python
# 🚦 generate_traffic_data.py — simulates realistic + suspicious network traffic

import json
import random
import time
from datetime import datetime, timedelta
import socket

def generate_traffic_record():
    """🎲 Generate a realistic network traffic record"""
    protocols = ['TCP', 'UDP', 'ICMP']

    # 🚪 Common port mappings for realistic traffic
    common_ports = {
        'web': [80, 443, 8080, 8443],
        'email': [25, 110, 143, 993, 995],
        'dns': [53],
        'ssh': [22],
        'ftp': [21, 22],
        'database': [3306, 5432, 1433, 27017]
    }

    # 🌐 Generate realistic IP addresses
    src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
    dst_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"

    # 🏷️ Select service type and corresponding port
    service_type = random.choice(list(common_ports.keys()))
    dst_port = random.choice(common_ports[service_type])
    src_port = random.randint(1024, 65535)

    protocol = random.choice(protocols)

    # 📊 Generate traffic characteristics based on service type
    if service_type == 'web':
        bytes_count = random.randint(500, 50000)
        packets = random.randint(5, 100)
        duration = random.uniform(0.1, 30.0)
    elif service_type == 'email':
        bytes_count = random.randint(1000, 10000000)
        packets = random.randint(10, 1000)
        duration = random.uniform(1.0, 300.0)
    elif service_type == 'dns':
        bytes_count = random.randint(50, 500)
        packets = random.randint(1, 5)
        duration = random.uniform(0.01, 1.0)
    else:
        bytes_count = random.randint(100, 100000)
        packets = random.randint(1, 500)
        duration = random.uniform(0.1, 60.0)

    # 🚨 Occasionally generate suspicious traffic
    if random.random() < 0.05:  # 5% chance
        # TODO: Increase this ratio if you want a denser sample of anomalies to hunt for
        src_port = random.randint(60000, 65535)
        dst_port = random.randint(1, 1023)
        bytes_count = random.randint(100000, 1000000)
        packets = random.randint(1000, 10000)
        duration = random.uniform(0.01, 0.5)

    record = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "bytes": bytes_count,
        "packets": packets,
        "duration": round(duration, 3),
        "service_type": service_type
    }

    return record

# 🚀 Generate continuous traffic data
print("Starting traffic data generation...")
with open('/var/log/network-traffic.log', 'w') as f:
    for i in range(1000):  # Generate 1000 initial records
        record = generate_traffic_record()
        f.write(json.dumps(record) + '\n')
        if i % 100 == 0:
            print(f"Generated {i} records...")
        time.sleep(0.1)  # Small delay to simulate real-time traffic

print("Initial traffic data generated. Continuing with real-time generation...")

# 🔁 Continue generating data in real-time
while True:
    with open('/var/log/network-traffic.log', 'a') as f:
        record = generate_traffic_record()
        f.write(json.dumps(record) + '\n')
    time.sleep(random.uniform(1, 5))  # Random interval between 1-5 seconds
```

```bash
# 📁 Create log directory and start traffic generation
sudo mkdir -p /var/log
sudo touch /var/log/network-traffic.log
sudo chmod 666 /var/log/network-traffic.log

# ▶️ Start traffic data generation in background
source ~/ml-env/bin/activate
nohup python3 ~/generate_traffic_data.py > ~/traffic_generator.log 2>&1 &
echo "Traffic data generation started"

# ⏳ Wait for some data to be generated
sleep 30
```

### 📈 Subtask 3.2: Create Kibana Index Pattern and Dashboards

```bash
# ⏳ Wait for Kibana to be fully ready
sleep 60

# 🗂️ Create index pattern via Kibana API
curl -X POST "localhost:5601/api/saved_objects/index-pattern/network-traffic-*" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "network-traffic-*",
      "timeFieldName": "@timestamp"
    }
  }'

# 🧩 Create dashboard configuration
cat > ~/dashboard_config.json << 'EOF'
{
  "version": "8.0.0",
  "objects": [
    {
      "id": "traffic-overview-dashboard",
      "type": "dashboard",
      "attributes": {
        "title": "AI-Enhanced Network Traffic Dashboard",
        "description": "Real-time network traffic analysis with AI classification",
        "panelsJSON": "[{\"version\":\"8.0.0\",\"gridData\":{\"x\":0,\"y\":0,\"w\":24,\"h\":15,\"i\":\"1\"},\"panelIndex\":\"1\",\"embeddableConfig\":{},\"panelRefName\":\"panel_1\"}]",
        "timeRestore": false,
        "version": 1
      }
    }
  ]
}
EOF

echo "Dashboard configuration created. Access Kibana at http://localhost:5601"
echo "Navigate to Dashboard section to create visualizations manually."

# TODO: Extend panelsJSON with additional panels once you've built your own visualizations
```

### 🎨 Subtask 3.3: Create Custom Kibana Visualizations

```bash
# 🎨 Create a script to set up basic visualizations
cat > ~/setup_kibana_visualizations.sh << 'EOF'
#!/bin/bash

echo "Setting up Kibana visualizations..."

# ⏳ Wait for Elasticsearch to have data
sleep 30

# 🥧 Create a simple visualization for traffic types
curl -X POST "localhost:5601/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "AI Traffic Classification",
      "visState": "{\"title\":\"AI Traffic Classification\",\"type\":\"pie\",\"params\":{\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"ai_classification.keyword\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\"}}]}",
      "uiStateJSON": "{}",
      "description": "",
      "version": 1,
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"index\":\"network-traffic-*\",\"query\":{\"match_all\":{}}}"
      }
    }
  }'

echo "Basic visualizations created. You can now build more complex dashboards in Kibana UI."
EOF

chmod +x ~/setup_kibana_visualizations.sh
~/setup_kibana_visualizations.sh

# TODO: Add a second visualization (e.g., risk_level over time) once the pie chart is confirmed working
```

---

## ✅ Verification and Testing

### 🔍 Verify ELK Stack Status

```bash
# 🩺 Check all services
echo "=== Service Status ==="
sudo systemctl status elasticsearch --no-pager -l
sudo systemctl status logstash --no-pager -l
sudo systemctl status kibana --no-pager -l

# 📇 Check Elasticsearch indices
echo "=== Elasticsearch Indices ==="
curl -X GET "localhost:9200/_cat/indices?v"

# 📄 Check if data is being processed
echo "=== Sample Data ==="
curl -X GET "localhost:9200/network-traffic-*/_search?size=5&pretty"
```

### 🧠 Test AI Enrichment

```bash
# 📜 Check AI enrichment service log
echo "=== AI Enrichment Service Status ==="
tail -20 ~/ai_service.log

# ✅ Verify AI-enriched documents
curl -X GET "localhost:9200/network-traffic-*/_search?q=ai_processed:true&size=3&pretty"
```

### 🌐 Access Kibana Dashboard

```bash
echo "=== Access Information ==="
echo "Kibana URL: http://localhost:5601"
echo "1. Go to 'Discover' to explore your data"
echo "2. Create index pattern: network-traffic-*"
echo "3. Navigate to 'Dashboard' to build visualizations"
echo "4. Use fields like 'ai_classification', 'anomalies_detected', 'risk_level' for AI insights"
```

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Relevance to This Lab |
|--------|-----------|-----|------------------------|
| Discovery | Network Service Discovery | T1046 | Traffic auto-tagged as `scan` (low packet count, sub-second duration) reflects port/service scanning behavior |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 | The `large_data_transfer` anomaly flag (>100MB) surfaces potential bulk data exfiltration |
| Command and Control | Non-Standard Port | T1571 | The `high_source_port_to_system_port` anomaly highlights connections to system ports from unusual ephemeral source ports |
| Command and Control | Application Layer Protocol | T1071 | AI classification of `web`, `dns`, and `email` traffic types supports baselining normal C2-capable protocols for later deviation detection |
| Exfiltration | Data Transfer Size Limits | T1030 | Correlating `bytes`, `packets`, and `duration` fields helps spot transfers deliberately sized to evade simple thresholds |

---

## 🧯 Troubleshooting

<details>
<summary>🔴 Elasticsearch fails to start</summary>

```bash
# Check Java version and memory
java -version
free -h

# Restart with proper configuration
sudo systemctl restart elasticsearch
sleep 30
curl localhost:9200
```

- Elasticsearch needs sufficient heap memory — on low-RAM lab machines, lower the JVM heap in `/etc/elasticsearch/jvm.options` (e.g., `-Xms1g` / `-Xmx1g`)
- Check `sudo journalctl -u elasticsearch -n 50 --no-pager` for the specific startup error

</details>

<details>
<summary>🔴 No data appears in Kibana</summary>

```bash
# Check Logstash processing
sudo tail -f /var/log/logstash/logstash-plain.log

# Verify log file has data
tail -10 /var/log/network-traffic.log

# Restart Logstash if needed
sudo systemctl restart logstash
```

- Confirm the index pattern `network-traffic-*` matches the actual index name in `curl localhost:9200/_cat/indices?v`
- Make sure `generate_traffic_data.py` is still running: `ps aux | grep generate_traffic_data`

</details>

<details>
<summary>🔴 AI enrichment service crashes or shows "model not found"</summary>

- Confirm `traffic_classifier.pkl` and `protocol_encoder.pkl` exist in the directory where the service was launched — the training script and the service must run from the same working directory
- Re-run `train_traffic_classifier.py` if the `.pkl` files are missing
- Check `~/ai_service.log` for the full stack trace

</details>

<details>
<summary>🔴 AI enrichment service can't connect to Elasticsearch</summary>

- Confirm Elasticsearch is up: `curl localhost:9200`
- Verify the `elasticsearch` Python client version installed matches your ES server's major version — mismatches commonly cause connection or serialization errors
- Check that `xpack.security.enabled: false` is still set if you haven't configured authentication in the client

</details>

<details>
<summary>🔴 Kibana API calls return 401 or 403 errors</summary>

- All saved-object API calls require the `kbn-xsrf: true` header — confirm it's present exactly as shown
- If security was enabled at some point, re-check `xpack.security.enabled` in both `elasticsearch.yml` and `kibana.yml`

</details>

---

## 📝 Conclusion

### 🏆 Key Accomplishments

- **Complete ELK Stack Deployment:** Set up Elasticsearch for data storage, Logstash for data processing, and Kibana for visualization
- **AI Integration:** Implemented machine learning models for automatic traffic classification and anomaly detection
- **Real-time Processing:** Created a continuous data pipeline that processes and enriches network traffic in real-time
- **Interactive Dashboards:** Built Kibana dashboards that display AI-enhanced insights about network behavior

### 🌍 Real-World Applications

This system provides automated security monitoring capabilities that can identify suspicious network patterns, classify traffic types, and detect anomalies without manual intervention. The AI enrichment adds intelligent context to raw network data, making it valuable for cybersecurity professionals, network administrators, and data analysts working in network operations centers. The skills learned here are directly applicable to enterprise security monitoring, threat detection systems, and network performance analysis in production environments.

---

<div align="center">

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cybersecurity%20Training-blueviolet?style=for-the-badge)

</div>
