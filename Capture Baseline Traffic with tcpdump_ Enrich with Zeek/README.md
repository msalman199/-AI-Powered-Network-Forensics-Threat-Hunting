<div align="center">

# 🌐 Capture Baseline Traffic with tcpdump, Enrich with Zeek

### Blue Team / DFIR Lab — Network Traffic Analysis Track

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![tcpdump](https://img.shields.io/badge/tcpdump-Packet%20Capture-blue?style=for-the-badge&logo=wireshark&logoColor=white)
![Zeek](https://img.shields.io/badge/Zeek-Network%20Security%20Monitor-00A98F?style=for-the-badge&logo=zerotier&logoColor=white)
![TCP/IP](https://img.shields.io/badge/TCP%2FIP-Networking-orange?style=for-the-badge&logo=cisco&logoColor=white)
![DNS](https://img.shields.io/badge/DNS-Analysis-9cf?style=for-the-badge&logo=internetarchive&logoColor=white)
![HTTP](https://img.shields.io/badge/HTTP-Traffic%20Inspection-red?style=for-the-badge&logo=http&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Beginner--Intermediate-yellow?style=for-the-badge)
![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cybersecurity%20Labs-6C63FF?style=for-the-badge&logo=readthedocs&logoColor=white)

</div>

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [🧰 Technology Stack](#-technology-stack)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [⚙️ Task 1: Install and Configure Required Tools](#️-task-1-install-and-configure-required-tools)
- [📡 Task 2: Capture Network Traffic with tcpdump](#-task-2-capture-network-traffic-with-tcpdump)
- [🔍 Task 3: Analyze Traffic with Zeek](#-task-3-analyze-traffic-with-zeek)
- [📊 Task 4: Analyze Baseline Traffic Patterns](#-task-4-analyze-baseline-traffic-patterns)
- [📝 Task 5: Document Baseline Findings](#-task-5-document-baseline-findings)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [✅ Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Install and configure `tcpdump` for network traffic capture |
| 2 | Deploy `Zeek` for advanced network traffic analysis |
| 3 | Capture baseline network traffic using both tools |
| 4 | Analyze captured data to establish network behavior patterns |
| 5 | Compare raw packet data with enriched Zeek logs |

---

## 🧰 Technology Stack

<div align="center">

| Tool | Purpose | Badge |
|------|---------|-------|
| **Linux (Ubuntu 20.04)** | Base lab operating system | ![Linux](https://img.shields.io/badge/OS-Linux-FCC624?logo=linux&logoColor=black) |
| **tcpdump** | Raw packet capture (CLI sniffer) | ![tcpdump](https://img.shields.io/badge/tool-tcpdump-blue) |
| **Zeek** | Network security monitor / log enrichment | ![Zeek](https://img.shields.io/badge/tool-Zeek-00A98F) |
| **Bash** | Automation & analysis scripting | ![Bash](https://img.shields.io/badge/scripting-Bash-4EAA25?logo=gnubash&logoColor=white) |
| **DNS/HTTP Protocols** | Traffic types analyzed | ![Protocols](https://img.shields.io/badge/protocols-DNS%20%7C%20HTTP%20%7C%20TCP%2FIP-orange) |

</div>

---

## 📋 Prerequisites

| Requirement | Details |
|--------------|---------|
| 🐧 Linux CLI Knowledge | Comfortable navigating and executing basic Linux commands |
| 🌐 Networking Fundamentals | Understanding of TCP/IP, HTTP, and DNS |
| 📄 Log Analysis Familiarity | Ability to read and interpret structured log output |
| 🔑 Root/Sudo Access | Required for packet capture on the network interface |

---

## 🖥️ Lab Environment

> Al Nafi provides Linux-based cloud machines for this lab. Simply click **Start Lab** to access your dedicated environment. The provided Linux machine is bare metal with no pre-installed tools — you will install all required software during the lab exercises.

---

## ⚙️ Task 1: Install and Configure Required Tools

### 🔹 Subtask 1.1: Update System and Install tcpdump

```bash
# 📦 Update package repositories
sudo apt update

# 📥 Install tcpdump
sudo apt install -y tcpdump

# ✅ Verify installation
tcpdump --version
```

### 🔹 Subtask 1.2: Install Zeek

```bash
# 📦 Install dependencies
sudo apt install -y curl gnupg2 software-properties-common

# ➕ Add Zeek repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list

# 🔑 Add repository key
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

# 🔄 Update and install Zeek
sudo apt update
sudo apt install -y zeek

# 🛣️ Add Zeek to PATH
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# ✅ Verify installation
/opt/zeek/bin/zeek --version
```

### 🔹 Subtask 1.3: Create Working Directory

```bash
# 📁 Create lab directory
mkdir ~/network_baseline_lab
cd ~/network_baseline_lab

# 🗂️ Create subdirectories for organization
mkdir tcpdump_captures zeek_logs analysis
```

---

## 📡 Task 2: Capture Network Traffic with tcpdump

### 🔹 Subtask 2.1: Identify Network Interface

```bash
# 🌐 List available network interfaces
ip link show

# 🔎 Check interface with active connection
ip route | grep default
```

### 🔹 Subtask 2.2: Start tcpdump Capture

```bash
# ▶️ Start tcpdump capture (replace eth0 with your interface)
sudo tcpdump -i eth0 -w ~/network_baseline_lab/tcpdump_captures/baseline_traffic.pcap -s 65535 &

# 🆔 Note the process ID for later termination
TCPDUMP_PID=$!
echo "tcpdump PID: $TCPDUMP_PID"
```

### 🔹 Subtask 2.3: Generate Network Activity

```bash
# 🚦 Generate various types of network traffic for baseline
ping -c 5 google.com
curl -s http://httpbin.org/get > /dev/null
nslookup github.com
wget -q -O /dev/null http://httpbin.org/json

# ⏳ Let capture run for 2 minutes
sleep 120
```

### 🔹 Subtask 2.4: Stop tcpdump Capture

```bash
# ⏹️ Stop tcpdump process
sudo kill $TCPDUMP_PID

# ✅ Verify capture file
ls -lh ~/network_baseline_lab/tcpdump_captures/
```

---

## 🔍 Task 3: Analyze Traffic with Zeek

### 🔹 Subtask 3.1: Process Capture with Zeek

```bash
# 📂 Navigate to Zeek logs directory
cd ~/network_baseline_lab/zeek_logs

# ⚡ Process the pcap file with Zeek
/opt/zeek/bin/zeek -r ../tcpdump_captures/baseline_traffic.pcap

# 📄 List generated log files
ls -la *.log
```

### 🔹 Subtask 3.2: Examine Zeek Log Files

```bash
# 🔗 View connection summary
head -20 conn.log

# 🌐 Check DNS queries
head -10 dns.log

# 📶 Review HTTP traffic
head -10 http.log

# 📁 Check detected files
head -10 files.log
```

---

## 📊 Task 4: Analyze Baseline Traffic Patterns

### 🔹 Subtask 4.1: Create Analysis Scripts

```bash
# 📂 Navigate to analysis directory
cd ~/network_baseline_lab/analysis

# 📝 Create connection analysis script
cat > analyze_connections.sh << 'EOF'
#!/bin/bash
echo "=== Connection Analysis ==="
echo "Total connections:"
tail -n +9 ../zeek_logs/conn.log | wc -l

echo -e "\nTop destination ports:"
tail -n +9 ../zeek_logs/conn.log | cut -f5 | sort | uniq -c | sort -nr | head -10

echo -e "\nTop protocols:"
tail -n +9 ../zeek_logs/conn.log | cut -f7 | sort | uniq -c | sort -nr
EOF

chmod +x analyze_connections.sh
```

### 🔹 Subtask 4.2: Create DNS Analysis Script

```bash
# 📝 Create DNS analysis script
cat > analyze_dns.sh << 'EOF'
#!/bin/bash
echo "=== DNS Analysis ==="
echo "Total DNS queries:"
tail -n +9 ../zeek_logs/dns.log | wc -l

echo -e "\nTop queried domains:"
tail -n +9 ../zeek_logs/dns.log | cut -f10 | sort | uniq -c | sort -nr | head -10

echo -e "\nQuery types:"
tail -n +9 ../zeek_logs/dns.log | cut -f14 | sort | uniq -c | sort -nr
EOF

chmod +x analyze_dns.sh
```

### 🔹 Subtask 4.3: Run Analysis Scripts

```bash
# ▶️ Execute connection analysis
./analyze_connections.sh

echo -e "\n" | tee -a baseline_report.txt
./analyze_connections.sh >> baseline_report.txt

# ▶️ Execute DNS analysis
./analyze_dns.sh

echo -e "\n" | tee -a baseline_report.txt
./analyze_dns.sh >> baseline_report.txt
```

### 🔹 Subtask 4.4: Compare Raw vs Enriched Data

```bash
# 📦 View raw packet count from tcpdump
echo "=== Raw Packet Analysis ==="
tcpdump -r ../tcpdump_captures/baseline_traffic.pcap | wc -l

# 🆚 Create comparison summary
cat > comparison_summary.sh << 'EOF'
#!/bin/bash
echo "=== Baseline Traffic Summary ==="
echo "Capture file size: $(ls -lh ../tcpdump_captures/baseline_traffic.pcap | awk '{print $5}')"
echo "Raw packets captured: $(tcpdump -r ../tcpdump_captures/baseline_traffic.pcap 2>/dev/null | wc -l)"
echo "Zeek connections logged: $(tail -n +9 ../zeek_logs/conn.log | wc -l)"
echo "DNS queries detected: $(tail -n +9 ../zeek_logs/dns.log | wc -l)"
echo "HTTP sessions found: $(tail -n +9 ../zeek_logs/http.log | wc -l)"
EOF

chmod +x comparison_summary.sh
./comparison_summary.sh
```

---

## 📝 Task 5: Document Baseline Findings

### 🔹 Subtask 5.1: Create Comprehensive Report

```bash
# 📄 Generate final baseline report
cat > final_baseline_report.txt << 'EOF'
NETWORK BASELINE ANALYSIS REPORT
================================
Generated: $(date)

METHODOLOGY:
- Captured 2 minutes of network traffic using tcpdump
- Processed raw packets through Zeek for protocol analysis
- Analyzed connection patterns, DNS queries, and HTTP traffic

FINDINGS:
EOF

# ➕ Append analysis results
echo -e "\n" >> final_baseline_report.txt
./comparison_summary.sh >> final_baseline_report.txt
echo -e "\n" >> final_baseline_report.txt
./analyze_connections.sh >> final_baseline_report.txt
echo -e "\n" >> final_baseline_report.txt
./analyze_dns.sh >> final_baseline_report.txt

# 👀 Display final report
cat final_baseline_report.txt
```

### 🔹 Subtask 5.2: Verify Data Integrity

```bash
# 🧪 Check file integrity and completeness
echo "=== Data Verification ==="
echo "tcpdump capture file:"
file ../tcpdump_captures/baseline_traffic.pcap

echo -e "\nZeek log files generated:"
ls -la ../zeek_logs/*.log | wc -l

echo -e "\nLog file sizes:"
du -sh ../zeek_logs/*.log
```

> 💡 **TODO:** Attach a screenshot of your `final_baseline_report.txt` output here as evidence of lab completion.

---

## 🗺️ MITRE ATT&CK Mapping

This lab builds foundational network visibility used to **detect** the following adversary techniques in later labs:

| Technique ID | Technique Name | Tactic | How This Lab Enables Detection |
|--------------|-----------------|--------|----------------------------------|
| T1046 | Network Service Discovery | Discovery | Zeek `conn.log` reveals scanning/enumeration patterns via connection volume and port spread |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | `http.log` surfaces anomalous HTTP sessions and user-agent/host patterns |
| T1071.004 | Application Layer Protocol: DNS | Command and Control | `dns.log` exposes suspicious query volume, entropy, and domain patterns (DNS tunneling indicators) |
| T1590 | Gather Victim Network Information | Reconnaissance | Baseline traffic capture establishes a "normal" reference to detect future reconnaissance activity |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Comparing raw pcap volume vs. Zeek-logged sessions helps flag data volume anomalies |

> 🧭 **Data Source Reference:** `DS0029 – Network Traffic` (MITRE ATT&CK)

---

## 🛠️ Troubleshooting

<details>
<summary>🔐 <strong>Permission Issues</strong></summary>

Ensure you run `tcpdump` with `sudo` privileges for network interface access.
</details>

<details>
<summary>🌐 <strong>Interface Not Found</strong></summary>

Use `ip link show` to identify the correct network interface name before starting the capture.
</details>

<details>
<summary>🛣️ <strong>Zeek Path Issues</strong></summary>

Verify the Zeek installation path with `which zeek`, or invoke it directly using the full path: `/opt/zeek/bin/zeek`.
</details>

<details>
<summary>📭 <strong>Empty Log Files</strong></summary>

Ensure network traffic was actively generated during the capture period and confirm the `.pcap` file contains data before processing it with Zeek.
</details>

---

## ✅ Conclusion

You have successfully established a network baseline using **tcpdump** for raw packet capture and **Zeek** for enriched traffic analysis. This baseline data provides essential insights into normal network behavior patterns, including connection frequencies, protocol usage, DNS query patterns, and HTTP traffic characteristics.

### 🏆 Key Accomplishments

- ⚙️ Installed and configured `tcpdump` and `Zeek` on a bare-metal Linux environment
- 📡 Captured live network traffic and generated a baseline `.pcap` dataset
- 🔍 Enriched raw packet data into structured, analyzable Zeek logs
- 📊 Built reusable Bash scripts for connection and DNS pattern analysis
- 📝 Produced a documented baseline report comparing raw vs. enriched telemetry

### 🌍 Real-World Applications

- Establishing a **normal traffic baseline** is foundational to any SOC's anomaly detection strategy
- Zeek-enriched logs feed directly into **SIEM platforms** (e.g., Elastic Stack, Splunk) for correlation and alerting
- Baseline comparisons help analysts spot **beaconing, tunneling, and exfiltration** attempts during incident response
- This workflow mirrors real DFIR practice: raw capture → protocol enrichment → pattern analysis → documentation

---

<div align="center">

### 🎓 Al Nafi Cybersecurity Labs
**Blue Team / DFIR Track — Network Traffic Analysis**

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Empowering%20Cyber%20Talent-6C63FF?style=for-the-badge)

*Building the next generation of security analysts, one lab at a time.*

</div>
