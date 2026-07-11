<div align="center">

# 🕵️ Deploy OSINT-Powered IOC Enrichment with MISP + LangChain

### Blue Team / Threat Intelligence Track — Automated IOC Enrichment & Detection Engineering

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MISP](https://img.shields.io/badge/MISP-Threat%20Intel%20Platform-0093DD?style=for-the-badge&logo=misp&logoColor=white)
![LangChain](https://img.shields.io/badge/LangChain-AI%20Orchestration-1C3C3C?style=for-the-badge&logo=chainlink&logoColor=white)
![MariaDB](https://img.shields.io/badge/MariaDB-Database-003545?style=for-the-badge&logo=mariadb&logoColor=white)
![Apache](https://img.shields.io/badge/Apache-Web%20Server-D22128?style=for-the-badge&logo=apache&logoColor=white)
![OSINT](https://img.shields.io/badge/OSINT-Enrichment-9cf?style=for-the-badge&logo=internetarchive&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate--Advanced-yellow?style=for-the-badge)
![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cybersecurity%20Labs-6C63FF?style=for-the-badge&logo=readthedocs&logoColor=white)

</div>

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [🧰 Technology Stack](#-technology-stack)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [⚙️ Task 1: Set up MISP for IOC Ingestion](#️-task-1-set-up-misp-for-ioc-ingestion)
- [🧠 Task 2: Use LangChain for Enhanced IOC Enrichment](#-task-2-use-langchain-for-enhanced-ioc-enrichment)
- [📊 Task 3: Analyze Enriched Data for New Detection Opportunities](#-task-3-analyze-enriched-data-for-new-detection-opportunities)
- [✅ Verification and Testing](#-verification-and-testing)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Install and configure MISP for IOC management |
| 2 | Integrate LangChain for automated OSINT enrichment |
| 3 | Analyze enriched IOC data to identify new detection opportunities |
| 4 | Build automated workflows for threat intelligence processing |

---

## 🧰 Technology Stack

<div align="center">

| Tool / Library | Purpose | Badge |
|-----------------|---------|-------|
| **Linux (Ubuntu)** | Base lab operating system | ![Linux](https://img.shields.io/badge/OS-Linux-FCC624?logo=linux&logoColor=black) |
| **MISP** | Threat intelligence platform for IOC management | ![MISP](https://img.shields.io/badge/platform-MISP-0093DD) |
| **MariaDB** | Backing database for MISP | ![MariaDB](https://img.shields.io/badge/db-MariaDB-003545?logo=mariadb&logoColor=white) |
| **Apache2** | Web server hosting the MISP interface | ![Apache](https://img.shields.io/badge/server-Apache-D22128?logo=apache&logoColor=white) |
| **PHP** | MISP application runtime | ![PHP](https://img.shields.io/badge/lang-PHP-777BB4?logo=php&logoColor=white) |
| **Python 3** | Enrichment & analysis scripting | ![Python](https://img.shields.io/badge/lang-Python%203-3776AB?logo=python&logoColor=white) |
| **LangChain** | LLM-orchestrated IOC analysis | ![LangChain](https://img.shields.io/badge/AI-LangChain-1C3C3C) |
| **Requests / BeautifulSoup4** | OSINT data retrieval & parsing | ![Requests](https://img.shields.io/badge/lib-Requests%20%7C%20BS4-blue) |
| **Pandas / Matplotlib / Seaborn** | Detection analytics & visualization | ![Pandas](https://img.shields.io/badge/data-Pandas%20%7C%20Viz-150458) |
| **Redis** | MISP background job queue | ![Redis](https://img.shields.io/badge/cache-Redis-DC382D?logo=redis&logoColor=white) |

</div>

---

## 📋 Prerequisites

| Requirement | Details |
|--------------|---------|
| 🐧 Linux CLI Knowledge | Basic understanding of Linux command line |
| 🧩 Threat Intel Concepts | Familiarity with IOCs, TTPs, and threat intelligence fundamentals |
| 🐍 Python Programming | Comfortable reading and running Python scripts |
| 🛡️ Cybersecurity Fundamentals | General knowledge of security operations concepts |

---

## 🖥️ Lab Environment

> Al Nafi provides a Linux-based cloud machine for this lab. Simply click **Start Lab** to access your dedicated environment. The machine comes as bare metal with no pre-installed tools — you'll install all required components during the lab.

---

## ⚙️ Task 1: Set up MISP for IOC Ingestion

### 🔹 Step 1.1: Install System Dependencies

```bash
# 🔄 Update the system and install required packages
sudo apt update && sudo apt upgrade -y
sudo apt install -y apache2 mariadb-server php php-cli php-dev php-json php-mysql php-opcache php-readline php-redis php-xml php-mbstring php-zip git python3 python3-pip redis-server curl wget unzip
```

### 🔹 Step 1.2: Configure MariaDB

```bash
# ▶️ Start and secure MariaDB
sudo systemctl start mariadb
sudo systemctl enable mariadb
sudo mysql_secure_installation
```

```sql
-- 🗄️ Create MISP database
CREATE DATABASE misp;
CREATE USER 'misp'@'localhost' IDENTIFIED BY 'MISPpassword123!';
GRANT ALL PRIVILEGES ON misp.* TO 'misp'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

> ⚠️ **TODO:** Replace `MISPpassword123!` with a strong, unique password before deploying beyond this lab environment.

### 🔹 Step 1.3: Install MISP

```bash
# 📦 Clone and set up MISP
cd /var/www/html
sudo git clone https://github.com/MISP/MISP.git
cd MISP
sudo git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
sudo git submodule update --init --recursive
```

```bash
# 🔐 Set permissions
sudo chown -R www-data:www-data /var/www/html/MISP
sudo chmod -R 755 /var/www/html/MISP
```

### 🔹 Step 1.4: Install PHP Dependencies

```bash
cd /var/www/html/MISP/app
sudo -u www-data php composer.phar install --no-dev
```

### 🔹 Step 1.5: Configure MISP Database

```bash
sudo -u www-data cp /var/www/html/MISP/INSTALL/setup/config.php /var/www/html/MISP/app/Plugin/CakeResque/Config/config.php
```

```bash
# 📥 Import database schema
sudo -u www-data mysql -u misp -p misp < /var/www/html/MISP/INSTALL/MYSQL.sql
```

### 🔹 Step 1.6: Configure Apache

```bash
# 🌐 Create MISP virtual host
sudo tee /etc/apache2/sites-available/misp.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /var/www/html/MISP/app/webroot
    <Directory /var/www/html/MISP/app/webroot>
        Options -Indexes
        AllowOverride all
        Require all granted
    </Directory>
    LogLevel warn
    ErrorLog /var/log/apache2/misp_error.log
    CustomLog /var/log/apache2/misp_access.log combined
</VirtualHost>
EOF
```

```bash
# ✅ Enable site and modules
sudo a2dissite 000-default
sudo a2ensite misp
sudo a2enmod rewrite
sudo systemctl restart apache2
```

### 🔹 Step 1.7: Configure MISP Settings

```bash
# 📄 Copy configuration files
sudo -u www-data cp /var/www/html/MISP/app/Config/bootstrap.default.php /var/www/html/MISP/app/Config/bootstrap.php
sudo -u www-data cp /var/www/html/MISP/app/Config/database.default.php /var/www/html/MISP/app/Config/database.php
sudo -u www-data cp /var/www/html/MISP/app/Config/core.default.php /var/www/html/MISP/app/Config/core.php
sudo -u www-data cp /var/www/html/MISP/app/Config/config.default.php /var/www/html/MISP/app/Config/config.php
```

```bash
# ✏️ Edit database configuration
sudo -u www-data nano /var/www/html/MISP/app/Config/database.php
```

```php
// 🔧 Update the database section
public $default = array(
    'datasource' => 'Database/Mysql',
    'persistent' => false,
    'host' => 'localhost',
    'login' => 'misp',
    'password' => 'MISPpassword123!',
    'database' => 'misp',
    'prefix' => '',
    'encoding' => 'utf8',
);
```

---

## 🧠 Task 2: Use LangChain for Enhanced IOC Enrichment

### 🔹 Step 2.1: Install Python Dependencies

```bash
pip3 install langchain openai requests python-misp beautifulsoup4 pandas numpy
```

### 🔹 Step 2.2: Create IOC Enrichment Script

```bash
nano ioc_enrichment.py
```

```python
# 🐍 ioc_enrichment.py — TODO: wire in real OSINT/threat-intel API keys for production use
#!/usr/bin/env python3
import requests
import json
import time
from langchain.llms import OpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
import re
from bs4 import BeautifulSoup

class IOCEnricher:
    def __init__(self, misp_url="http://localhost", misp_key=""):
        self.misp_url = misp_url
        self.misp_key = misp_key
        self.headers = {
            'Authorization': misp_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def get_iocs_from_misp(self):
        """Retrieve IOCs from MISP"""
        try:
            response = requests.get(f"{self.misp_url}/attributes/restSearch",
                                  headers=self.headers, verify=False)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"Error fetching IOCs: {e}")
            return None

    def osint_lookup(self, ioc_value, ioc_type):
        """Perform OSINT lookup for IOC"""
        enrichment_data = {}

        if ioc_type == "ip-dst":
            enrichment_data.update(self.ip_lookup(ioc_value))
        elif ioc_type == "domain":
            enrichment_data.update(self.domain_lookup(ioc_value))
        elif ioc_type == "md5" or ioc_type == "sha1" or ioc_type == "sha256":
            enrichment_data.update(self.hash_lookup(ioc_value))

        return enrichment_data

    def ip_lookup(self, ip):
        """Lookup IP information"""
        data = {}
        try:
            # 🌍 Using ipinfo.io (free tier)
            response = requests.get(f"http://ipinfo.io/{ip}/json", timeout=10)
            if response.status_code == 200:
                ip_data = response.json()
                data['geolocation'] = {
                    'country': ip_data.get('country', ''),
                    'region': ip_data.get('region', ''),
                    'city': ip_data.get('city', ''),
                    'org': ip_data.get('org', '')
                }
        except Exception as e:
            print(f"IP lookup error: {e}")

        return data

    def domain_lookup(self, domain):
        """Lookup domain information"""
        data = {}
        try:
            # 🔎 Simple DNS resolution check
            import socket
            ip = socket.gethostbyname(domain)
            data['resolved_ip'] = ip
            data['ip_info'] = self.ip_lookup(ip)
        except Exception as e:
            print(f"Domain lookup error: {e}")

        return data

    def hash_lookup(self, hash_value):
        """Lookup hash information"""
        data = {}
        # In a real scenario, you would query VirusTotal, Hybrid Analysis, etc.
        # For this lab, we'll simulate the data
        data['hash_type'] = self.detect_hash_type(hash_value)
        data['simulated_detection'] = "Potentially malicious (simulated)"
        return data

    def detect_hash_type(self, hash_value):
        """Detect hash type based on length"""
        length = len(hash_value)
        if length == 32:
            return "MD5"
        elif length == 40:
            return "SHA1"
        elif length == 64:
            return "SHA256"
        return "Unknown"

    def langchain_analysis(self, ioc_data, enrichment_data):
        """Use LangChain for intelligent analysis"""
        # For this lab, we'll use a simple template without requiring OpenAI API
        analysis_template = """
        Analyze the following IOC and enrichment data:

        IOC Type: {ioc_type}
        IOC Value: {ioc_value}
        Enrichment Data: {enrichment_data}

        Based on this information, provide:
        1. Risk assessment (High/Medium/Low)
        2. Recommended actions
        3. Detection opportunities
        """

        # 🧪 Simulate LangChain analysis without API call
        risk_level = self.assess_risk(ioc_data, enrichment_data)
        recommendations = self.generate_recommendations(ioc_data, enrichment_data)
        detection_opportunities = self.identify_detection_opportunities(ioc_data, enrichment_data)

        return {
            'risk_level': risk_level,
            'recommendations': recommendations,
            'detection_opportunities': detection_opportunities
        }

    def assess_risk(self, ioc_data, enrichment_data):
        """Simple risk assessment logic"""
        risk_factors = 0

        if 'geolocation' in enrichment_data:
            # High-risk countries (example)
            high_risk_countries = ['CN', 'RU', 'KP', 'IR']
            if enrichment_data['geolocation'].get('country') in high_risk_countries:
                risk_factors += 2

        if 'hash_type' in enrichment_data:
            risk_factors += 1

        if risk_factors >= 2:
            return "High"
        elif risk_factors == 1:
            return "Medium"
        else:
            return "Low"

    def generate_recommendations(self, ioc_data, enrichment_data):
        """Generate actionable recommendations"""
        recommendations = []

        if ioc_data.get('type') == 'ip-dst':
            recommendations.append("Block IP at firewall level")
            recommendations.append("Monitor for connections to this IP")

        if ioc_data.get('type') == 'domain':
            recommendations.append("Block domain in DNS filtering")
            recommendations.append("Monitor DNS queries for this domain")

        if 'hash' in ioc_data.get('type', ''):
            recommendations.append("Add hash to endpoint detection rules")
            recommendations.append("Scan systems for this file hash")

        return recommendations

    def identify_detection_opportunities(self, ioc_data, enrichment_data):
        """Identify new detection opportunities"""
        opportunities = []

        if 'geolocation' in enrichment_data:
            country = enrichment_data['geolocation'].get('country')
            opportunities.append(f"Monitor traffic to/from {country}")

        if 'resolved_ip' in enrichment_data:
            opportunities.append(f"Monitor connections to resolved IP: {enrichment_data['resolved_ip']}")

        opportunities.append("Create correlation rules for related IOCs")
        opportunities.append("Implement behavioral detection for similar patterns")

        return opportunities

def main():
    # 🧭 Initialize enricher
    enricher = IOCEnricher()

    # 🧪 Sample IOCs for testing
    sample_iocs = [
        {'type': 'ip-dst', 'value': '8.8.8.8', 'comment': 'Test IP'},
        {'type': 'domain', 'value': 'google.com', 'comment': 'Test domain'},
        {'type': 'md5', 'value': 'd41d8cd98f00b204e9800998ecf8427e', 'comment': 'Test hash'}
    ]

    print("=== IOC Enrichment Analysis ===\n")

    for ioc in sample_iocs:
        print(f"Analyzing IOC: {ioc['value']} ({ioc['type']})")
        print("-" * 50)

        # 🌐 Perform OSINT lookup
        enrichment_data = enricher.osint_lookup(ioc['value'], ioc['type'])
        print(f"Enrichment Data: {json.dumps(enrichment_data, indent=2)}")

        # 🧠 Perform LangChain analysis
        analysis = enricher.langchain_analysis(ioc, enrichment_data)
        print(f"Risk Level: {analysis['risk_level']}")
        print(f"Recommendations: {analysis['recommendations']}")
        print(f"Detection Opportunities: {analysis['detection_opportunities']}")
        print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    main()
```

### 🔹 Step 2.3: Create MISP Integration Script

```bash
nano misp_integration.py
```

```python
# 🐍 misp_integration.py — TODO: replace empty misp_key with your MISP API authorization key
#!/usr/bin/env python3
import requests
import json
import sys

class MISPIntegration:
    def __init__(self, misp_url="http://localhost", misp_key=""):
        self.misp_url = misp_url
        self.misp_key = misp_key
        self.headers = {
            'Authorization': misp_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def create_event(self, event_info):
        """Create a new MISP event"""
        event_data = {
            'Event': {
                'info': event_info,
                'distribution': '1',
                'threat_level_id': '2',
                'analysis': '1'
            }
        }

        try:
            response = requests.post(f"{self.misp_url}/events",
                                   headers=self.headers,
                                   data=json.dumps(event_data),
                                   verify=False)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error creating event: {response.status_code}")
                return None
        except Exception as e:
            print(f"Exception creating event: {e}")
            return None

    def add_attribute(self, event_id, attr_type, attr_value, comment=""):
        """Add attribute to MISP event"""
        attr_data = {
            'Attribute': {
                'type': attr_type,
                'value': attr_value,
                'comment': comment,
                'distribution': '1'
            }
        }

        try:
            response = requests.post(f"{self.misp_url}/attributes/add/{event_id}",
                                   headers=self.headers,
                                   data=json.dumps(attr_data),
                                   verify=False)
            return response.status_code == 200
        except Exception as e:
            print(f"Exception adding attribute: {e}")
            return False

def main():
    # 🧭 Test MISP integration
    misp = MISPIntegration()

    # 📝 Create test event
    event = misp.create_event("OSINT Enrichment Test Event")
    if event:
        event_id = event['Event']['id']
        print(f"Created event with ID: {event_id}")

        # ➕ Add test attributes
        test_attributes = [
            {'type': 'ip-dst', 'value': '192.168.1.100', 'comment': 'Suspicious IP'},
            {'type': 'domain', 'value': 'malicious-domain.com', 'comment': 'C2 Domain'},
            {'type': 'md5', 'value': 'a1b2c3d4e5f6789012345678901234567', 'comment': 'Malware hash'}
        ]

        for attr in test_attributes:
            success = misp.add_attribute(event_id, attr['type'], attr['value'], attr['comment'])
            print(f"Added {attr['type']}: {attr['value']} - {'Success' if success else 'Failed'}")
    else:
        print("Failed to create event")

if __name__ == "__main__":
    main()
```

---

## 📊 Task 3: Analyze Enriched Data for New Detection Opportunities

### 🔹 Step 3.1: Create Analysis Dashboard Script

```bash
nano detection_analysis.py
```

```python
# 🐍 detection_analysis.py — TODO: swap sample_data for a live MISP export before production use
#!/usr/bin/env python3
import json
import pandas as pd
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns

class DetectionAnalyzer:
    def __init__(self):
        self.enriched_data = []

    def load_enriched_data(self, data_file=None):
        """Load enriched IOC data"""
        # 🧪 Sample enriched data for analysis
        sample_data = [
            {
                'ioc_type': 'ip-dst',
                'ioc_value': '192.168.1.100',
                'risk_level': 'High',
                'country': 'CN',
                'detection_opportunities': ['Block at firewall', 'Monitor connections'],
                'enrichment_score': 8.5
            },
            {
                'ioc_type': 'domain',
                'ioc_value': 'malicious-site.com',
                'risk_level': 'Medium',
                'country': 'US',
                'detection_opportunities': ['DNS filtering', 'Web proxy blocking'],
                'enrichment_score': 6.2
            },
            {
                'ioc_type': 'md5',
                'ioc_value': 'a1b2c3d4e5f6',
                'risk_level': 'High',
                'country': 'Unknown',
                'detection_opportunities': ['Endpoint detection', 'File scanning'],
                'enrichment_score': 9.1
            }
        ]

        self.enriched_data = sample_data
        return len(self.enriched_data)

    def analyze_risk_distribution(self):
        """Analyze risk level distribution"""
        risk_levels = [item['risk_level'] for item in self.enriched_data]
        risk_counter = Counter(risk_levels)

        print("=== Risk Level Distribution ===")
        for risk, count in risk_counter.items():
            print(f"{risk}: {count} IOCs")

        return risk_counter

    def analyze_geographic_distribution(self):
        """Analyze geographic distribution of threats"""
        countries = [item['country'] for item in self.enriched_data if item['country'] != 'Unknown']
        country_counter = Counter(countries)

        print("\n=== Geographic Distribution ===")
        for country, count in country_counter.items():
            print(f"{country}: {count} IOCs")

        return country_counter

    def identify_detection_gaps(self):
        """Identify potential detection gaps"""
        all_opportunities = []
        for item in self.enriched_data:
            all_opportunities.extend(item['detection_opportunities'])

        opportunity_counter = Counter(all_opportunities)

        print("\n=== Detection Opportunities ===")
        for opportunity, count in opportunity_counter.items():
            print(f"{opportunity}: {count} IOCs")

        return opportunity_counter

    def generate_detection_rules(self):
        """Generate sample detection rules"""
        rules = []

        for item in self.enriched_data:
            if item['ioc_type'] == 'ip-dst' and item['risk_level'] == 'High':
                rule = f"alert tcp any any -> {item['ioc_value']} any (msg:\"High-risk IP connection\"; sid:1000001;)"
                rules.append(rule)

            elif item['ioc_type'] == 'domain' and item['risk_level'] in ['High', 'Medium']:
                rule = f"alert dns any any -> any any (msg:\"Suspicious domain query\"; query; content:\"{item['ioc_value']}\"; sid:1000002;)"
                rules.append(rule)

        print("\n=== Generated Detection Rules ===")
        for i, rule in enumerate(rules, 1):
            print(f"{i}. {rule}")

        return rules

    def create_threat_intelligence_report(self):
        """Create comprehensive threat intelligence report"""
        report = {
            'summary': {
                'total_iocs': len(self.enriched_data),
                'high_risk_iocs': len([x for x in self.enriched_data if x['risk_level'] == 'High']),
                'average_enrichment_score': sum([x['enrichment_score'] for x in self.enriched_data]) / len(self.enriched_data)
            },
            'recommendations': [
                "Implement automated blocking for high-risk IOCs",
                "Enhance monitoring for medium-risk indicators",
                "Develop correlation rules for geographic clustering",
                "Regular review and update of detection rules"
            ]
        }

        print("\n=== Threat Intelligence Report ===")
        print(f"Total IOCs Analyzed: {report['summary']['total_iocs']}")
        print(f"High-Risk IOCs: {report['summary']['high_risk_iocs']}")
        print(f"Average Enrichment Score: {report['summary']['average_enrichment_score']:.2f}")

        print("\nRecommendations:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"{i}. {rec}")

        return report

def main():
    analyzer = DetectionAnalyzer()

    # 📥 Load and analyze data
    data_count = analyzer.load_enriched_data()
    print(f"Loaded {data_count} enriched IOCs for analysis\n")

    # 📊 Perform various analyses
    analyzer.analyze_risk_distribution()
    analyzer.analyze_geographic_distribution()
    analyzer.identify_detection_gaps()
    analyzer.generate_detection_rules()
    analyzer.create_threat_intelligence_report()

if __name__ == "__main__":
    main()
```

### 🔹 Step 3.2: Run Complete Analysis Pipeline

```bash
nano run_analysis.py
```

```python
# 🐍 run_analysis.py — orchestrates the full enrichment → integration → analysis pipeline
#!/usr/bin/env python3
import subprocess
import sys
import time

def run_script(script_name, description):
    """Run a Python script and handle errors"""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"{'='*60}")

    try:
        result = subprocess.run([sys.executable, script_name],
                              capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            print(result.stdout)
            print(f"✓ {description} completed successfully")
        else:
            print(f"✗ Error in {description}:")
            print(result.stderr)

    except subprocess.TimeoutExpired:
        print(f"✗ {description} timed out")
    except Exception as e:
        print(f"✗ Exception in {description}: {e}")

def main():
    print("OSINT-Powered IOC Enrichment Analysis Pipeline")
    print("=" * 60)

    # ▶️ Run analysis scripts in sequence
    scripts = [
        ("ioc_enrichment.py", "IOC Enrichment with OSINT"),
        ("misp_integration.py", "MISP Integration Test"),
        ("detection_analysis.py", "Detection Opportunity Analysis")
    ]

    for script, description in scripts:
        run_script(script, description)
        time.sleep(2)  # Brief pause between scripts

    print(f"\n{'='*60}")
    print("Analysis Pipeline Complete!")
    print("Review the output above for enrichment results and detection opportunities.")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
```

### 🔹 Step 3.3: Execute the Complete Analysis

```bash
# 🔐 Make scripts executable and run the analysis
chmod +x *.py
python3 run_analysis.py
```

### 🔹 Step 3.4: Verify MISP Installation

```bash
# 🔎 Check if MISP is accessible
curl -I http://localhost
systemctl status apache2
systemctl status mariadb
```

> 🌐 **Access MISP web interface (if available):**
> - URL: `http://localhost`
> - Default credentials: `admin@admin.test` / `admin`
>
> ⚠️ **TODO:** Change the default MISP admin credentials immediately after first login.

---

## ✅ Verification and Testing

### 🔹 Test IOC Enrichment

```bash
# 🧪 Run individual components to verify functionality
python3 ioc_enrichment.py

# 🧪 Test detection analysis
python3 detection_analysis.py
```

### 🔹 Validate Results

Check that the scripts produce:

- ✅ Risk assessments for each IOC type
- ✅ Geographic analysis of threat sources
- ✅ Detection rule generation based on enrichment
- ✅ Actionable recommendations for security teams

> 💡 **TODO:** Attach a screenshot of your `run_analysis.py` output and the MISP web UI as evidence of lab completion.

---

## 🗺️ MITRE ATT&CK Mapping

This lab enriches IOCs (IPs, domains, hashes) that correspond to observable artifacts of the following techniques:

| Technique ID | Technique Name | Tactic | How Enrichment Supports Detection |
|--------------|-----------------|--------|--------------------------------------|
| T1071.001/.004 | Application Layer Protocol: Web/DNS | Command and Control | `ip-dst`/`domain` enrichment reveals C2 infrastructure geolocation and hosting patterns |
| T1583 | Acquire Infrastructure | Resource Development | Geographic and WHOIS-style enrichment helps attribute attacker-controlled infrastructure |
| T1105 | Ingress Tool Transfer | Command and Control | Hash enrichment (`md5`/`sha1`/`sha256`) supports identifying transferred malicious files |
| T1590 | Gather Victim Network Information | Reconnaissance | MISP event sharing builds organizational awareness of targeting patterns |
| T1204 | User Execution | Execution | Correlated hash + domain IOCs help flag delivery vectors for malicious payloads |

> 🧭 **Platform Note:** MISP's structured IOC sharing (events/attributes) operationalizes `DS0022 – File`, `DS0029 – Network Traffic`, and `DS0035 – Internet Scan` data sources referenced across ATT&CK detections.

---

## 🛠️ Troubleshooting

<details>
<summary>🗄️ <strong>MariaDB Connection Errors</strong></summary>

If MISP can't connect to the database, verify `mysql_secure_installation` completed successfully and that the credentials in `database.php` exactly match the `misp` user created in Step 1.2.
</details>

<details>
<summary>🌐 <strong>MISP Web Interface Not Loading</strong></summary>

Run `systemctl status apache2` to confirm Apache is active, and check `/var/log/apache2/misp_error.log` for permission or configuration errors. Confirm `a2ensite misp` and `a2enmod rewrite` were both applied.
</details>

<details>
<summary>🔐 <strong>Composer Install Fails</strong></summary>

If `composer.phar install` fails, ensure PHP extensions (`php-mysql`, `php-xml`, `php-mbstring`, `php-zip`) were installed in Step 1.1, since MISP's dependencies require them at build time.
</details>

<details>
<summary>🧠 <strong>LangChain Import Errors</strong></summary>

If `from langchain.llms import OpenAI` fails, confirm `pip3 install langchain openai` succeeded and that you're using a LangChain version compatible with the import paths used in the script — newer LangChain releases may relocate these modules.
</details>

<details>
<summary>🔑 <strong>MISP API Authorization Failures</strong></summary>

`misp_integration.py` uses an empty `misp_key` by default. Generate a real API key from the MISP web UI (User Profile → Auth Keys) and pass it into `MISPIntegration(misp_key="...")` before expecting successful event creation.
</details>

---

## 🏁 Conclusion

You have successfully deployed an **OSINT-powered IOC enrichment system** that combines centralized threat intel management with AI-assisted analysis.

### 🏆 Key Accomplishments

- 🗄️ Integrated MISP for centralized IOC management and sharing
- 🧠 Implemented LangChain for intelligent analysis and enrichment of threat indicators
- 🔄 Created automated workflows that combine multiple OSINT sources for comprehensive threat intelligence
- 📊 Generated actionable detection opportunities based on enriched IOC data
- 📜 Developed detection rules and recommendations for security operations

### 🌍 Real-World Applications

- MISP is a widely deployed **threat intelligence platform** used by SOCs, CERTs, and ISACs to share and correlate IOCs across organizations
- LLM-assisted enrichment reduces manual analyst time spent triaging raw indicators, freeing capacity for deeper investigation
- Geographic and infrastructure-based enrichment supports **attribution and campaign tracking**
- Auto-generated detection rules bridge the gap between raw threat intel and deployable **SIEM/IDS signatures**

The skills learned here are directly applicable to SOC operations, threat hunting, and security architecture roles where automated threat intelligence processing is essential for maintaining effective cybersecurity defenses.

---

<div align="center">

### 🎓 Al Nafi Cybersecurity Labs
**Blue Team / Threat Intelligence Track — Automated IOC Enrichment & Detection Engineering**

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Empowering%20Cyber%20Talent-6C63FF?style=for-the-badge)

*Building the next generation of security analysts, one lab at a time.*

</div>
