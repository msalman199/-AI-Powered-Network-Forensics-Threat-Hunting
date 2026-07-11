import json
import random
from datetime import datetime, timedelta
import uuid

class AlertGenerator:
    def __init__(self):
        self.alert_types = [
            "Malware Detection", "Suspicious Network Activity", 
            "Failed Login Attempts", "Data Exfiltration", 
            "Privilege Escalation", "Phishing Attempt"
        ]
        self.severities = ["Low", "Medium", "High", "Critical"]
        self.sources = ["Firewall", "IDS", "Antivirus", "SIEM", "EDR"]
        
    def generate_alert(self):
        return {
            "id": str(uuid.uuid4()),
            "timestamp": (datetime.now() - timedelta(
                minutes=random.randint(0, 1440))).isoformat(),
            "type": random.choice(self.alert_types),
            "severity": random.choice(self.severities),
            "source": random.choice(self.sources),
            "description": f"Alert detected: {random.choice(self.alert_types)}",
            "source_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
            "destination_ip": f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",
            "affected_systems": random.randint(1, 10),
            "confidence_score": round(random.uniform(0.1, 1.0), 2)
        }
    
    def generate_dataset(self, count=100):
        return [self.generate_alert() for _ in range(count)]

if __name__ == "__main__":
    generator = AlertGenerator()
    alerts = generator.generate_dataset(200)
    
    with open("../data/sample_alerts.json", "w") as f:
        json.dump(alerts, f, indent=2)
    
    print(f"Generated {len(alerts)} sample alerts")
