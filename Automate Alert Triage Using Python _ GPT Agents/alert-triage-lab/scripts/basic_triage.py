import json
import pandas as pd
from datetime import datetime

class BasicTriageEngine:
    def __init__(self):
        self.severity_weights = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1
        }
        
        self.type_priorities = {
            "Malware Detection": 4,
            "Data Exfiltration": 4,
            "Privilege Escalation": 3,
            "Suspicious Network Activity": 2,
            "Failed Login Attempts": 2,
            "Phishing Attempt": 3
        }
    
    def calculate_priority_score(self, alert):
        severity_score = self.severity_weights.get(alert["severity"], 1)
        type_score = self.type_priorities.get(alert["type"], 1)
        confidence_score = alert["confidence_score"]
        affected_systems = min(alert["affected_systems"], 10) / 10
        
        priority_score = (severity_score * 0.4 + 
                         type_score * 0.3 + 
                         confidence_score * 0.2 + 
                         affected_systems * 0.1)
        
        return round(priority_score, 2)
    
    def classify_alert(self, alert):
        priority_score = self.calculate_priority_score(alert)
        
        if priority_score >= 3.5:
            return "Immediate"
        elif priority_score >= 2.5:
            return "High Priority"
        elif priority_score >= 1.5:
            return "Medium Priority"
        else:
            return "Low Priority"
    
    def triage_alerts(self, alerts):
        triaged_alerts = []
        for alert in alerts:
            priority_score = self.calculate_priority_score(alert)
            classification = self.classify_alert(alert)
            
            triaged_alert = alert.copy()
            triaged_alert["priority_score"] = priority_score
            triaged_alert["classification"] = classification
            triaged_alert["triage_timestamp"] = datetime.now().isoformat()
            
            triaged_alerts.append(triaged_alert)
        
        return sorted(triaged_alerts, key=lambda x: x["priority_score"], reverse=True)

if __name__ == "__main__":
    with open("../data/sample_alerts.json", "r") as f:
        alerts = json.load(f)
    
    triage_engine = BasicTriageEngine()
    triaged = triage_engine.triage_alerts(alerts)
    
    with open("../data/triaged_alerts.json", "w") as f:
        json.dump(triaged, f, indent=2)
    
    print(f"Triaged {len(triaged)} alerts")
    print(f"Classifications: {pd.DataFrame(triaged)['classification'].value_counts().to_dict()}")
