import json
import time
import requests
from datetime import datetime

class GPTTriageAgent:
    def __init__(self, config_path="../config/config.json"):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        # For this lab, we'll simulate GPT responses
        # In production, you would use actual OpenAI API
        self.simulate_gpt = True
        
    def format_alert_for_analysis(self, alert):
        return f"""
        ID: {alert['id']}
        Type: {alert['type']}
        Severity: {alert['severity']}
        Source: {alert['source']}
        Description: {alert['description']}
        Source IP: {alert['source_ip']}
        Affected Systems: {alert['affected_systems']}
        Confidence: {alert['confidence_score']}
        """
    
    def simulate_gpt_response(self, alert):
        # Simulate GPT analysis based on alert characteristics
        severity_map = {"Critical": 9, "High": 7, "Medium": 5, "Low": 3}
        base_risk = severity_map.get(alert["severity"], 3)
        
        # Add some variation based on other factors
        if alert["type"] in ["Malware Detection", "Data Exfiltration"]:
            risk_score = min(10, base_risk + 2)
        elif alert["confidence_score"] > 0.8:
            risk_score = min(10, base_risk + 1)
        else:
            risk_score = base_risk
        
        actions = {
            (9, 10): "Immediate investigation required",
            (7, 8): "Escalate to security team",
            (5, 6): "Monitor and investigate within 4 hours",
            (1, 4): "Log and review during next cycle"
        }
        
        urgency_levels = {
            (9, 10): "Critical",
            (7, 8): "High",
            (5, 6): "Medium",
            (1, 4): "Low"
        }
        
        action = next(v for k, v in actions.items() if k[0] <= risk_score <= k[1])
        urgency = next(v for k, v in urgency_levels.items() if k[0] <= risk_score <= k[1])
        
        return {
            "risk_assessment": risk_score,
            "recommended_action": action,
            "reasoning": f"Based on {alert['type']} with {alert['severity']} severity and {alert['confidence_score']} confidence",
            "urgency_level": urgency,
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def analyze_alert(self, alert):
        if self.simulate_gpt:
            return self.simulate_gpt_response(alert)
        else:
            # Real GPT API call would go here
            # This is where you'd integrate with OpenAI API
            pass
    
    def batch_analyze_alerts(self, alerts, max_alerts=50):
        analyzed_alerts = []
        
        for i, alert in enumerate(alerts[:max_alerts]):
            print(f"Analyzing alert {i+1}/{min(len(alerts), max_alerts)}")
            
            gpt_analysis = self.analyze_alert(alert)
            
            enhanced_alert = alert.copy()
            enhanced_alert["gpt_analysis"] = gpt_analysis
            enhanced_alert["final_priority"] = self.calculate_final_priority(alert, gpt_analysis)
            
            analyzed_alerts.append(enhanced_alert)
            
            # Simulate API rate limiting
            time.sleep(0.1)
        
        return analyzed_alerts
    
    def calculate_final_priority(self, alert, gpt_analysis):
        # Combine basic triage with GPT insights
        basic_score = alert.get("priority_score", 2.0)
        gpt_risk = gpt_analysis["risk_assessment"] / 10 * 4  # Scale to 0-4
        
        final_score = (basic_score * 0.6) + (gpt_risk * 0.4)
        return round(final_score, 2)

if __name__ == "__main__":
    with open("../data/triaged_alerts.json", "r") as f:
        alerts = json.load(f)
    
    agent = GPTTriageAgent()
    enhanced_alerts = agent.batch_analyze_alerts(alerts, max_alerts=30)
    
    with open("../data/gpt_enhanced_alerts.json", "w") as f:
        json.dump(enhanced_alerts, f, indent=2)
    
    print(f"Enhanced {len(enhanced_alerts)} alerts with GPT analysis")
