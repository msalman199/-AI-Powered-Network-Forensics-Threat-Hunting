import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
from datetime import datetime
import numpy as np

class HuntingDashboard:
    def __init__(self):
        plt.style.use('default')
        sns.set_palette("husl")
    
    def create_dashboard(self):
        """Create comprehensive hunting dashboard"""
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('AI-Assisted Threat Hunting Dashboard', fontsize=16, fontweight='bold')
        
        # Load data
        try:
            classified_events = pd.read_csv('classified_events.csv')
            anomalies = pd.read_csv('windows_anomalies.csv')
            
            with open('apt_hunt_report.json', 'r') as f:
                apt_report = json.load(f)
        except:
            print("Warning: Some data files not found. Creating sample dashboard.")
            return
        
        # 1. Threat Category Distribution
        threat_counts = classified_events['threat_category'].value_counts()
        axes[0,0].pie(threat_counts.values, labels=threat_counts.index, autopct='%1.1f%%')
        axes[0,0].set_title('Threat Category Distribution')
        
        # 2. Anomaly Scores Timeline
        if not anomalies.empty:
            anomalies['timestamp'] = pd.to_datetime(anomalies['timestamp'])
            axes[0,1].scatter(anomalies['timestamp'], anomalies['anomaly_score'], alpha=0.7)
            axes[0,1].set_title('Anomaly Scores Over Time')
            axes[0,1].tick_params(axis='x', rotation=45)
        
        # 3. APT Indicators by Category
        apt_indicators = apt_report['detailed_findings']['apt_indicators']
        if apt_indicators:
            categories = [ind['category'] for ind in apt_indicators]
            category_counts = pd.Series(categories).value_counts()
            axes[0,2].bar(category_counts.index, category_counts.values)
            axes[0,2].set_title('APT Indicators by Category')
            axes[0,2].tick_params(axis='x', rotation=45)
        
        # 4. Event Timeline
        classified_events['timestamp'] = pd.to_datetime(classified_events['timestamp'])
        classified_events['hour'] = classified_events['timestamp'].dt.hour
        hourly_counts = classified_events['hour'].value_counts().sort_index()
        axes[1,0].plot(hourly_counts.index, hourly_counts.values, marker='o')
        axes[1,0].set_title('Events by Hour of Day')
        axes[1,0].set_xlabel('Hour')
        axes[1,0].set_ylabel('Event Count')
        
        # 5. Confidence Distribution
        axes[1,1].hist(classified_events['confidence'], bins=20, alpha=0.7)
        axes[1,1].set_title('Classification Confidence Distribution')
        axes[1,1].set_xlabel('Confidence Score')
        axes[1,1].set_ylabel('Frequency')
        
        # 6. Risk Summary
        risk_data = {
            'Total Events': len(classified_events),
            'Anomalies': len(anomalies),
            'APT Indicators': len(apt_indicators),
            'High Risk': len(classified_events[classified_events['threat_category'] != 'normal'])
        }
        
        axes[1,2].bar(risk_data.keys(), risk_data.values())
        axes[1,2].set_title('Security Risk Summary')
        axes[1,2].tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig('hunting_dashboard.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        # Create summary report
        summary = {
            'dashboard_generated': str(datetime.now()),
            'total_events_analyzed': len(classified_events),
            'anomalies_detected': len(anomalies),
            'apt_indicators_found': len(apt_indicators),
            'risk_level': apt_report['executive_summary']['risk_level'],
            'key_findings': apt_report['executive_summary']['key_findings']
        }
        
        with open('dashboard_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        print("Hunting dashboard created successfully!")
        print(f"Dashboard saved as: hunting_dashboard.png")
        print(f"Summary saved as: dashboard_summary.json")
        
        return summary

if __name__ == "__main__":
    dashboard = HuntingDashboard()
    summary = dashboard.create_dashboard()
    
    if summary:
        print(f"\n=== HUNTING DASHBOARD SUMMARY ===")
        print(f"Total Events Analyzed: {summary['total_events_analyzed']}")
        print(f"Anomalies Detected: {summary['anomalies_detected']}")
        print(f"APT Indicators Found: {summary['apt_indicators_found']}")
        print(f"Overall Risk Level: {summary['risk_level']}")
