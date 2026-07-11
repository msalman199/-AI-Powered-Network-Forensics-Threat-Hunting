import json
import pandas as pd
from datetime import datetime

class TriageDashboard:
    def __init__(self):
        self.alerts_data = None
        self.performance_data = None
    
    def load_data(self):
        with open("../data/gpt_enhanced_alerts.json", "r") as f:
            self.alerts_data = json.load(f)
        
        with open("../logs/performance_report.json", "r") as f:
            self.performance_data = json.load(f)
    
    def display_summary(self):
        print("=" * 60)
        print("           AUTOMATED ALERT TRIAGE DASHBOARD")
        print("=" * 60)
        
        # Alert Statistics
        total_alerts = len(self.alerts_data)
        df = pd.DataFrame(self.alerts_data)
        
        print(f"\n📊 ALERT STATISTICS")
        print(f"   Total Alerts Processed: {total_alerts}")
        print(f"   Alert Types: {df['type'].nunique()}")
        print(f"   Severity Levels: {df['severity'].nunique()}")
        print(f"   Average Confidence: {df['confidence_score'].mean():.2f}")
        
        # Priority Distribution
        priority_dist = df['classification'].value_counts()
        print(f"\n🎯 PRIORITY DISTRIBUTION")
        for priority, count in priority_dist.items():
            percentage = (count / total_alerts) * 100
            print(f"   {priority}: {count} ({percentage:.1f}%)")
        
        # Performance Metrics
        perf = self.performance_data['classification_performance']
        print(f"\n📈 PERFORMANCE METRICS")
        print(f"   Accuracy: {perf['accuracy']:.1%}")
        print(f"   Precision: {perf['precision']:.1%}")
        print(f"   Recall: {perf['recall']:.1%}")
        print(f"   F1-Score: {perf['f1_score']:.1%}")
        
        # Top Risk Alerts
        high_risk_alerts = [a for a in self.alerts_data 
                           if a.get('gpt_analysis', {}).get('risk_assessment', 0) >= 8]
        print(f"\n🚨 HIGH RISK ALERTS")
        print(f"   Count: {len(high_risk_alerts)}")
        
        if high_risk_alerts:
            print("   Top 3 High Risk Alerts:")
            for i, alert in enumerate(sorted(high_risk_alerts, 
                                           key=lambda x: x['gpt_analysis']['risk_assessment'], 
                                           reverse=True)[:3], 1):
                risk_score = alert['gpt_analysis']['risk_assessment']
                print(f"   {i}. {alert['type']} (Risk: {risk_score}/10)")
        
        # Recommendations
        recommendations = self.performance_data.get('recommendations', [])
        if recommendations:
            print(f"\n💡 RECOMMENDATIONS")
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec}")
        
        print(f"\n⏰ Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

if __name__ == "__main__":
    dashboard = TriageDashboard()
    dashboard.load_data()
    dashboard.display_summary()
