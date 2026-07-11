import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix
from datetime import datetime

class TriagePerformanceEvaluator:
    def __init__(self):
        self.metrics = {}
        
    def load_data(self, filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    
    def create_ground_truth(self, alerts):
        # Simulate ground truth based on alert characteristics
        ground_truth = []
        for alert in alerts:
            # Create realistic ground truth labels
            if (alert["severity"] == "Critical" and 
                alert["confidence_score"] > 0.7 and
                alert["type"] in ["Malware Detection", "Data Exfiltration"]):
                ground_truth.append("True Positive")
            elif (alert["severity"] in ["Low", "Medium"] and 
                  alert["confidence_score"] < 0.4):
                ground_truth.append("False Positive")
            elif alert["confidence_score"] > 0.8:
                ground_truth.append("True Positive")
            else:
                ground_truth.append("True Positive" if np.random.random() > 0.3 else "False Positive")
        
        return ground_truth
    
    def evaluate_classification_accuracy(self, alerts, ground_truth):
        predictions = []
        for alert in alerts:
            gpt_risk = alert.get("gpt_analysis", {}).get("risk_assessment", 5)
            if gpt_risk >= 7:
                predictions.append("True Positive")
            else:
                predictions.append("False Positive")
        
        # Calculate metrics
        tp = sum(1 for p, g in zip(predictions, ground_truth) if p == "True Positive" and g == "True Positive")
        fp = sum(1 for p, g in zip(predictions, ground_truth) if p == "True Positive" and g == "False Positive")
        tn = sum(1 for p, g in zip(predictions, ground_truth) if p == "False Positive" and g == "False Positive")
        fn = sum(1 for p, g in zip(predictions, ground_truth) if p == "False Positive" and g == "True Positive")
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / len(predictions)
        
        return {
            "accuracy": round(accuracy, 3),
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1_score": round(f1_score, 3),
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn
        }
    
    def analyze_triage_efficiency(self, alerts):
        df = pd.DataFrame(alerts)
        
        # Priority distribution
        priority_dist = df['classification'].value_counts()
        
        # Average processing scores
        avg_priority_score = df['priority_score'].mean()
        avg_final_priority = df['final_priority'].mean()
        
        # Risk assessment distribution
        risk_scores = [alert.get("gpt_analysis", {}).get("risk_assessment", 0) for alert in alerts]
        avg_risk_score = np.mean(risk_scores)
        
        return {
            "priority_distribution": priority_dist.to_dict(),
            "average_priority_score": round(avg_priority_score, 2),
            "average_final_priority": round(avg_final_priority, 2),
            "average_risk_score": round(avg_risk_score, 2),
            "total_alerts_processed": len(alerts)
        }
    
    def generate_performance_report(self, alerts):
        ground_truth = self.create_ground_truth(alerts)
        classification_metrics = self.evaluate_classification_accuracy(alerts, ground_truth)
        efficiency_metrics = self.analyze_triage_efficiency(alerts)
        
        report = {
            "evaluation_timestamp": datetime.now().isoformat(),
            "classification_performance": classification_metrics,
            "triage_efficiency": efficiency_metrics,
            "recommendations": self.generate_recommendations(classification_metrics, efficiency_metrics)
        }
        
        return report
    
    def generate_recommendations(self, classification_metrics, efficiency_metrics):
        recommendations = []
        
        if classification_metrics["precision"] < 0.8:
            recommendations.append("Consider adjusting risk thresholds to reduce false positives")
        
        if classification_metrics["recall"] < 0.8:
            recommendations.append("Review alert detection rules to capture more true threats")
        
        if efficiency_metrics["average_risk_score"] < 5:
            recommendations.append("Alert sources may need calibration for better risk assessment")
        
        high_priority_ratio = efficiency_metrics["priority_distribution"].get("Immediate", 0) / efficiency_metrics["total_alerts_processed"]
        if high_priority_ratio > 0.3:
            recommendations.append("Too many high-priority alerts - consider refining classification criteria")
        
        return recommendations
    
    def create_visualizations(self, alerts):
        df = pd.DataFrame(alerts)
        
        # Create plots
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Priority distribution
        priority_counts = df['classification'].value_counts()
        axes[0, 0].pie(priority_counts.values, labels=priority_counts.index, autopct='%1.1f%%')
        axes[0, 0].set_title('Alert Priority Distribution')
        
        # Risk score distribution
        risk_scores = [alert.get("gpt_analysis", {}).get("risk_assessment", 0) for alert in alerts]
        axes[0, 1].hist(risk_scores, bins=10, edgecolor='black')
        axes[0, 1].set_title('GPT Risk Assessment Distribution')
        axes[0, 1].set_xlabel('Risk Score')
        axes[0, 1].set_ylabel('Frequency')
        
        # Severity vs Priority Score
        severity_order = ['Low', 'Medium', 'High', 'Critical']
        df['severity'] = pd.Categorical(df['severity'], categories=severity_order, ordered=True)
        df.boxplot(column='priority_score', by='severity', ax=axes[1, 0])
        axes[1, 0].set_title('Priority Score by Severity')
        
        # Final priority vs Basic priority
        axes[1, 1].scatter(df['priority_score'], df['final_priority'], alpha=0.6)
        axes[1, 1].plot([0, 4], [0, 4], 'r--', alpha=0.8)
        axes[1, 1].set_xlabel('Basic Priority Score')
        axes[1, 1].set_ylabel('Final Priority Score')
        axes[1, 1].set_title('Basic vs Enhanced Priority Scores')
        
        plt.tight_layout()
        plt.savefig('../logs/triage_performance_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print("Performance visualizations saved to ../logs/triage_performance_analysis.png")

if __name__ == "__main__":
    evaluator = TriagePerformanceEvaluator()
    
    # Load enhanced alerts
    alerts = evaluator.load_data("../data/gpt_enhanced_alerts.json")
    
    # Generate performance report
    report = evaluator.generate_performance_report(alerts)
    
    # Save report
    with open("../logs/performance_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    # Create visualizations
    evaluator.create_visualizations(alerts)
    
    # Print summary
    print("=== TRIAGE PERFORMANCE EVALUATION ===")
    print(f"Total Alerts Processed: {report['triage_efficiency']['total_alerts_processed']}")
    print(f"Classification Accuracy: {report['classification_performance']['accuracy']}")
    print(f"Precision: {report['classification_performance']['precision']}")
    print(f"Recall: {report['classification_performance']['recall']}")
    print(f"F1-Score: {report['classification_performance']['f1_score']}")
    print(f"Average Risk Score: {report['triage_efficiency']['average_risk_score']}")
    
    print("\n=== RECOMMENDATIONS ===")
    for i, rec in enumerate(report['recommendations'], 1):
        print(f"{i}. {rec}")
    
    print(f"\nDetailed report saved to: ../logs/performance_report.json")
