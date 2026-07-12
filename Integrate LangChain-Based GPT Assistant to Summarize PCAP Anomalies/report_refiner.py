#!/usr/bin/env python3
import json
from datetime import datetime

class ReportRefiner:
    def __init__(self, ai_report_file):
        with open(ai_report_file, 'r') as f:
            self.ai_report = json.load(f)
    
    def extract_actionable_items(self):
        """Extract and prioritize actionable items"""
        actionable_items = []
        
        # Extract from overall recommendations
        overall_recs = self.ai_report['overall_summary'].get('recommendations', [])
        for rec in overall_recs:
            actionable_items.append({
                'category': 'General Security',
                'action': rec,
                'priority': self.determine_priority(rec),
                'source': 'Overall Analysis'
            })
        
        # Extract from detailed anomaly analyses
        for detail in self.ai_report['detailed_anomaly_analyses']:
            anomaly_type = detail['anomaly'].get('type', 'Unknown')
            severity = detail['anomaly'].get('severity', 'Low')
            
            # Extract specific actions from AI analysis
            ai_text = detail['ai_analysis']
            if isinstance(ai_text, str):
                actions = self.extract_actions_from_text(ai_text)
                for action in actions:
                    actionable_items.append({
                        'category': anomaly_type,
                        'action': action,
                        'priority': severity,
                        'source': f'Anomaly Analysis: {anomaly_type}'
                    })
        
        return actionable_items
    
    def determine_priority(self, text):
        """Determine priority level from text content"""
        text_lower = text.lower()
        
        if any(keyword in text_lower for keyword in ['immediate', 'urgent', 'critical', 'asap']):
            return 'High'
        elif any(keyword in text_lower for keyword in ['soon', 'important', 'should']):
            return 'Medium'
        else:
            return 'Low'
    
    def extract_actions_from_text(self, text):
        """Extract actionable statements from analysis text"""
        actions = []
        sentences = text.split('.')
        
        for sentence in sentences:
            sentence = sentence.strip()
            if any(keyword in sentence.lower() for keyword in [
                'implement', 'configure', 'monitor', 'block', 'update', 
                'install', 'enable', 'disable', 'review', 'check'
            ]):
                if len(sentence) > 10:  # Filter out very short sentences
                    actions.append(sentence)
        
        return actions[:3]  # Limit to top 3 actions per anomaly
    
    def generate_executive_summary(self):
        """Generate executive summary for management"""
        original_stats = self.ai_report['original_analysis']['basic_statistics']
        anomalies = self.ai_report['original_analysis']['anomalies_detected']
        risk_level = self.ai_report['overall_summary']['risk_level']
        
        summary = {
            'assessment_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'network_overview': {
                'total_packets_analyzed': original_stats['total_packets'],
                'anomalies_detected': len(anomalies),
                'overall_risk_level': risk_level
            },
            'key_findings': [],
            'immediate_actions_required': 0,
            'business_impact': self.assess_business_impact(risk_level, anomalies)
        }
        
        # Categorize findings
        for anomaly in anomalies:
            summary['key_findings'].append({
                'type': anomaly['type'],
                'severity': anomaly.get('severity', 'Unknown'),
                'description': self.generate_finding_description(anomaly)
            })
            
            if anomaly.get('severity') == 'High':
                summary['immediate_actions_required'] += 1
        
        return summary
    
    def assess_business_impact(self, risk_level, anomalies):
        """Assess potential business impact"""
        if risk_level == 'High':
            return "High - Potential for data breach, service disruption, or compliance violations"
        elif risk_level == 'Medium':
            return "Medium - Possible security vulnerabilities that could be exploited"
        else:
            return "Low - Minor security concerns with minimal immediate impact"
    
    def generate_finding_description(self, anomaly):
        """Generate human-readable description of findings"""
        anomaly_type = anomaly.get('type', 'Unknown')
        
        descriptions = {
            'Port Scan': f"Detected port scanning activity from {anomaly.get('source_ip', 'unknown IP')} targeting {anomaly.get('ports_scanned', 0)} ports",
            'Excessive DNS Queries': f"Unusual DNS query volume from {anomaly.get('source_ip', 'unknown IP')} with {anomaly.get('query_count', 0)} queries",
            'Large Packets Detected': f"Detected {anomaly.get('count', 0)} oversized packets, maximum size {anomaly.get('max_size', 0)} bytes"
        }
        
        return descriptions.get(anomaly_type, f"Detected {anomaly_type} anomaly")
    
    def create_refined_report(self):
        """Create final refined report"""
        actionable_items = self.extract_actionable_items()
        executive_summary = self.generate_executive_summary()
        
        # Sort actionable items by priority
        priority_order = {'High': 3, 'Medium': 2, 'Low': 1}
        actionable_items.sort(key=lambda x: priority_order.get(x['priority'], 0), reverse=True)
        
        refined_report = {
            'executive_summary': executive_summary,
            'actionable_items': {
                'high_priority': [item for item in actionable_items if item['priority'] == 'High'],
                'medium_priority': [item for item in actionable_items if item['priority'] == 'Medium'],
                'low_priority': [item for item in actionable_items if item['priority'] == 'Low']
            },
            'technical_details': {
                'analysis_methodology': 'Traditional PCAP analysis enhanced with AI-powered insights',
                'tools_used': ['tcpdump', 'scapy', 'LangChain', 'OpenAI GPT'],
                'confidence_level': 'High'
            }
        }
        
        return refined_report

if __name__ == "__main__":
    refiner = ReportRefiner('ai_enhanced_pcap_report.json')
    refined_report = refiner.create_refined_report()
    
    # Save refined report
    with open('final_actionable_report.json', 'w') as f:
        json.dump(refined_report, f, indent=2)
    
    # Display summary
    print("=== NETWORK SECURITY ASSESSMENT SUMMARY ===")
    print(f"Assessment Date: {refined_report['executive_summary']['assessment_date']}")
    print(f"Overall Risk Level: {refined_report['executive_summary']['network_overview']['overall_risk_level']}")
    print(f"Anomalies Detected: {refined_report['executive_summary']['network_overview']['anomalies_detected']}")
    print(f"Immediate Actions Required: {refined_report['executive_summary']['immediate_actions_required']}")
    
    print("\n=== HIGH PRIORITY ACTIONS ===")
    for item in refined_report['actionable_items']['high_priority'][:5]:
        print(f"• {item['action']}")
    
    print(f"\nFull actionable report saved to: final_actionable_report.json")
