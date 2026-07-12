#!/usr/bin/env python3
import json
from datetime import datetime

def create_html_dashboard():
    """Create an HTML dashboard for the analysis results"""
    
    # Load the final report
    with open('final_actionable_report.json', 'r') as f:
        report = json.load(f)
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Network Security Analysis Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
            .risk-high {{ color: #e74c3c; font-weight: bold; }}
            .risk-medium {{ color: #f39c12; font-weight: bold; }}
            .risk-low {{ color: #27ae60; font-weight: bold; }}
            .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
            .action-item {{ margin: 10px 0; padding: 10px; background-color: #f8f9fa; border-left: 4px solid #007bff; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Network Security Analysis Dashboard</h1>
            <p>Generated: {report['executive_summary']['assessment_date']}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Total Packets Analyzed</td><td>{report['executive_summary']['network_overview']['total_packets_analyzed']}</td></tr>
                <tr><td>Anomalies Detected</td><td>{report['executive_summary']['network_overview']['anomalies_detected']}</td></tr>
                <tr><td>Overall Risk Level</td><td class="risk-{report['executive_summary']['network_overview']['overall_risk_level'].lower()}">{report['executive_summary']['network_overview']['overall_risk_level']}</td></tr>
                <tr><td>Immediate Actions Required</td><td>{report['executive_summary']['immediate_actions_required']}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Key Findings</h2>
    """
    
    for finding in report['executive_summary']['key_findings']:
        risk_class = f"risk-{finding['severity'].lower()}"
        html_content += f"""
            <div class="action-item">
                <strong>{finding['type']}</strong> 
                <span class="{risk_class}">({finding['severity']} Severity)</span><br>
                {finding['description']}
            </div>
        """
    
    html_content += """
        </div>
        
        <div class="section">
            <h2>High Priority Actions</h2>
    """
    
    for action in report['actionable_items']['high_priority']:
        html_content += f"""
            <div class="action-item">
                <strong>Category:</strong> {action['category']}<br>
                <strong>Action:</strong> {action['action']}<br>
                <strong>Source:</strong> {action['source']}
            </div>
        """
    
    html_content += """
        </div>
        
        <div class="section">
            <h2>Technical Details</h2>
            <p><strong>Analysis Methodology:</strong> Traditional PCAP analysis enhanced with AI-powered insights</p>
            <p><strong>Tools Used:</strong> tcpdump, scapy, LangChain, OpenAI GPT</p>
            <p><strong>Confidence Level:</strong> High</p>
        </div>
    </body>
    </html>
    """
    
    with open('security_dashboard.html', 'w') as f:
        f.write(html_content)
    
    print("HTML dashboard created: security_dashboard.html")

if __name__ == "__main__":
    create_html_dashboard()
