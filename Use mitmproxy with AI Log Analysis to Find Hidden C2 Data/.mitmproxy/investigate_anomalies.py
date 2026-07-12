#!/usr/bin/env python3
import json
import sys
from mitmproxy import io, http
from mitmproxy.exceptions import FlowReadException
import re
import base64
from urllib.parse import urlparse, parse_qs

class AnomalyInvestigator:
    def __init__(self, flow_file):
        self.flow_file = flow_file
        self.flows = []
        self.load_flows()
    
    def load_flows(self):
        """Load flows from mitmproxy dump"""
        try:
            with open(self.flow_file, "rb") as logfile:
                freader = io.FlowReader(logfile)
                for flow in freader.stream():
                    if isinstance(flow, http.HTTPFlow):
                        self.flows.append(flow)
        except FlowReadException as e:
            print(f"Error loading flows: {e}")
    
    def investigate_suspicious_patterns(self):
        """Investigate specific C2 patterns"""
        print("\n" + "="*60)
        print("DETAILED ANOMALY INVESTIGATION")
        print("="*60)
        
        c2_indicators = {
            'command_execution': ['cmd', 'exec', 'shell', 'powershell', 'bash'],
            'data_exfiltration': ['download', 'upload', 'file', 'data'],
            'persistence': ['install', 'service', 'registry', 'startup'],
            'communication': ['beacon', 'checkin', 'heartbeat', 'ping']
        }
        
        findings = []
        
        for i, flow in enumerate(self.flows):
            flow_analysis = {
                'flow_id': i,
                'url': flow.request.pretty_url,
                'method': flow.request.method,
                'indicators': [],
                'risk_score': 0
            }
            
            # Analyze request content
            request_content = flow.request.get_text() or ''
            
            # Check for C2 indicators
            for category, keywords in c2_indicators.items():
                matches = [kw for kw in keywords if kw in request_content.lower()]
                if matches:
                    flow_analysis['indicators'].append({
                        'category': category,
                        'matches': matches
                    })
                    flow_analysis['risk_score'] += len(matches) * 10
            
            # Check for encoded content
            if self.check_encoded_content(request_content):
                flow_analysis['indicators'].append({
                    'category': 'encoded_content',
                    'matches': ['base64_detected']
                })
                flow_analysis['risk_score'] += 15
            
            # Check for unusual headers
            suspicious_headers = self.analyze_headers(flow.request.headers)
            if suspicious_headers:
                flow_analysis['indicators'].append({
                    'category': 'suspicious_headers',
                    'matches': suspicious_headers
                })
                flow_analysis['risk_score'] += 5
            
            # Check POST data patterns
            if flow.request.method == 'POST':
                post_analysis = self.analyze_post_data(flow.request)
                if post_analysis:
                    flow_analysis['indicators'].extend(post_analysis)
                    flow_analysis['risk_score'] += 20
            
            if flow_analysis['risk_score'] > 0:
                findings.append(flow_analysis)
        
        # Sort by risk score
        findings.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return findings
    
    def check_encoded_content(self, content):
        """Check for base64 or other encoded content"""
        # Base64 pattern
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        return bool(re.search(base64_pattern, content))
    
    def analyze_headers(self, headers):
        """Analyze headers for suspicious patterns"""
        suspicious = []
        
        # Check User-Agent
        ua = headers.get('user-agent', '').lower()
        if any(bot in ua for bot in ['bot', 'crawler', 'python', 'curl']):
            suspicious.append('suspicious_user_agent')
        
        # Check for custom headers
        custom_headers = [h for h in headers.keys() if h.startswith('x-') and h not in ['x-forwarded-for', 'x-real-ip']]
        if custom_headers:
            suspicious.append('custom_headers')
        
        return suspicious
    
    def analyze_post_data(self, request):
        """Analyze POST data for C2 patterns"""
        indicators = []
        
        try:
            content = request.get_text() or ''
            
            # Check for JSON with suspicious keys
            if 'application/json' in request.headers.get('content-type', ''):
                try:
                    data = json.loads(content)
                    if isinstance(data, dict):
                        suspicious_keys = ['cmd', 'command', 'exec', 'shell', 'id', 'key', 'token']
                        found_keys = [k for k in data.keys() if k.lower() in suspicious_keys]
                        if found_keys:
                            indicators.append({
                                'category': 'suspicious_json_keys',
                                'matches': found_keys
                            })
                except:
                    pass
            
            # Check for form data
            if 'application/x-www-form-urlencoded' in request.headers.get('content-type', ''):
                if any(param in content.lower() for param in ['cmd=', 'exec=', 'shell=']):
                    indicators.append({
                        'category': 'suspicious_form_data',
                        'matches': ['command_parameters']
                    })
        
        except:
            pass
        
        return indicators
    
    def generate_report(self, findings):
        """Generate detailed investigation report"""
        print(f"\nFOUND {len(findings)} SUSPICIOUS FLOWS")
        print("-" * 50)
        
        for i, finding in enumerate(findings[:10], 1):  # Show top 10
            print(f"\n{i}. HIGH-RISK FLOW (Score: {finding['risk_score']})")
            print(f"   URL: {finding['url']}")
            print(f"   Method: {finding['method']}")
            print(f"   Indicators:")
            
            for indicator in finding['indicators']:
                print(f"     - {indicator['category']}: {', '.join(indicator['matches'])}")
        
        # Summary statistics
        print(f"\n" + "="*50)
        print("INVESTIGATION SUMMARY")
        print("="*50)
        
        total_flows = len(self.flows)
        suspicious_flows = len(findings)
        
        print(f"Total Flows Analyzed: {total_flows}")
        print(f"Suspicious Flows Found: {suspicious_flows}")
        print(f"Suspicion Rate: {(suspicious_flows/total_flows)*100:.1f}%")
        
        # Category breakdown
        categories = {}
        for finding in findings:
            for indicator in finding['indicators']:
                cat = indicator['category']
                categories[cat] = categories.get(cat, 0) + 1
        
        print(f"\nThreat Categories Detected:")
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {cat}: {count} occurrences")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 investigate_anomalies.py <mitm_flow_file>")
        sys.exit(1)
    
    flow_file = sys.argv[1]
    investigator = AnomalyInvestigator(flow_file)
    
    findings = investigator.investigate_suspicious_patterns()
    investigator.generate_report(findings)

if __name__ == "__main__":
    main()
