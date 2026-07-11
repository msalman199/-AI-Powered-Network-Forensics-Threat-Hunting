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
            # Using ipinfo.io (free tier)
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
            # Simple DNS resolution check
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
        
        # Simulate LangChain analysis without API call
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
    # Initialize enricher
    enricher = IOCEnricher()
    
    # Sample IOCs for testing
    sample_iocs = [
        {'type': 'ip-dst', 'value': '8.8.8.8', 'comment': 'Test IP'},
        {'type': 'domain', 'value': 'google.com', 'comment': 'Test domain'},
        {'type': 'md5', 'value': 'd41d8cd98f00b204e9800998ecf8427e', 'comment': 'Test hash'}
    ]
    
    print("=== IOC Enrichment Analysis ===\n")
    
    for ioc in sample_iocs:
        print(f"Analyzing IOC: {ioc['value']} ({ioc['type']})")
        print("-" * 50)
        
        # Perform OSINT lookup
        enrichment_data = enricher.osint_lookup(ioc['value'], ioc['type'])
        print(f"Enrichment Data: {json.dumps(enrichment_data, indent=2)}")
        
        # Perform LangChain analysis
        analysis = enricher.langchain_analysis(ioc, enrichment_data)
        print(f"Risk Level: {analysis['risk_level']}")
        print(f"Recommendations: {analysis['recommendations']}")
        print(f"Detection Opportunities: {analysis['detection_opportunities']}")
        print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    main()
