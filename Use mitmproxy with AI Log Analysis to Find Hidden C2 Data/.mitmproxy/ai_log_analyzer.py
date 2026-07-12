#!/usr/bin/env python3
import json
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
import re
import sys
from mitmproxy import io, http
from mitmproxy.exceptions import FlowReadException

class C2TrafficAnalyzer:
    def __init__(self):
        self.flows = []
        self.features = []
        
    def load_mitm_flows(self, flow_file):
        """Load flows from mitmproxy dump file"""
        try:
            with open(flow_file, "rb") as logfile:
                freader = io.FlowReader(logfile)
                for flow in freader.stream():
                    if isinstance(flow, http.HTTPFlow):
                        self.flows.append(flow)
        except FlowReadException as e:
            print(f"Error reading flow file: {e}")
            return False
        return True
    
    def extract_features(self):
        """Extract features for AI analysis"""
        features = []
        
        for flow in self.flows:
            feature = {
                'url': flow.request.pretty_url,
                'method': flow.request.method,
                'status_code': flow.response.status_code if flow.response else 0,
                'request_size': len(flow.request.raw_content) if flow.request.raw_content else 0,
                'response_size': len(flow.response.raw_content) if flow.response and flow.response.raw_content else 0,
                'headers_count': len(flow.request.headers),
                'has_json': 'application/json' in flow.request.headers.get('content-type', ''),
                'user_agent': flow.request.headers.get('user-agent', ''),
                'content': flow.request.get_text() or '',
                'response_content': flow.response.get_text() if flow.response else ''
            }
            
            # Extract suspicious keywords
            suspicious_keywords = ['cmd', 'exec', 'shell', 'beacon', 'payload', 'download', 'upload']
            feature['suspicious_keywords'] = sum(1 for keyword in suspicious_keywords 
                                               if keyword in feature['content'].lower())
            
            # Calculate entropy of content
            feature['content_entropy'] = self.calculate_entropy(feature['content'])
            
            # Check for base64 patterns
            feature['has_base64'] = bool(re.search(r'[A-Za-z0-9+/]{20,}={0,2}', feature['content']))
            
            features.append(feature)
        
        self.features = features
        return features
    
    def calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * np.log2(p) for p in prob if p > 0])
        return entropy
    
    def detect_anomalies(self):
        """Use AI to detect anomalous traffic patterns"""
        if not self.features:
            return []
        
        # Prepare numerical features for ML
        df = pd.DataFrame(self.features)
        
        numerical_features = [
            'request_size', 'response_size', 'headers_count', 
            'suspicious_keywords', 'content_entropy'
        ]
        
        # Handle missing values
        for col in numerical_features:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        X = df[numerical_features].values
        
        # Apply Isolation Forest for anomaly detection
        iso_forest = IsolationForest(contamination=0.3, random_state=42)
        anomaly_labels = iso_forest.fit_predict(X)
        
        # Identify anomalies
        anomalies = []
        for i, label in enumerate(anomaly_labels):
            if label == -1:  # Anomaly detected
                anomaly_data = {
                    'index': i,
                    'url': df.iloc[i]['url'],
                    'method': df.iloc[i]['method'],
                    'suspicious_score': abs(iso_forest.decision_function(X[i:i+1])[0]),
                    'features': {k: df.iloc[i][k] for k in numerical_features}
                }
                anomalies.append(anomaly_data)
        
        return sorted(anomalies, key=lambda x: x['suspicious_score'], reverse=True)
    
    def analyze_content_patterns(self):
        """Analyze content patterns using text mining"""
        if not self.features:
            return []
        
        # Extract all content for analysis
        contents = [f['content'] + ' ' + f['response_content'] for f in self.features]
        contents = [c for c in contents if c.strip()]
        
        if not contents:
            return []
        
        # Use TF-IDF to find unusual patterns
        vectorizer = TfidfVectorizer(max_features=100, stop_words='english', ngram_range=(1, 2))
        tfidf_matrix = vectorizer.fit_transform(contents)
        
        # Apply DBSCAN clustering to find outliers
        clustering = DBSCAN(eps=0.5, min_samples=2, metric='cosine')
        cluster_labels = clustering.fit_predict(tfidf_matrix.toarray())
        
        # Identify outlier patterns
        outliers = []
        for i, label in enumerate(cluster_labels):
            if label == -1:  # Outlier
                outliers.append({
                    'index': i,
                    'url': self.features[i]['url'],
                    'content_snippet': contents[i][:200] + '...' if len(contents[i]) > 200 else contents[i]
                })
        
        return outliers

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 ai_log_analyzer.py <mitm_flow_file>")
        sys.exit(1)
    
    flow_file = sys.argv[1]
    analyzer = C2TrafficAnalyzer()
    
    print("Loading mitmproxy flows...")
    if not analyzer.load_mitm_flows(flow_file):
        print("Failed to load flows")
        sys.exit(1)
    
    print(f"Loaded {len(analyzer.flows)} flows")
    
    print("Extracting features...")
    analyzer.extract_features()
    
    print("Detecting anomalies with AI...")
    anomalies = analyzer.detect_anomalies()
    
    print("Analyzing content patterns...")
    content_outliers = analyzer.analyze_content_patterns()
    
    # Display results
    print("\n" + "="*60)
    print("AI-POWERED C2 TRAFFIC ANALYSIS RESULTS")
    print("="*60)
    
    print(f"\nANOMALOUS TRAFFIC DETECTED: {len(anomalies)} flows")
    print("-" * 40)
    
    for i, anomaly in enumerate(anomalies[:5], 1):  # Show top 5
        print(f"\n{i}. SUSPICIOUS FLOW:")
        print(f"   URL: {anomaly['url']}")
        print(f"   Method: {anomaly['method']}")
        print(f"   Suspicion Score: {anomaly['suspicious_score']:.3f}")
        print(f"   Features: {anomaly['features']}")
    
    print(f"\nCONTENT PATTERN OUTLIERS: {len(content_outliers)} flows")
    print("-" * 40)
    
    for i, outlier in enumerate(content_outliers[:3], 1):  # Show top 3
        print(f"\n{i}. UNUSUAL CONTENT PATTERN:")
        print(f"   URL: {outlier['url']}")
        print(f"   Content: {outlier['content_snippet']}")

if __name__ == "__main__":
    main()
