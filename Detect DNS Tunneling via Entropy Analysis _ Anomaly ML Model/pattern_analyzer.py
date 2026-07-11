#!/usr/bin/env python3
import pandas as pd
import numpy as np
import re
from collections import Counter

class DNSTunnelingDetector:
    def __init__(self):
        self.entropy_threshold = 3.5
        self.length_threshold = 20
        self.suspicious_patterns = [
            r'[a-f0-9]{16,}',  # Long hex strings
            r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64-like patterns
            r'\d{10,}',  # Long numeric sequences
        ]
    
    def analyze_patterns(self, df):
        """Analyze DNS queries for tunneling patterns"""
        results = []
        
        for _, row in df.iterrows():
            query = row['query']
            subdomain = row['subdomain']
            
            # Check various indicators
            indicators = {
                'high_entropy': row.get('entropy', 0) > self.entropy_threshold,
                'long_subdomain': len(subdomain) > self.length_threshold,
                'suspicious_pattern': any(re.search(pattern, subdomain) for pattern in self.suspicious_patterns),
                'high_digit_ratio': self.calculate_digit_ratio(subdomain) > 0.5,
                'low_vowel_ratio': self.calculate_vowel_ratio(subdomain) < 0.1,
                'ml_anomaly': row.get('is_anomaly', False)
            }
            
            # Calculate suspicion score
            suspicion_score = sum(indicators.values())
            
            results.append({
                'query': query,
                'subdomain': subdomain,
                'entropy': row.get('entropy', 0),
                'length': len(subdomain),
                'suspicion_score': suspicion_score,
                'is_suspicious': suspicion_score >= 3,
                **indicators
            })
        
        return pd.DataFrame(results)
    
    def calculate_digit_ratio(self, text):
        """Calculate ratio of digits in text"""
        if len(text) == 0:
            return 0
        return sum(c.isdigit() for c in text) / len(text)
    
    def calculate_vowel_ratio(self, text):
        """Calculate ratio of vowels in text"""
        if len(text) == 0:
            return 0
        vowels = 'aeiouAEIOU'
        return sum(c in vowels for c in text) / len(text)
    
    def generate_report(self, df):
        """Generate comprehensive analysis report"""
        suspicious = df[df['is_suspicious']]
        
        print("DNS Tunneling Detection Report")
        print("=" * 50)
        print(f"Total queries analyzed: {len(df)}")
        print(f"Suspicious queries detected: {len(suspicious)}")
        print(f"Suspicion rate: {len(suspicious)/len(df)*100:.1f}%")
        
        if len(suspicious) > 0:
            print("\nSuspicious Queries:")
            print("-" * 30)
            for _, row in suspicious.iterrows():
                print(f"Query: {row['query']}")
                print(f"  Entropy: {row['entropy']:.2f}")
                print(f"  Length: {row['length']}")
                print(f"  Suspicion Score: {row['suspicion_score']}/6")
                
                indicators = []
                if row['high_entropy']: indicators.append("High Entropy")
                if row['long_subdomain']: indicators.append("Long Subdomain")
                if row['suspicious_pattern']: indicators.append("Suspicious Pattern")
                if row['high_digit_ratio']: indicators.append("High Digit Ratio")
                if row['low_vowel_ratio']: indicators.append("Low Vowel Ratio")
                if row['ml_anomaly']: indicators.append("ML Anomaly")
                
                print(f"  Indicators: {', '.join(indicators)}")
                print()
        
        # Statistics
        print("Analysis Statistics:")
        print("-" * 20)
        print(f"Average entropy: {df['entropy'].mean():.2f}")
        print(f"Average length: {df['length'].mean():.1f}")
        print(f"High entropy queries (>{self.entropy_threshold}): {sum(df['high_entropy'])}")
        print(f"Long subdomain queries (>{self.length_threshold}): {sum(df['long_subdomain'])}")
        print(f"ML detected anomalies: {sum(df['ml_anomaly'])}")

if __name__ == "__main__":
    # Load analysis results
    try:
        df = pd.read_csv('anomaly_detection_results.csv')
    except FileNotFoundError:
        try:
            df = pd.read_csv('dns_entropy_results.csv')
            df['is_anomaly'] = False  # Add default values
        except FileNotFoundError:
            print("No analysis results found. Please run previous steps first.")
            exit(1)
    
    # Initialize detector
    detector = DNSTunnelingDetector()
    
    # Analyze patterns
    pattern_results = detector.analyze_patterns(df)
    
    # Generate report
    detector.generate_report(pattern_results)
    
    # Save results
    pattern_results.to_csv('tunneling_detection_results.csv', index=False)
    print(f"\nDetailed results saved to 'tunneling_detection_results.csv'")
