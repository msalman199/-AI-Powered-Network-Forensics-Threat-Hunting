#!/usr/bin/env python3
import argparse
import time
from model_trainer import ObfuscationDetector
from pcap_analyzer import PCAPAnalyzer
import pandas as pd

class RealTimeDetector:
    def __init__(self, model_path="models/obfuscation_detector.pkl"):
        self.detector = ObfuscationDetector()
        self.detector.load_model(model_path)
        self.alert_threshold = 0.7
    
    def analyze_pcap_file(self, pcap_file):
        """Analyze a PCAP file for obfuscated payloads"""
        print(f"\n{'='*50}")
        print(f"Analyzing: {pcap_file}")
        print(f"{'='*50}")
        
        # Extract features
        analyzer = PCAPAnalyzer(pcap_file)
        df_features = analyzer.extract_features()
        
        if len(df_features) == 0:
            print("No analyzable packets found in PCAP file")
            return
        
        # Make predictions
        X = df_features[self.detector.feature_columns].fillna(0)
        predictions, probabilities = self.detector.predict(X)
        
        # Generate alerts
        alerts = []
        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
            if prob[1] > self.alert_threshold:  # High probability of obfuscation
                alert = {
                    'packet_id': i,
                    'src_ip': df_features.iloc[i]['src_ip'],
                    'dst_ip': df_features.iloc[i]['dst_ip'],
                    'dst_port': df_features.iloc[i]['dst_port'],
                    'entropy': df_features.iloc[i]['entropy'],
                    'obfuscation_probability': prob[1],
                    'prediction': 'OBFUSCATED' if pred == 1 else 'NORMAL'
                }
                alerts.append(alert)
        
        # Display results
        total_packets = len(df_features)
        obfuscated_packets = sum(predictions)
        
        print(f"Total packets: {total_packets}")
        print(f"Obfuscated packets detected: {obfuscated_packets}")
        print(f"Detection rate: {obfuscated_packets/total_packets*100:.1f}%")
        
        if alerts:
            print(f"\n🚨 HIGH-CONFIDENCE ALERTS ({len(alerts)}):")
            print("-" * 80)
            for alert in alerts[:10]:  # Show top 10 alerts
                print(f"Packet {alert['packet_id']:3d}: {alert['src_ip']:15s} -> {alert['dst_ip']:15s}:{alert['dst_port']:5d} "
                      f"| Entropy: {alert['entropy']:5.2f} | Prob: {alert['obfuscation_probability']:5.3f} | {alert['prediction']}")
        
        return alerts
    
    def batch_analysis(self, pcap_files):
        """Analyze multiple PCAP files"""
        all_alerts = []
        
        for pcap_file in pcap_files:
            try:
                alerts = self.analyze_pcap_file(pcap_file)
                if alerts:
                    all_alerts.extend(alerts)
            except Exception as e:
                print(f"Error analyzing {pcap_file}: {e}")
        
        # Summary report
        print(f"\n{'='*50}")
        print("BATCH ANALYSIS SUMMARY")
        print(f"{'='*50}")
        print(f"Files analyzed: {len(pcap_files)}")
        print(f"Total alerts generated: {len(all_alerts)}")
        
        if all_alerts:
            # Top suspicious IPs
            src_ips = [alert['src_ip'] for alert in all_alerts]
            from collections import Counter
            top_ips = Counter(src_ips).most_common(5)
            
            print("\nTop suspicious source IPs:")
            for ip, count in top_ips:
                print(f"  {ip}: {count} alerts")
        
        return all_alerts

def main():
    parser = argparse.ArgumentParser(description='Real-time obfuscated payload detector')
    parser.add_argument('pcap_files', nargs='+', help='PCAP files to analyze')
    parser.add_argument('--threshold', type=float, default=0.7, 
                       help='Alert threshold (0.0-1.0)')
    parser.add_argument('--model', default='models/obfuscation_detector.pkl',
                       help='Path to trained model')
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = RealTimeDetector(args.model)
    detector.alert_threshold = args.threshold
    
    # Run analysis
    if len(args.pcap_files) == 1:
        detector.analyze_pcap_file(args.pcap_files[0])
    else:
        detector.batch_analysis(args.pcap_files)

if __name__ == "__main__":
    # Demo with existing files
    detector = RealTimeDetector()
    pcap_files = ["data/normal_traffic.pcap", "data/obfuscated_traffic.pcap", "data/mixed_traffic.pcap"]
    detector.batch_analysis(pcap_files)
