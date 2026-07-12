#!/usr/bin/env python3
import pandas as pd
import numpy as np
from model_trainer import ObfuscationDetector
from pcap_analyzer import PCAPAnalyzer
import matplotlib.pyplot as plt

def evaluate_on_new_pcap(pcap_file, model_path="models/obfuscation_detector.pkl"):
    """Evaluate model on new PCAP file"""
    # Load trained model
    detector = ObfuscationDetector()
    detector.load_model(model_path)
    
    # Analyze new PCAP
    analyzer = PCAPAnalyzer(pcap_file)
    df_features = analyzer.extract_features()
    
    if len(df_features) == 0:
        print("No features extracted from PCAP file")
        return
    
    # Prepare features
    X = df_features[detector.feature_columns].fillna(0)
    
    # Make predictions
    predictions, probabilities = detector.predict(X)
    
    # Add predictions to dataframe
    df_features['predicted_label'] = predictions
    df_features['obfuscation_probability'] = probabilities[:, 1]
    
    # Summary
    total_packets = len(df_features)
    obfuscated_count = sum(predictions)
    normal_count = total_packets - obfuscated_count
    
    print(f"\nPCAP Analysis Results for {pcap_file}:")
    print(f"Total packets analyzed: {total_packets}")
    print(f"Normal traffic: {normal_count} ({normal_count/total_packets*100:.1f}%)")
    print(f"Obfuscated traffic: {obfuscated_count} ({obfuscated_count/total_packets*100:.1f}%)")
    
    # Show high-confidence obfuscated packets
    high_confidence = df_features[df_features['obfuscation_probability'] > 0.8]
    if len(high_confidence) > 0:
        print(f"\nHigh-confidence obfuscated packets ({len(high_confidence)}):")
        print(high_confidence[['src_ip', 'dst_ip', 'dst_port', 'entropy', 'obfuscation_probability']].head())
    
    return df_features

# Evaluate on mixed traffic
if __name__ == "__main__":
    results = evaluate_on_new_pcap("data/mixed_traffic.pcap")
    
    # Save results
    if results is not None:
        results.to_csv("results/detection_results.csv", index=False)
        print("\nDetection results saved to results/detection_results.csv")
