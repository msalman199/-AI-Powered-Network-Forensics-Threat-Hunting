#!/usr/bin/env python3
import subprocess
import json
import pandas as pd
from datetime import datetime

def run_rita_analysis():
    """Run RITA beacon analysis and capture results"""
    print("Running RITA beacon analysis...")
    
    try:
        result = subprocess.run(['rita', 'show-beacons', 'beacon_analysis_db', '--human-readable'], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("RITA Analysis Results:")
            print("-" * 40)
            print(result.stdout)
            return result.stdout
        else:
            print(f"RITA error: {result.stderr}")
            return None
    except Exception as e:
        print(f"Error running RITA: {e}")
        return None

def correlate_results():
    """Correlate RITA and AI analysis results"""
    print("\nCORRELATING RITA AND AI RESULTS:")
    print("=" * 50)
    
    # Load AI results if available
    try:
        ai_results = pd.read_csv('beacon_analysis_results.csv')
        print(f"AI Analysis found {len(ai_results)} connections")
        
        high_confidence_beacons = ai_results[ai_results['beacon_score'] > 70]
        print(f"High confidence beacons: {len(high_confidence_beacons)}")
        
        for idx, beacon in high_confidence_beacons.iterrows():
            print(f"  {beacon['connection']} - Score: {beacon['beacon_score']:.2f}")
            
    except FileNotFoundError:
        print("AI results not found. Run ai_feature_extractor.py first.")
    
    # Run RITA analysis
    rita_output = run_rita_analysis()
    
    return rita_output

def generate_final_report():
    """Generate final comprehensive report"""
    print("\n" + "="*60)
    print("COMPREHENSIVE C2 BEACON DETECTION REPORT")
    print("="*60)
    print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    correlate_results()
    
    print("\nRECOMMENDATIONS:")
    print("-" * 20)
    print("1. Investigate high-scoring beacon connections")
    print("2. Check destination IPs against threat intelligence")
    print("3. Monitor identified patterns for persistence")
    print("4. Implement network segmentation for suspicious hosts")
    print("5. Set up continuous monitoring for detected patterns")

if __name__ == "__main__":
    generate_final_report()
