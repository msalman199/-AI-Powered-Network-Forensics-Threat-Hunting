#!/usr/bin/env python3
import json
import pandas as pd
from datetime import datetime

def correlate_detections():
    """Correlate Sigma and ML detections"""
    print("=== Detection Correlation Analysis ===")
    
    # Load events
    events = []
    with open('sample_events.json', 'r') as f:
        for line in f:
            events.append(json.loads(line.strip()))
    
    df = pd.DataFrame(events)
    
    # Define high-risk indicators
    high_risk_processes = ['powershell.exe', 'mimikatz.exe', 'net.exe']
    high_risk_commands = ['-enc', 'sekurlsa', 'administrator', '/active:yes']
    
    # Score events
    df['risk_score'] = 0
    
    for idx, row in df.iterrows():
        score = 0
        
        # Process-based scoring
        if row.get('process_name') in high_risk_processes:
            score += 3
        
        # Command-based scoring
        command = row.get('command_line', '').lower()
        for indicator in high_risk_commands:
            if indicator.lower() in command:
                score += 2
        
        # User-based scoring
        if row.get('user') == 'administrator':
            score += 2
        
        df.at[idx, 'risk_score'] = score
    
    # Classify risk levels
    df['risk_level'] = df['risk_score'].apply(lambda x: 
        'CRITICAL' if x >= 7 else
        'HIGH' if x >= 5 else
        'MEDIUM' if x >= 3 else
        'LOW'
    )
    
    # Generate correlation report
    print(f"\nRisk Distribution:")
    print(df['risk_level'].value_counts())
    
    print(f"\nHigh-Risk Events (CRITICAL/HIGH):")
    high_risk = df[df['risk_level'].isin(['CRITICAL', 'HIGH'])]
    
    for idx, event in high_risk.iterrows():
        print(f"\nEvent {idx + 1} - {event['risk_level']} RISK (Score: {event['risk_score']}):")
        print(f"  Process: {event.get('process_name', 'N/A')}")
        print(f"  Command: {event.get('command_line', 'N/A')}")
        print(f"  User: {event.get('user', 'N/A')}")
        print(f"  Timestamp: {event.get('timestamp', 'N/A')}")
    
    # ATT&CK technique mapping
    print(f"\n=== ATT&CK Technique Mapping ===")
    technique_mapping = {
        'powershell.exe': 'T1059.001 - PowerShell',
        'mimikatz.exe': 'T1003.001 - LSASS Memory',
        'net.exe': 'T1078 - Valid Accounts'
    }
    
    detected_techniques = set()
    for _, event in high_risk.iterrows():
        process = event.get('process_name', '')
        if process in technique_mapping:
            detected_techniques.add(technique_mapping[process])
    
    for technique in detected_techniques:
        print(f"  - {technique}")
    
    # Save results
    df.to_csv('correlation_results.csv', index=False)
    print(f"\nCorrelation results saved to correlation_results.csv")

if __name__ == "__main__":
    correlate_detections()
