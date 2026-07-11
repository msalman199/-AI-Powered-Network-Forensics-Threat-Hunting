#!/usr/bin/env python3
import json
import yaml
import re

def load_sigma_rule(rule_file):
    """Load Sigma rule from YAML file"""
    with open(rule_file, 'r') as f:
        return yaml.safe_load(f)

def check_event_against_rule(event, rule):
    """Check if event matches Sigma rule"""
    detection = rule.get('detection', {})
    selection = detection.get('selection', {})
    
    matches = []
    
    # Check Image/process_name
    if 'Image|endswith' in selection:
        for pattern in selection['Image|endswith']:
            if event.get('process_name', '').endswith(pattern.replace('\\', '')):
                matches.append(f"Process name matches: {pattern}")
    
    # Check CommandLine
    if 'CommandLine|contains' in selection:
        for pattern in selection['CommandLine|contains']:
            if pattern.lower() in event.get('command_line', '').lower():
                matches.append(f"Command line contains: {pattern}")
    
    return matches

def analyze_events_with_sigma():
    """Analyze events using Sigma rules"""
    # Load events
    events = []
    with open('sample_events.json', 'r') as f:
        for line in f:
            events.append(json.loads(line.strip()))
    
    # Load rules
    rules = [
        ('powershell_encoded_command.yml', 'PowerShell Encoded Command'),
        ('admin_account_activation.yml', 'Admin Account Activation'),
        ('credential_dumping.yml', 'Credential Dumping')
    ]
    
    print("=== Sigma Rule Analysis Results ===")
    
    for rule_file, rule_name in rules:
        try:
            rule = load_sigma_rule(rule_file)
            print(f"\n--- {rule_name} ---")
            
            detections = 0
            for i, event in enumerate(events):
                matches = check_event_against_rule(event, rule)
                if matches:
                    detections += 1
                    print(f"Event {i+1} DETECTED:")
                    print(f"  Process: {event.get('process_name', 'N/A')}")
                    print(f"  Command: {event.get('command_line', 'N/A')}")
                    print(f"  Matches: {', '.join(matches)}")
                    print(f"  ATT&CK Tags: {', '.join(rule.get('tags', []))}")
            
            if detections == 0:
                print("No detections for this rule")
                
        except Exception as e:
            print(f"Error processing {rule_file}: {e}")

if __name__ == "__main__":
    analyze_events_with_sigma()
