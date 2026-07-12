import pandas as pd
import json
from datetime import datetime, timedelta
import re

class APTHunter:
    def __init__(self):
        self.apt_indicators = {
            'lateral_movement': [
                r'psexec',
                r'wmic.*process.*call.*create',
                r'net\s+use.*\$',
                r'powershell.*invoke-command'
            ],
            'persistence': [
                r'schtasks.*create',
                r'reg.*add.*run',
                r'wmic.*startup',
                r'service.*create'
            ],
            'data_exfiltration': [
                r'copy.*\\\\',
                r'xcopy.*network',
                r'ftp.*put',
                r'curl.*upload'
            ],
            'command_control': [
                r'powershell.*-enc',
                r'certutil.*decode',
                r'bitsadmin.*transfer',
                r'wget.*http'
            ]
        }
    
    def analyze_timeline(self, events_df):
        """Analyze events for APT behavior patterns"""
        results = {
            'suspicious_sequences': [],
            'apt_indicators': [],
            'timeline_analysis': {}
        }
        
        # Sort events by timestamp
        events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
        events_df = events_df.sort_values('timestamp')
        
        # Look for APT indicators
        for category, patterns in self.apt_indicators.items():
            for pattern in patterns:
                matches = events_df[events_df['message'].str.contains(pattern, case=False, na=False)]
                if not matches.empty:
                    for _, match in matches.iterrows():
                        results['apt_indicators'].append({
                            'category': category,
                            'pattern': pattern,
                            'timestamp': str(match['timestamp']),
                            'message': match['message'],
                            'user': match.get('user', 'unknown'),
                            'host': match.get('host', 'unknown')
                        })
        
        # Analyze suspicious sequences (multiple APT activities within short timeframe)
        apt_events = pd.DataFrame(results['apt_indicators'])
        if not apt_events.empty:
            apt_events['timestamp'] = pd.to_datetime(apt_events['timestamp'])
            
            # Group events within 1-hour windows
            for i, event in apt_events.iterrows():
                window_start = event['timestamp']
                window_end = window_start + timedelta(hours=1)
                
                window_events = apt_events[
                    (apt_events['timestamp'] >= window_start) & 
                    (apt_events['timestamp'] <= window_end)
                ]
                
                if len(window_events) >= 3:  # 3+ APT indicators in 1 hour
                    sequence = {
                        'start_time': str(window_start),
                        'end_time': str(window_end),
                        'event_count': len(window_events),
                        'categories': list(window_events['category'].unique()),
                        'events': window_events.to_dict('records')
                    }
                    
                    # Avoid duplicates
                    if sequence not in results['suspicious_sequences']:
                        results['suspicious_sequences'].append(sequence)
        
        # Timeline analysis summary
        results['timeline_analysis'] = {
            'total_events': len(events_df),
            'apt_indicators_found': len(results['apt_indicators']),
            'suspicious_sequences': len(results['suspicious_sequences']),
            'time_range': {
                'start': str(events_df['timestamp'].min()),
                'end': str(events_df['timestamp'].max())
            }
        }
        
        return results
    
    def generate_hunt_report(self, hunt_results):
        """Generate comprehensive APT hunting report"""
        report = {
            'executive_summary': {},
            'detailed_findings': hunt_results,
            'recommendations': []
        }
        
        # Executive summary
        total_indicators = hunt_results['timeline_analysis']['apt_indicators_found']
        suspicious_sequences = hunt_results['timeline_analysis']['suspicious_sequences']
        
        if total_indicators > 0:
            report['executive_summary']['risk_level'] = 'HIGH' if suspicious_sequences > 0 else 'MEDIUM'
            report['executive_summary']['key_findings'] = [
                f"{total_indicators} APT indicators detected",
                f"{suspicious_sequences} suspicious activity sequences identified"
            ]
        else:
            report['executive_summary']['risk_level'] = 'LOW'
            report['executive_summary']['key_findings'] = ["No significant APT indicators detected"]
        
        # Recommendations
        if suspicious_sequences > 0:
            report['recommendations'].extend([
                "Immediate investigation of suspicious activity sequences required",
                "Review user accounts involved in flagged activities",
                "Implement additional monitoring on affected systems"
            ])
        elif total_indicators > 0:
            report['recommendations'].extend([
                "Monitor flagged activities for escalation",
                "Review security policies and access controls"
            ])
        else:
            report['recommendations'].append("Continue regular monitoring and threat hunting activities")
        
        return report

if __name__ == "__main__":
    hunter = APTHunter()
    
    # Load and analyze security events
    print("Loading security events for APT hunting...")
    
    # Combine all security data
    windows_events = pd.read_csv('/home/ubuntu/security_logs/windows_security.csv')
    
    # Add some synthetic APT-like events for demonstration
    apt_events = pd.DataFrame([
        {
            'timestamp': '2024-01-15T09:18:00Z',
            'event_id': 4688,
            'source': 'Security',
            'message': 'Process creation: psexec.exe \\\\target cmd.exe',
            'user': 'admin',
            'host': 'workstation01'
        },
        {
            'timestamp': '2024-01-15T09:19:15Z',
            'event_id': 4688,
            'source': 'Security',
            'message': 'Process creation: powershell.exe -enc SGVsbG8gV29ybGQ=',
            'user': 'admin',
            'host': 'workstation01'
        },
        {
            'timestamp': '2024-01-15T09:20:30Z',
            'event_id': 4688,
            'source': 'Security',
            'message': 'schtasks /create /tn "WindowsUpdate" /tr "malware.exe"',
            'user': 'admin',
            'host': 'workstation01'
        }
    ])
    
    # Combine events
    all_events = pd.concat([windows_events, apt_events], ignore_index=True)
    
    # Perform APT hunting
    print("Performing APT hunting analysis...")
    hunt_results = hunter.analyze_timeline(all_events)
    
    # Generate report
    report = hunter.generate_hunt_report(hunt_results)
    
    # Display results
    print(f"\n=== APT HUNTING REPORT ===")
    print(f"Risk Level: {report['executive_summary']['risk_level']}")
    print(f"APT Indicators Found: {hunt_results['timeline_analysis']['apt_indicators_found']}")
    print(f"Suspicious Sequences: {hunt_results['timeline_analysis']['suspicious_sequences']}")
    
    if hunt_results['apt_indicators']:
        print(f"\nDetected APT Indicators:")
        for indicator in hunt_results['apt_indicators']:
            print(f"  - {indicator['category']}: {indicator['message']}")
    
    if hunt_results['suspicious_sequences']:
        print(f"\nSuspicious Activity Sequences:")
        for seq in hunt_results['suspicious_sequences']:
            print(f"  - {seq['event_count']} events from {seq['start_time']} to {seq['end_time']}")
            print(f"    Categories: {', '.join(seq['categories'])}")
    
    print(f"\nRecommendations:")
    for rec in report['recommendations']:
        print(f"  - {rec}")
    
    # Save detailed report
    with open('apt_hunt_report.json', 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\nDetailed report saved to apt_hunt_report.json")
