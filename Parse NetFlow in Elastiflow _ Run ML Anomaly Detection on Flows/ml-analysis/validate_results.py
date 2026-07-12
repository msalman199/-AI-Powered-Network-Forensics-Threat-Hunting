#!/usr/bin/env python3
import os
import json

def validate_lab_completion():
    checks = {
        'Docker services': False,
        'NetFlow data generation': False,
        'ML analysis': False,
        'Pattern analysis': False,
        'Visualization': False
    }
    
    # Check if Docker containers are running
    if os.system('docker-compose ps | grep -q "Up"') == 0:
        checks['Docker services'] = True
    
    # Check if NetFlow simulator exists and is executable
    if os.path.exists('netflow_simulator.py') and os.access('netflow_simulator.py', os.X_OK):
        checks['NetFlow data generation'] = True
    
    # Check if ML analysis script exists
    if os.path.exists('anomaly_detector.py'):
        checks['ML analysis'] = True
    
    # Check if pattern analysis script exists
    if os.path.exists('flow_pattern_analyzer.py'):
        checks['Pattern analysis'] = True
    
    # Check if visualization was created
    if os.path.exists('netflow_anomaly_analysis.png'):
        checks['Visualization'] = True
    
    print("Lab Completion Validation:")
    print("=" * 40)
    for check, status in checks.items():
        status_symbol = "✓" if status else "✗"
        print(f"{status_symbol} {check}")
    
    completion_rate = sum(checks.values()) / len(checks) * 100
    print(f"\nOverall completion: {completion_rate:.0f}%")
    
    if completion_rate == 100:
        print("🎉 Lab completed successfully!")
    else:
        print("⚠️  Some components need attention")

if __name__ == "__main__":
    validate_lab_completion()
