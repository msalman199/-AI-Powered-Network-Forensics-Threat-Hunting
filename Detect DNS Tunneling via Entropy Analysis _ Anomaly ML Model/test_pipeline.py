#!/usr/bin/env python3
import subprocess
import os

def test_pipeline():
    """Test the complete DNS tunneling detection pipeline"""
    print("Testing DNS Tunneling Detection Pipeline")
    print("=" * 50)
    
    # Check if all required files exist
    required_files = [
        'dns_traffic_generator.py',
        'entropy_analyzer.py', 
        'ml_anomaly_detector.py',
        'pattern_analyzer.py'
    ]
    
    for file in required_files:
        if os.path.exists(file):
            print(f"✓ {file} exists")
        else:
            print(f"✗ {file} missing")
            return False
    
    # Test each component
    print("\nTesting components:")
    
    # Test traffic generation
    print("1. Testing traffic generation...")
    result = subprocess.run(['python3', 'dns_traffic_generator.py'], 
                          capture_output=True, text=True)
    if result.returncode == 0:
        print("✓ Traffic generation successful")
    else:
        print("✗ Traffic generation failed")
    
    # Test entropy analysis
    print("2. Testing entropy analysis...")
    if os.path.exists('dns_traffic.pcap'):
        result = subprocess.run(['python3', 'entropy_analyzer.py'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Entropy analysis successful")
        else:
            print("✗ Entropy analysis failed")
    
    # Test ML model
    print("3. Testing ML anomaly detection...")
    result = subprocess.run(['python3', 'ml_anomaly_detector.py'], 
                          capture_output=True, text=True)
    if result.returncode == 0:
        print("✓ ML model training successful")
    else:
        print("✗ ML model training failed")
    
    # Test pattern analysis
    print("4. Testing pattern analysis...")
    result = subprocess.run(['python3', 'pattern_analyzer.py'], 
                          capture_output=True, text=True)
    if result.returncode == 0:
        print("✓ Pattern analysis successful")
    else:
        print("✗ Pattern analysis failed")
    
    print("\nPipeline test complete!")
    return True

if __name__ == "__main__":
    test_pipeline()
