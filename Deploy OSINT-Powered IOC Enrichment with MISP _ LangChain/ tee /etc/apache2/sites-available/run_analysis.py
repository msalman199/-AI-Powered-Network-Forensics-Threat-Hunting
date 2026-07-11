#!/usr/bin/env python3
import subprocess
import sys
import time

def run_script(script_name, description):
    """Run a Python script and handle errors"""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run([sys.executable, script_name], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(result.stdout)
            print(f"✓ {description} completed successfully")
        else:
            print(f"✗ Error in {description}:")
            print(result.stderr)
            
    except subprocess.TimeoutExpired:
        print(f"✗ {description} timed out")
    except Exception as e:
        print(f"✗ Exception in {description}: {e}")

def main():
    print("OSINT-Powered IOC Enrichment Analysis Pipeline")
    print("=" * 60)
    
    # Run analysis scripts in sequence
    scripts = [
        ("ioc_enrichment.py", "IOC Enrichment with OSINT"),
        ("misp_integration.py", "MISP Integration Test"),
        ("detection_analysis.py", "Detection Opportunity Analysis")
    ]
    
    for script, description in scripts:
        run_script(script, description)
        time.sleep(2)  # Brief pause between scripts
    
    print(f"\n{'='*60}")
    print("Analysis Pipeline Complete!")
    print("Review the output above for enrichment results and detection opportunities.")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
