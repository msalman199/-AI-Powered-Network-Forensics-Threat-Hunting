import json
import os
from datetime import datetime

def verify_files_exist():
    required_files = [
        "../data/sample_alerts.json",
        "../data/triaged_alerts.json", 
        "../data/gpt_enhanced_alerts.json",
        "../logs/performance_report.json"
    ]
    
    print("🔍 Verifying Pipeline Files...")
    all_exist = True
    
    for file_path in required_files:
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            print(f"   ✅ {file_path} ({size} bytes)")
        else:
            print(f"   ❌ {file_path} - MISSING")
            all_exist = False
    
    return all_exist

def verify_data_integrity():
    print("\n🔍 Verifying Data Integrity...")
    
    try:
        # Check sample alerts
        with open("../data/sample_alerts.json", "r") as f:
            sample_alerts = json.load(f)
        print(f"   ✅ Sample alerts: {len(sample_alerts)} records")
        
        # Check triaged alerts
        with open("../data/triaged_alerts.json", "r") as f:
            triaged_alerts = json.load(f)
        print(f"   ✅ Triaged alerts: {len(triaged_alerts)} records")
        
        # Check enhanced alerts
        with open("../data/gpt_enhanced_alerts.json", "r") as f:
            enhanced_alerts = json.load(f)
        print(f"   ✅ GPT enhanced alerts: {len(enhanced_alerts)} records")
        
        # Verify data flow
        if len(enhanced_alerts) <= len(triaged_alerts) <= len(sample_alerts):
            print("   ✅ Data flow integrity maintained")
            return True
        else:
            print("   ❌ Data flow integrity issue detected")
            return False
            
    except Exception as e:
        print(f"   ❌ Data integrity check failed: {e}")
        return False

def verify_performance_metrics():
    print("\n🔍 Verifying Performance Metrics...")
    
    try:
        with open("../logs/performance_report.json", "r") as f:
            report = json.load(f)
        
        required_metrics = ['accuracy', 'precision', 'recall', 'f1_score']
        classification_perf = report.get('classification_performance', {})
        
        for metric in required_metrics:
            if metric in classification_perf:
                value = classification_perf[metric]
                print(f"   ✅ {metric.capitalize()}: {value}")
            else:
                print(f"   ❌ Missing metric: {metric}")
                return False
        
        return True
        
    except Exception as e:
        print(f"   ❌ Performance metrics verification failed: {e}")
        return False

def main():
    print("=" * 50)
    print("    ALERT TRIAGE PIPELINE VERIFICATION")
    print("=" * 50)
    
    files_ok = verify_files_exist()
    data_ok = verify_data_integrity()
    metrics_ok = verify_performance_metrics()
    
    print(f"\n📋 VERIFICATION SUMMARY")
    print(f"   Files: {'✅ PASS' if files_ok else '❌ FAIL'}")
    print(f"   Data Integrity: {'✅ PASS' if data_ok else '❌ FAIL'}")
    print(f"   Performance Metrics: {'✅ PASS' if metrics_ok else '❌ FAIL'}")
    
    if all([files_ok, data_ok, metrics_ok]):
        print(f"\n🎉 PIPELINE VERIFICATION: ✅ SUCCESS")
        print("   All components are working correctly!")
    else:
        print(f"\n⚠️  PIPELINE VERIFICATION: ❌ ISSUES DETECTED")
        print("   Please review the failed components above.")
    
    print("=" * 50)

if __name__ == "__main__":
    main()
