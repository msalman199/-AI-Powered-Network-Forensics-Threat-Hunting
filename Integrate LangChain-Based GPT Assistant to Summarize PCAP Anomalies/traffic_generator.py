#!/usr/bin/env python3
import subprocess
import time
import threading

def generate_normal_traffic():
    """Generate normal web traffic"""
    commands = [
        "curl -s http://httpbin.org/get > /dev/null",
        "curl -s http://httpbin.org/post -d 'data=test' > /dev/null",
        "nslookup google.com > /dev/null",
        "ping -c 3 8.8.8.8 > /dev/null"
    ]
    
    for cmd in commands:
        subprocess.run(cmd, shell=True)
        time.sleep(2)

def generate_suspicious_traffic():
    """Generate suspicious-looking traffic patterns"""
    # Port scanning simulation
    for port in [22, 23, 80, 443, 3389]:
        subprocess.run(f"timeout 1 nc -z 192.168.1.1 {port} 2>/dev/null", shell=True)
        time.sleep(0.5)
    
    # Rapid DNS queries
    domains = ["malicious-domain.com", "suspicious-site.net", "bad-actor.org"]
    for domain in domains:
        subprocess.run(f"nslookup {domain} 2>/dev/null", shell=True)
        time.sleep(1)

if __name__ == "__main__":
    print("Generating network traffic...")
    
    # Run normal traffic
    normal_thread = threading.Thread(target=generate_normal_traffic)
    normal_thread.start()
    
    time.sleep(5)
    
    # Run suspicious traffic
    suspicious_thread = threading.Thread(target=generate_suspicious_traffic)
    suspicious_thread.start()
    
    normal_thread.join()
    suspicious_thread.join()
    
    print("Traffic generation complete")
