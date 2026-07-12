#!/usr/bin/env python3
import time
import requests
import threading
import random

def generate_beacon_traffic():
    """Generate periodic HTTP requests to simulate C2 beaconing"""
    targets = [
        "http://httpbin.org/get",
        "http://httpbin.org/user-agent",
        "http://httpbin.org/headers"
    ]
    
    for i in range(50):
        try:
            target = random.choice(targets)
            response = requests.get(target, timeout=5)
            print(f"Beacon {i+1}: {response.status_code} - {target}")
            time.sleep(random.uniform(58, 62))  # ~60 second intervals
        except Exception as e:
            print(f"Error in beacon {i+1}: {e}")
            time.sleep(60)

if __name__ == "__main__":
    generate_beacon_traffic()
