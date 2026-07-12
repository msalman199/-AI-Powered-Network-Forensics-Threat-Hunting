#!/usr/bin/env python3
import requests
import time
import random
import threading
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def generate_normal_traffic():
    """Generate normal web traffic"""
    sites = [
        'https://httpbin.org/get',
        'https://httpbin.org/json',
        'https://httpbin.org/user-agent'
    ]
    
    for _ in range(10):
        try:
            site = random.choice(sites)
            response = requests.get(site, verify=False, timeout=5)
            print(f"Normal traffic: {site} - Status: {response.status_code}")
            time.sleep(random.uniform(1, 3))
        except:
            pass

def generate_c2_traffic():
    """Generate suspicious C2-like traffic"""
    c2_patterns = [
        {'url': 'https://httpbin.org/post', 'data': {'cmd': 'whoami', 'id': '12345'}},
        {'url': 'https://httpbin.org/post', 'data': {'beacon': 'alive', 'host': 'target1'}},
        {'url': 'https://httpbin.org/post', 'data': {'download': 'payload.exe', 'key': 'abc123'}}
    ]
    
    for pattern in c2_patterns:
        try:
            response = requests.post(pattern['url'], json=pattern['data'], verify=False, timeout=5)
            print(f"C2 traffic: {pattern['url']} - Status: {response.status_code}")
            time.sleep(random.uniform(5, 10))
        except:
            pass

if __name__ == "__main__":
    # Run both traffic types concurrently
    normal_thread = threading.Thread(target=generate_normal_traffic)
    c2_thread = threading.Thread(target=generate_c2_traffic)
    
    normal_thread.start()
    c2_thread.start()
    
    normal_thread.join()
    c2_thread.join()
