#!/usr/bin/env python3
import subprocess
import time
import random
import string

def generate_normal_dns():
    """Generate normal DNS queries"""
    normal_domains = [
        "google.com", "facebook.com", "amazon.com", "microsoft.com",
        "apple.com", "netflix.com", "twitter.com", "linkedin.com"
    ]
    
    for domain in normal_domains:
        subprocess.run(['dig', '+short', domain], capture_output=True)
        time.sleep(0.5)

def generate_tunneling_dns():
    """Generate DNS tunneling-like queries with high entropy"""
    base_domain = "tunnel.example.com"
    
    for _ in range(10):
        # Generate high-entropy subdomain
        random_data = ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
        tunneling_query = f"{random_data}.{base_domain}"
        
        # Simulate DNS query (will fail but generate traffic)
        subprocess.run(['dig', '+short', tunneling_query], capture_output=True)
        time.sleep(0.3)

if __name__ == "__main__":
    print("Generating normal DNS traffic...")
    generate_normal_dns()
    
    print("Generating tunneling-like DNS traffic...")
    generate_tunneling_dns()
    
    print("Traffic generation complete!")
