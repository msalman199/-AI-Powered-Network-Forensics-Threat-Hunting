#!/usr/bin/env python3
import math
from collections import Counter
from scapy.all import *
import pandas as pd
import numpy as np

def calculate_entropy(data):
    """Calculate Shannon entropy of a string"""
    if len(data) == 0:
        return 0
    
    # Count frequency of each character
    counter = Counter(data)
    length = len(data)
    
    # Calculate entropy
    entropy = 0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def extract_dns_queries(pcap_file):
    """Extract DNS queries from pcap file"""
    dns_queries = []
    
    try:
        packets = rdpcap(pcap_file)
        
        for packet in packets:
            if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
                query_name = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                dns_queries.append(query_name)
    
    except Exception as e:
        print(f"Error reading pcap: {e}")
    
    return dns_queries

def analyze_dns_entropy(queries):
    """Analyze entropy of DNS queries"""
    results = []
    
    for query in queries:
        # Extract subdomain part (everything before the last two parts)
        parts = query.split('.')
        if len(parts) > 2:
            subdomain = '.'.join(parts[:-2])
        else:
            subdomain = parts[0] if parts else query
        
        entropy = calculate_entropy(subdomain)
        length = len(subdomain)
        
        results.append({
            'query': query,
            'subdomain': subdomain,
            'entropy': entropy,
            'length': length,
            'entropy_per_char': entropy / length if length > 0 else 0
        })
    
    return results

if __name__ == "__main__":
    # Extract DNS queries from captured traffic
    queries = extract_dns_queries('dns_traffic.pcap')
    
    if not queries:
        print("No DNS queries found in capture file")
        exit(1)
    
    # Analyze entropy
    results = analyze_dns_entropy(queries)
    
    # Create DataFrame
    df = pd.DataFrame(results)
    
    # Display results
    print("DNS Entropy Analysis Results:")
    print("=" * 50)
    print(df.to_string(index=False))
    
    # Save results
    df.to_csv('dns_entropy_results.csv', index=False)
    print(f"\nResults saved to dns_entropy_results.csv")
    
    # Basic statistics
    print(f"\nStatistics:")
    print(f"Average entropy: {df['entropy'].mean():.2f}")
    print(f"Max entropy: {df['entropy'].max():.2f}")
    print(f"Min entropy: {df['entropy'].min():.2f}")
    print(f"Std deviation: {df['entropy'].std():.2f}")
