#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd
import sys
from mitmproxy import io, http
from mitmproxy.exceptions import FlowReadException
import numpy as np

def load_and_analyze_flows(flow_file):
    """Load flows and create visualizations"""
    flows = []
    
    try:
        with open(flow_file, "rb") as logfile:
            freader = io.FlowReader(logfile)
            for flow in freader.stream():
                if isinstance(flow, http.HTTPFlow):
                    flows.append(flow)
    except FlowReadException as e:
        print(f"Error loading flows: {e}")
        return
    
    if not flows:
        print("No flows found")
        return
    
    # Extract data for visualization
    data = []
    for flow in flows:
        data.append({
            'method': flow.request.method,
            'status_code': flow.response.status_code if flow.response else 0,
            'request_size': len(flow.request.raw_content) if flow.request.raw_content else 0,
            'response_size': len(flow.response.raw_content) if flow.response and flow.response.raw_content else 0,
            'url': flow.request.pretty_url,
            'has_json': 'application/json' in flow.request.headers.get('content-type', ''),
            'is_post': flow.request.method == 'POST'
        })
    
    df = pd.DataFrame(data)
    
    # Create visualizations
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle('Traffic Analysis Dashboard', fontsize=16)
    
    # 1. Request methods distribution
    method_counts = df['method'].value_counts()
    axes[0, 0].pie(method_counts.values, labels=method_counts.index, autopct='%1.1f%%')
    axes[0, 0].set_title('HTTP Methods Distribution')
    
    # 2. Request vs Response sizes
    axes[0, 1].scatter(df['request_size'], df['response_size'], alpha=0.6)
    axes[0, 1].set_xlabel('Request Size (bytes)')
    axes[0, 1].set_ylabel('Response Size (bytes)')
    axes[0, 1].set_title('Request vs Response Size')
    
    # 3. Status codes distribution
    status_counts = df['status_code'].value_counts()
    axes[1, 0].bar(range(len(status_counts)), status_counts.values)
    axes[1, 0].set_xticks(range(len(status_counts)))
    axes[1, 0].set_xticklabels(status_counts.index, rotation=45)
    axes[1, 0].set_title('HTTP Status Codes')
    axes[1, 0].set_ylabel('Count')
    
    # 4. POST vs GET traffic analysis
    post_data = df[df['is_post']]
    get_data = df[~df['is_post']]
    
    axes[1, 1].hist([post_data['request_size'], get_data['request_size']], 
                   bins=20, alpha=0.7, label=['POST', 'GET'])
    axes[1, 1].set_xlabel('Request Size (bytes)')
    axes[1, 1].set_ylabel('Frequency')
    axes[1, 1].set_title('Request Size Distribution by Method')
    axes[1, 1].legend()
    
    plt.tight_layout()
    plt.savefig('traffic_analysis.png', dpi=150, bbox_inches='tight')
    print("Traffic visualization saved as 'traffic_analysis.png'")
    
    # Print summary statistics
    print("\n" + "="*50)
    print("TRAFFIC ANALYSIS SUMMARY")
    print("="*50)
    print(f"Total Flows: {len(df)}")
    print(f"POST Requests: {len(post_data)} ({len(post_data)/len(df)*100:.1f}%)")
    print(f"JSON Requests: {df['has_json'].sum()} ({df['has_json'].sum()/len(df)*100:.1f}%)")
    print(f"Average Request Size: {df['request_size'].mean():.1f} bytes")
    print(f"Average Response Size: {df['response_size'].mean():.1f} bytes")
    
    # Identify potential C2 characteristics
    suspicious_indicators = 0
    if len(post_data) / len(df) > 0.3:  # High POST ratio
        print("⚠️  High POST request ratio detected")
        suspicious_indicators += 1
    
    if df['has_json'].sum() / len(df) > 0.2:  # High JSON usage
        print("⚠️  High JSON content ratio detected")
        suspicious_indicators += 1
    
    large_requests = df[df['request_size'] > df['request_size'].quantile(0.9)]
    if len(large_requests) > 0:
        print(f"⚠️  {len(large_requests)} unusually large requests detected")
        suspicious_indicators += 1
    
    print(f"\nSuspicious Indicators Found: {suspicious_indicators}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 visualize_traffic.py <mitm_flow_file>")
        sys.exit(1)
    
    load_and_analyze_flows(sys.argv[1])
