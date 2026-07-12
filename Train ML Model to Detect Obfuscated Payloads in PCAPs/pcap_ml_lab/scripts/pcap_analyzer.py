#!/usr/bin/env python3
import dpkt
import socket
import base64
import re
import pandas as pd
import numpy as np
from collections import Counter

class PCAPAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.features = []
    
    def extract_features(self):
        """Extract features from PCAP file"""
        with open(self.pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            
            for timestamp, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    
                    ip = eth.data
                    if not isinstance(ip.data, dpkt.tcp.TCP):
                        continue
                    
                    tcp = ip.data
                    if len(tcp.data) == 0:
                        continue
                    
                    payload = tcp.data
                    features = self.analyze_payload(payload)
                    features['src_ip'] = socket.inet_ntoa(ip.src)
                    features['dst_ip'] = socket.inet_ntoa(ip.dst)
                    features['src_port'] = tcp.sport
                    features['dst_port'] = tcp.dport
                    features['payload_length'] = len(payload)
                    
                    self.features.append(features)
                    
                except Exception as e:
                    continue
        
        return pd.DataFrame(self.features)
    
    def analyze_payload(self, payload):
        """Analyze payload for obfuscation indicators"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
        except:
            payload_str = str(payload)
        
        features = {}
        
        # Entropy calculation
        features['entropy'] = self.calculate_entropy(payload_str)
        
        # Base64 detection
        features['base64_ratio'] = self.detect_base64(payload_str)
        
        # Hex pattern detection
        features['hex_ratio'] = self.detect_hex_patterns(payload_str)
        
        # Character frequency analysis
        features['printable_ratio'] = self.calculate_printable_ratio(payload_str)
        
        # Compression ratio (simple heuristic)
        features['compression_ratio'] = len(payload_str) / max(len(set(payload_str)), 1)
        
        # Suspicious patterns
        features['suspicious_patterns'] = self.detect_suspicious_patterns(payload_str)
        
        return features
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        if len(data) == 0:
            return 0
        
        counter = Counter(data)
        length = len(data)
        entropy = 0
        
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
    
    def detect_base64(self, data):
        """Detect base64 encoded content"""
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{4,}={0,2}')
        matches = base64_pattern.findall(data)
        
        if not matches:
            return 0
        
        base64_chars = sum(len(match) for match in matches)
        return base64_chars / len(data)
    
    def detect_hex_patterns(self, data):
        """Detect hexadecimal patterns"""
        hex_pattern = re.compile(r'[0-9a-fA-F]{8,}')
        matches = hex_pattern.findall(data)
        
        if not matches:
            return 0
        
        hex_chars = sum(len(match) for match in matches)
        return hex_chars / len(data)
    
    def calculate_printable_ratio(self, data):
        """Calculate ratio of printable characters"""
        if len(data) == 0:
            return 0
        
        printable_count = sum(1 for c in data if c.isprintable())
        return printable_count / len(data)
    
    def detect_suspicious_patterns(self, data):
        """Detect suspicious patterns count"""
        patterns = [
            r'\\x[0-9a-fA-F]{2}',  # Hex escape sequences
            r'%[0-9a-fA-F]{2}',    # URL encoding
            r'&#x[0-9a-fA-F]+;',   # HTML hex entities
            r'\\u[0-9a-fA-F]{4}',  # Unicode escapes
        ]
        
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, data))
        
        return count

# Analyze sample files
if __name__ == "__main__":
    # Analyze normal traffic
    print("Analyzing normal traffic...")
    analyzer_normal = PCAPAnalyzer("data/normal_traffic.pcap")
    df_normal = analyzer_normal.extract_features()
    df_normal['label'] = 0  # Normal traffic
    
    # Analyze obfuscated traffic
    print("Analyzing obfuscated traffic...")
    analyzer_obfuscated = PCAPAnalyzer("data/obfuscated_traffic.pcap")
    df_obfuscated = analyzer_obfuscated.extract_features()
    df_obfuscated['label'] = 1  # Obfuscated traffic
    
    # Combine datasets
    df_combined = pd.concat([df_normal, df_obfuscated], ignore_index=True)
    
    # Save features
    df_combined.to_csv("data/extracted_features.csv", index=False)
    print(f"Extracted features saved. Total samples: {len(df_combined)}")
    print("\nFeature summary:")
    print(df_combined.describe())
