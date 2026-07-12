#!/usr/bin/env python3
import os
from scapy.all import *
import random
import string
import base64

def generate_normal_traffic():
    """Generate normal HTTP traffic"""
    packets = []
    
    # Normal HTTP GET requests
    for i in range(50):
        pkt = IP(dst="192.168.1.100")/TCP(dport=80)/Raw(load=f"GET /page{i}.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        packets.append(pkt)
    
    return packets

def generate_obfuscated_traffic():
    """Generate obfuscated payload traffic"""
    packets = []
    
    # Base64 encoded payloads
    for i in range(30):
        payload = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
        encoded_payload = base64.b64encode(payload.encode()).decode()
        pkt = IP(dst="192.168.1.100")/TCP(dport=443)/Raw(load=f"POST /api HTTP/1.1\r\nContent-Length: {len(encoded_payload)}\r\n\r\n{encoded_payload}")
        packets.append(pkt)
    
    # Hex encoded payloads
    for i in range(20):
        payload = ''.join(random.choices('0123456789abcdef', k=200))
        pkt = IP(dst="192.168.1.100")/TCP(dport=8080)/Raw(load=f"POST /upload HTTP/1.1\r\nContent-Type: application/octet-stream\r\n\r\n{payload}")
        packets.append(pkt)
    
    return packets

# Generate and save PCAPs
normal_packets = generate_normal_traffic()
obfuscated_packets = generate_obfuscated_traffic()

# Save normal traffic
wrpcap("data/normal_traffic.pcap", normal_packets)
print("Generated normal_traffic.pcap with {} packets".format(len(normal_packets)))

# Save obfuscated traffic
wrpcap("data/obfuscated_traffic.pcap", obfuscated_packets)
print("Generated obfuscated_traffic.pcap with {} packets".format(len(obfuscated_packets)))

# Create mixed traffic for testing
mixed_packets = normal_packets[:25] + obfuscated_packets[:25]
random.shuffle(mixed_packets)
wrpcap("data/mixed_traffic.pcap", mixed_packets)
print("Generated mixed_traffic.pcap with {} packets".format(len(mixed_packets)))
