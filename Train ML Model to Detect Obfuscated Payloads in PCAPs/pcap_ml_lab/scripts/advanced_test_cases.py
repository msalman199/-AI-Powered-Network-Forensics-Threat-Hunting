#!/usr/bin/env python3
from scapy.all import *
import base64
import zlib
import random
import string

def create_advanced_obfuscation_samples():
    """Create advanced obfuscation test cases"""
    packets = []
    
    # 1. Multi-layer encoding (Base64 + URL encoding)
    payload1 = "SELECT * FROM users WHERE id=1"
    encoded1 = base64.b64encode(payload1.encode()).decode()
    url_encoded1 = encoded1.replace('+', '%2B').replace('/', '%2F').replace('=', '%3D')
    pkt1 = IP(dst="10.0.0.1")/TCP(dport=443)/Raw(load=f"POST /api HTTP/1.1\r\nContent-Length: {len(url_encoded1)}\r\n\r\n{url_encoded1}")
    packets.append(pkt1)
    
    # 2. Compressed + encoded payload
    payload2 = "powershell -enc " + "A" * 200
    compressed2 = zlib.compress(payload2.encode())
    encoded2 = base64.b64encode(compressed2).decode()
    pkt2 = IP(dst="10.0.0.2")/TCP(dport=8080)/Raw(load=f"POST /upload HTTP/1.1\r\n\r\n{encoded2}")
    packets.append(pkt2)
    
    # 3. Hex-encoded shellcode pattern
    shellcode = "\\x90" * 50 + "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68"
    pkt3 = IP(dst="10.0.0.3")/TCP(dport=4444)/Raw(load=shellcode)
    packets.append(pkt3)
    
    # 4. High entropy random data
    random_data = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=500))
    pkt4 = IP(dst="10.0.0.4")/TCP(dport=443)/Raw(load=f"POST /data HTTP/1.1\r\n\r\n{random_data}")
    packets.append(pkt4)
    
    # 5. Unicode escape sequences
    unicode_payload = "\\u0048\\u0065\\u006c\\u006c\\u006f\\u0020\\u0057\\u006f\\u0072\\u006c\\u0064"
    pkt5 = IP(dst="10.0.0.5")/TCP(dport=80)/Raw(load=f"GET /search?q={unicode_payload} HTTP/1.1\r\n\r\n")
    packets.append(pkt5)
    
    return packets

def create_evasion_samples():
    """Create samples designed to evade detection"""
    packets = []
    
    # 1. Low entropy but suspicious patterns
    pattern = "AAAA" + "B" * 100 + "CCCC"
    encoded_pattern = base64.b64encode(pattern.encode()).decode()
    pkt1 = IP(dst="192.168.1.50")/TCP(dport=443)/Raw(load=f"POST /api HTTP/1.1\r\n\r\n{encoded_pattern}")
    packets.append(pkt1)
    
    # 2. Mixed normal and obfuscated content
    normal_part = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
    obfuscated_part = base64.b64encode(b"hidden_payload").decode()
    mixed_payload = normal_part + f"X-Custom-Header: {obfuscated_part}\r\n\r\n"
    pkt2 = IP(dst="192.168.1.51")/TCP(dport=80)/Raw(load=mixed_payload)
    packets.append(pkt2)
    
    return packets

# Generate advanced test cases
print("Generating advanced obfuscation test cases...")
advanced_packets = create_advanced_obfuscation_samples()
evasion_packets = create_evasion_samples()

# Save test PCAPs
wrpcap("data/advanced_obfuscation.pcap", advanced_packets)
wrpcap("data/evasion_attempts.pcap", evasion_packets)

print(f"Generated advanced_obfuscation.pcap with {len(advanced_packets)} packets")
print(f"Generated evasion_attempts.pcap with {len(evasion_packets)} packets")

# Test with real-time detector
from real_time_detector import RealTimeDetector

detector = RealTimeDetector()
print("\nTesting advanced obfuscation samples:")
detector.analyze_pcap_file("data/advanced_obfuscation.pcap")

print("\nTesting evasion attempts:")
detector.analyze_pcap_file("data/evasion_attempts.pcap")
