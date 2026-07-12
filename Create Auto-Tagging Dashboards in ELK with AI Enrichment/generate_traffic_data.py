import json
import random
import time
from datetime import datetime, timedelta
import socket

def generate_traffic_record():
    """Generate a realistic network traffic record"""
    protocols = ['TCP', 'UDP', 'ICMP']
    
    # Common port mappings for realistic traffic
    common_ports = {
        'web': [80, 443, 8080, 8443],
        'email': [25, 110, 143, 993, 995],
        'dns': [53],
        'ssh': [22],
        'ftp': [21, 22],
        'database': [3306, 5432, 1433, 27017]
    }
    
    # Generate realistic IP addresses
    src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
    dst_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
    
    # Select service type and corresponding port
    service_type = random.choice(list(common_ports.keys()))
    dst_port = random.choice(common_ports[service_type])
    src_port = random.randint(1024, 65535)
    
    protocol = random.choice(protocols)
    
    # Generate traffic characteristics based on service type
    if service_type == 'web':
        bytes_count = random.randint(500, 50000)
        packets = random.randint(5, 100)
        duration = random.uniform(0.1, 30.0)
    elif service_type == 'email':
        bytes_count = random.randint(1000, 10000000)
        packets = random.randint(10, 1000)
        duration = random.uniform(1.0, 300.0)
    elif service_type == 'dns':
        bytes_count = random.randint(50, 500)
        packets = random.randint(1, 5)
        duration = random.uniform(0.01, 1.0)
    else:
        bytes_count = random.randint(100, 100000)
        packets = random.randint(1, 500)
        duration = random.uniform(0.1, 60.0)
    
    # Occasionally generate suspicious traffic
    if random.random() < 0.05:  # 5% chance
        src_port = random.randint(60000, 65535)
        dst_port = random.randint(1, 1023)
        bytes_count = random.randint(100000, 1000000)
        packets = random.randint(1000, 10000)
        duration = random.uniform(0.01, 0.5)
    
    record = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "bytes": bytes_count,
        "packets": packets,
        "duration": round(duration, 3),
        "service_type": service_type
    }
    
    return record

# Generate continuous traffic data
print("Starting traffic data generation...")
with open('/var/log/network-traffic.log', 'w') as f:
    for i in range(1000):  # Generate 1000 initial records
        record = generate_traffic_record()
        f.write(json.dumps(record) + '\n')
        if i % 100 == 0:
            print(f"Generated {i} records...")
        time.sleep(0.1)  # Small delay to simulate real-time traffic

print("Initial traffic data generated. Continuing with real-time generation...")

# Continue generating data in real-time
while True:
    with open('/var/log/network-traffic.log', 'a') as f:
        record = generate_traffic_record()
        f.write(json.dumps(record) + '\n')
    time.sleep(random.uniform(1, 5))  # Random interval between 1-5 seconds
