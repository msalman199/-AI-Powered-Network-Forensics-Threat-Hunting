import numpy as np
import pandas as pd
from scapy.all import *
import time
import threading
import random

class TrafficGenerator:
    def __init__(self):
        self.normal_patterns = []
        self.anomaly_patterns = []
    
    def generate_normal_traffic(self, count=1000):
        """Generate normal encrypted traffic patterns"""
        normal_data = []
        
        for i in range(count):
            # Simulate normal HTTPS traffic characteristics
            packet_size = np.random.normal(1200, 300)  # Normal web traffic size
            inter_arrival_time = np.random.exponential(0.1)  # Normal timing
            flow_duration = np.random.normal(5.0, 1.5)  # Normal session duration
            bytes_per_second = packet_size / inter_arrival_time
            
            # Encrypted payload entropy (high for encrypted data)
            entropy = np.random.normal(7.8, 0.2)  # High entropy for encrypted
            
            normal_data.append([
                packet_size, inter_arrival_time, flow_duration, 
                bytes_per_second, entropy, 0  # 0 = normal
            ])
        
        return normal_data
    
    def generate_anomaly_traffic(self, count=100):
        """Generate anomalous encrypted traffic patterns"""
        anomaly_data = []
        
        for i in range(count):
            anomaly_type = random.choice(['exfiltration', 'c2', 'tunnel'])
            
            if anomaly_type == 'exfiltration':
                # Data exfiltration: large, consistent packets
                packet_size = np.random.normal(8000, 500)
                inter_arrival_time = np.random.normal(0.05, 0.01)  # Very regular
                flow_duration = np.random.normal(30.0, 5.0)  # Long sessions
                
            elif anomaly_type == 'c2':
                # Command & Control: small, regular beacons
                packet_size = np.random.normal(200, 50)
                inter_arrival_time = np.random.normal(60.0, 5.0)  # Regular beacons
                flow_duration = np.random.normal(1.0, 0.2)  # Short sessions
                
            else:  # tunnel
                # Tunneling: unusual size distribution
                packet_size = np.random.choice([100, 1500, 9000])  # Bimodal
                inter_arrival_time = np.random.exponential(0.01)
                flow_duration = np.random.normal(15.0, 8.0)
            
            bytes_per_second = packet_size / max(inter_arrival_time, 0.001)
            entropy = np.random.normal(7.9, 0.1)  # Still encrypted
            
            anomaly_data.append([
                packet_size, inter_arrival_time, flow_duration,
                bytes_per_second, entropy, 1  # 1 = anomaly
            ])
        
        return anomaly_data

# Generate dataset
generator = TrafficGenerator()
normal_traffic = generator.generate_normal_traffic(2000)
anomaly_traffic = generator.generate_anomaly_traffic(200)

# Combine and save dataset
all_traffic = normal_traffic + anomaly_traffic
columns = ['packet_size', 'inter_arrival_time', 'flow_duration', 
           'bytes_per_second', 'entropy', 'label']

df = pd.DataFrame(all_traffic, columns=columns)
df = df.sample(frac=1).reset_index(drop=True)  # Shuffle
df.to_csv('encrypted_traffic_dataset.csv', index=False)

print(f"Generated dataset with {len(df)} samples")
print(f"Normal traffic: {len(df[df['label']==0])}")
print(f"Anomalous traffic: {len(df[df['label']==1])}")
