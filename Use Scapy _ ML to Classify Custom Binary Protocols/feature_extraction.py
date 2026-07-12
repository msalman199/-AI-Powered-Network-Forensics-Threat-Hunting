from scapy.all import *
import pandas as pd
import numpy as np
from collections import Counter

class ProtocolFeatureExtractor:
    def __init__(self, pcap_file):
        self.packets = rdpcap(pcap_file)
        self.features = []
    
    def extract_packet_features(self, packet):
        """Extract features from a single packet"""
        features = {}
        
        # Basic packet information
        features['packet_size'] = len(packet)
        features['has_tcp'] = 1 if packet.haslayer(TCP) else 0
        features['has_udp'] = 1 if packet.haslayer(UDP) else 0
        features['has_ip'] = 1 if packet.haslayer(IP) else 0
        
        if packet.haslayer(IP):
            features['ip_len'] = packet[IP].len
            features['ip_ttl'] = packet[IP].ttl
            features['ip_proto'] = packet[IP].proto
        else:
            features['ip_len'] = 0
            features['ip_ttl'] = 0
            features['ip_proto'] = 0
        
        if packet.haslayer(TCP):
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            features['tcp_flags'] = packet[TCP].flags
            features['tcp_window'] = packet[TCP].window
            features['tcp_seq'] = packet[TCP].seq
        elif packet.haslayer(UDP):
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport
            features['tcp_flags'] = 0
            features['tcp_window'] = 0
            features['tcp_seq'] = 0
        else:
            features['src_port'] = 0
            features['dst_port'] = 0
            features['tcp_flags'] = 0
            features['tcp_window'] = 0
            features['tcp_seq'] = 0
        
        # Payload analysis
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            features['payload_len'] = len(payload)
            features['payload_entropy'] = self.calculate_entropy(payload)
            features['payload_mean'] = np.mean(list(payload)) if payload else 0
            features['payload_std'] = np.std(list(payload)) if len(payload) > 1 else 0
            
            # Check for common magic bytes/patterns
            features['has_magic_abcd'] = 1 if b'\xab\xcd' in payload[:10] else 0
            features['has_magic_1234'] = 1 if b'\x12\x34\x56\x78' in payload[:10] else 0
            features['has_magic_dead'] = 1 if b'\xde\xad' in payload[:10] else 0
            
            # Byte frequency analysis
            if payload:
                byte_counts = Counter(payload)
                features['unique_bytes'] = len(byte_counts)
                features['most_common_byte_freq'] = byte_counts.most_common(1)[0][1] / len(payload)
            else:
                features['unique_bytes'] = 0
                features['most_common_byte_freq'] = 0
        else:
            features['payload_len'] = 0
            features['payload_entropy'] = 0
            features['payload_mean'] = 0
            features['payload_std'] = 0
            features['has_magic_abcd'] = 0
            features['has_magic_1234'] = 0
            features['has_magic_dead'] = 0
            features['unique_bytes'] = 0
            features['most_common_byte_freq'] = 0
        
        return features
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        byte_counts = Counter(data)
        entropy = 0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def extract_all_features(self):
        """Extract features from all packets"""
        print(f"Extracting features from {len(self.packets)} packets...")
        
        for i, packet in enumerate(self.packets):
            features = self.extract_packet_features(packet)
            features['packet_id'] = i
            self.features.append(features)
        
        return pd.DataFrame(self.features)
    
    def label_protocols(self, df):
        """Label protocols based on port patterns and magic bytes"""
        labels = []
        
        for _, row in df.iterrows():
            if row['has_magic_abcd'] == 1:
                labels.append('ProtocolA')
            elif row['has_magic_1234'] == 1:
                labels.append('ProtocolB')
            elif row['has_magic_dead'] == 1:
                labels.append('ProtocolC')
            elif row['dst_port'] == 8001 or row['src_port'] == 8001:
                labels.append('ProtocolA')
            elif row['dst_port'] == 8002 or row['src_port'] == 8002:
                labels.append('ProtocolB')
            elif row['dst_port'] == 8003 or row['src_port'] == 8003:
                labels.append('ProtocolC')
            else:
                labels.append('Unknown')
        
        df['protocol_label'] = labels
        return df

if __name__ == "__main__":
    # Extract features from captured traffic
    extractor = ProtocolFeatureExtractor("protocol_traffic.pcap")
    features_df = extractor.extract_all_features()
    
    # Label the protocols
    labeled_df = extractor.label_protocols(features_df)
    
    # Save features to CSV
    labeled_df.to_csv("protocol_features.csv", index=False)
    
    print("Feature extraction completed!")
    print(f"Extracted {len(labeled_df)} feature vectors")
    print("\nProtocol distribution:")
    print(labeled_df['protocol_label'].value_counts())
    
    # Display sample features
    print("\nSample features:")
    print(labeled_df.head())
