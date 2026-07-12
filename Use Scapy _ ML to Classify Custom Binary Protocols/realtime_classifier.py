from scapy.all import *
import joblib
import numpy as np
import pandas as pd
from collections import Counter
import time

class RealtimeProtocolClassifier:
    def __init__(self, model_file, scaler_file, encoder_file):
        """Initialize the real-time classifier"""
        print("Loading trained model...")
        self.model = joblib.load(model_file)
        self.scaler = joblib.load(scaler_file)
        self.label_encoder = joblib.load(encoder_file)
        
        self.classification_results = []
        self.packet_count = 0
        
        print(f"Model loaded successfully!")
        print(f"Can classify: {self.label_encoder.classes_}")
    
    def extract_packet_features(self, packet):
        """Extract features from a single packet (same as training)"""
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
            
            # Check for magic bytes
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
        """Calculate Shannon entropy"""
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
    
    def classify_packet(self, packet):
        """Classify a single packet"""
        try:
            # Extract features
            features = self.extract_packet_features(packet)
            
            # Convert to array and handle NaN
            feature_array = np.array(list(features.values())).reshape(1, -1)
            feature_array = np.nan_to_num(feature_array)
            
            # Scale features
            feature_scaled = self.scaler.transform(feature_array)
            
            # Make prediction
            prediction = self.model.predict(feature_scaled)[0]
            probability = self.model.predict_proba(feature_scaled)[0]
            
            # Convert prediction back to label
            protocol_label = self.label_encoder.inverse_transform([prediction])[0]
            confidence = np.max(probability)
            
            return protocol_label, confidence, features
            
        except Exception as e:
            print(f"Error classifying packet: {e}")
            return "Unknown", 0.0, {}
    
    def packet_handler(self, packet):
        """Handle each captured packet"""
        self.packet_count += 1
        
        # Only process packets with payload
        if not packet.haslayer(Raw):
            return
        
        # Classify packet
        protocol, confidence, features = self.classify_packet(packet)
        
        # Store result
        result = {
            'packet_num': self.packet_count,
            'timestamp': time.time(),
            'protocol': protocol,
            'confidence': confidence,
            'src_port': features.get('src_port', 0),
            'dst_port': features.get('dst_port', 0),
            'payload_len': features.get('payload_len', 0)
        }
        
        self.classification_results.append(result)
        
        # Print real-time results
        if confidence > 0.7:  # Only show high-confidence predictions
            print(f"Packet {self.packet_count}: {protocol} "
                  f"(confidence: {confidence:.3f}) "
                  f"Port: {features.get('src_port', 0)}->{features.get('dst_port', 0)} "
                  f"Payload: {features.get('payload_len', 0)} bytes")
    
    def start_realtime_classification(self, interface="lo", duration=30):
        """Start real-time packet classification"""
        print(f"\nStarting real-time classification on {interface}...")
        print(f"Duration: {duration} seconds")
        print("=" * 60)
        
        # Start packet capture with our handler
        sniff(iface=interface, prn=self.packet_handler, timeout=duration,
              filter="tcp or udp")
        
        print("=" * 60)
        print(f"Classification completed! Processed {self.packet_count} packets")
        
        # Show summary
        self.show_classification_summary()
    
    def show_classification_summary(self):
        """Show classification summary"""
        if not self.classification_results:
            print("No classification results to show")
            return
        
        df = pd.DataFrame(self.classification_results)
        
        print("\n=== Classification Summary ===")
        print(f"Total packets classified: {len(df)}")
        
        # Protocol distribution
        print("\nProtocol Distribution:")
        protocol_counts = df['protocol'].value_counts()
        for protocol, count in protocol_counts.items():
            percentage = (count / len(df)) * 100
            print(f"  {protocol}: {count} packets ({percentage:.1f}%)")
        
        # Average confidence by protocol
        print("\nAverage Confidence by Protocol:")
        confidence_by_protocol = df.groupby('protocol')['confidence'].mean()
        for protocol, conf in confidence_by_protocol.items():
            print(f"  {protocol}: {conf:.3f}")
        
        # High confidence predictions
        high_conf = df[df['confidence'] > 0.8]
        print(f"\nHigh confidence predictions (>0.8): {len(high_conf)}/{len(df)} "
              f"({len(high_conf)/len(df)*100:.1f}%)")
        
        # Save results
        df.to_csv("realtime_classification_results.csv", index=False)
        print("\nResults saved to: realtime_classification_results.csv")

def test_with_new_traffic():
    """Generate new test traffic and classify it"""
    print("Generating new test traffic...")
    
    # Import and run protocol simulators
    import subprocess
    import threading
    
    def run_test_protocols():
        subprocess.run(["python3", "protocol_simulators.py"])
    
    # Start test traffic in background
    traffic_thread = threading.Thread(target=run_test_protocols)
    traffic_thread.start()
    
    # Wait for servers to start
    time.sleep(2)
    
    # Start real-time classification
    classifier = RealtimeProtocolClassifier(
        "protocol_classifier_random_forest.joblib",
        "feature_scaler.joblib", 
        "label_encoder.joblib"
    )
    
    classifier.start_realtime_classification(duration=25)
    
    # Wait for traffic generation to complete
    traffic_thread.join()

if __name__ == "__main__":
    test_with_new_traffic()
