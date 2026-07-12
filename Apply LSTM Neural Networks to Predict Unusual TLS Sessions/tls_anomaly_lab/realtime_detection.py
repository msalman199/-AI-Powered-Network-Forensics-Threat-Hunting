import numpy as np
import tensorflow as tf
import pickle
import pandas as pd
from datetime import datetime
import time
import random

class TLSAnomalyDetector:
    def __init__(self, model_path, scaler_path, encoders_path):
        """Initialize the real-time TLS anomaly detector"""
        
        # Load trained model
        self.model = tf.keras.models.load_model(model_path)
        
        # Load scaler
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        # Load encoders
        with open(encoders_path, 'rb') as f:
            self.encoders = pickle.load(f)
        
        # Initialize session buffer for sequence creation
        self.session_buffer = []
        self.sequence_length = 10
        
        print("TLS Anomaly Detector initialized successfully!")
    
    def preprocess_session(self, session_data):
        """Preprocess a single TLS session"""
        
        # Extract features similar to training data
        features = {
            'handshake_time': session_data.get('handshake_time', 0.15),
            'cert_size': session_data.get('cert_size', 2048),
            'session_duration': session_data.get('session_duration', 30),
            'bytes_sent': session_data.get('bytes_sent', 5000),
            'bytes_received': session_data.get('bytes_received', 15000),
            'src_port': session_data.get('src_port', 443),
            'cipher_suite_encoded': self._encode_cipher_suite(session_data.get('cipher_suite', 'TLS_AES_256_GCM_SHA384')),
            'tls_version_encoded': self._encode_tls_version(session_data.get('tls_version', 'TLSv1.3')),
            'hour': datetime.now().hour,
            'day_of_week': datetime.now().weekday(),
            'src_ip_last_octet': int(session_data.get('src_ip', '192.168.1.100').split('.')[-1]),
            'dst_ip_class': int(session_data.get('dst_ip', '10.0.1.1').split('.')[0])
        }
        
        return list(features.values())
    
    def _encode_cipher_suite(self, cipher_suite):
        """Encode cipher suite using trained encoder"""
        try:
            return self.encoders['cipher'].transform([cipher_suite])[0]
        except:
            return 0  # Default for unknown cipher suites
    
    def _encode_tls_version(self, tls_version):
        """Encode TLS version using trained encoder"""
        try:
            return self.encoders['tls'].transform([tls_version])[0]
        except:
            return 0  # Default for unknown TLS versions
    
    def detect_anomaly(self, session_data):
        """Detect if a TLS session is anomalous"""
        
        # Preprocess session
        features = self.preprocess_session(session_data)
        
        # Add to buffer
        self.session_buffer.append(features)
        
        # Keep only the last sequence_length sessions
        if len(self.session_buffer) > self.sequence_length:
            self.session_buffer.pop(0)
        
        # Need at least sequence_length sessions for prediction
        if len(self.session_buffer) < self.sequence_length:
            return None, 0.0
        
        # Create sequence and normalize
        sequence = np.array(self.session_buffer).reshape(1, self.sequence_length, -1)
        sequence_scaled = self.scaler.transform(sequence.reshape(-1, sequence.shape[-1])).reshape(sequence.shape)
        
        # Make prediction
        prediction_proba = self.model.predict(sequence_scaled, verbose=0)[0][0]
        is_anomaly = prediction_proba > 0.5
        
        return is_anomaly, prediction_proba

# Initialize detector
detector = TLSAnomalyDetector(
    'data/lstm_tls_anomaly_model.h5',
    'data/scaler.pkl',
    'data/encoders.pkl'
)

def simulate_tls_session():
    """Simulate a TLS session with random characteristics"""
    
    # Randomly decide if this should be anomalous
    is_anomalous = random.random() < 0.15
    
    if is_anomalous:
        # Generate anomalous session
        session = {
            'timestamp': datetime.now(),
            'src_ip': f"192.168.1.{random.randint(1, 254)}",
            'dst_ip': f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            'src_port': random.randint(1024, 65535),
            'dst_port': 443,
            'handshake_time': random.uniform(2.0, 5.0),  # Slow handshake
            'cert_size': random.randint(256, 1024),      # Small certificate
            'cipher_suite': random.choice(['TLS_RSA_WITH_RC4_128_MD5', 'SSL_RSA_WITH_NULL_MD5']),
            'tls_version': 'TLSv1.2',
            'session_duration': random.uniform(1, 10),    # Short duration
            'bytes_sent': random.randint(100, 1000),      # Low traffic
            'bytes_received': random.randint(100, 2000),
            'true_label': 1
        }
    else:
        # Generate normal session
        session = {
            'timestamp': datetime.now(),
            'src_ip': f"192.168.1.{random.randint(1, 254)}",
            'dst_ip': f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            'src_port': random.randint(1024, 65535),
            'dst_port': 443,
            'handshake_time': random.uniform(0.1, 0.3),   # Fast handshake
            'cert_size': random.randint(1536, 4096),      # Normal certificate
            'cipher_suite': random.choice(['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256']),
            'tls_version': 'TLSv1.3',
            'session_duration': random.uniform(20, 60),   # Normal duration
            'bytes_sent': random.randint(3000, 8000),     # Normal traffic
            'bytes_received': random.randint(10000, 25000),
            'true_label': 0
        }
    
    return session

def run_realtime_detection(num_sessions=50):
    """Run real-time anomaly detection simulation"""
    
    print("\nStarting real-time TLS anomaly detection...")
    print("="*70)
    print(f"{'Session':<8} {'True':<6} {'Pred':<6} {'Confidence':<12} {'Status':<15} {'Details'}")
    print("="*70)
    
    correct_predictions = 0
    total_predictions = 0
    
    for i in range(num_sessions):
        # Simulate a TLS session
        session = simulate_tls_session()
        
        # Detect anomaly
        is_anomaly, confidence = detector.detect_anomaly(session)
        
        if is_anomaly is not None:  # Only count when we have enough data
            total_predictions += 1
            predicted_label = 1 if is_anomaly else 0
            true_label = session['true_label']
            
            # Check if prediction is correct
            is_correct = predicted_label == true_label
            if is_correct:
                correct_predictions += 1
            
            # Determine status
            if true_label == 1 and predicted_label == 1:
                status = "✓ DETECTED"
            elif true_label == 1 and predicted_label == 0:
                status = "✗ MISSED"
            elif true_label == 0 and predicted_label == 1:
                status = "✗ FALSE ALARM"
            else:
                status = "✓ NORMAL"
            
            # Format details
            details = f"HS:{session['handshake_time']:.2f}s, Cert:{session['cert_size']}"
            
            print(f"{i+1:<8} {true_label:<6} {predicted_label:<6} {confidence:<12.4f} {status:<15} {details}")
        else:
            print(f"{i+1:<8} {'?':<6} {'?':<6} {'N/A':<12} {'BUFFERING':<15} Building sequence...")
        
        # Small delay to simulate real-time processing
        time.sleep(0.1)
    
    # Calculate accuracy
    if total_predictions > 0:
        accuracy = correct_predictions / total_predictions
        print("="*70)
        print(f"Real-time Detection Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"Total Predictions: {total_predictions}")
        print(f"Correct Predictions: {correct_predictions}")

# Run real-time simulation
run_realtime_detection(50)

