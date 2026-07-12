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
