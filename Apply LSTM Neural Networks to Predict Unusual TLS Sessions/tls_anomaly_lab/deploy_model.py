import tensorflow as tf
import numpy as np
import pickle
import json
from datetime import datetime

class TLSAnomalyDetectorDeployment:
    """Production-ready TLS anomaly detector"""
    
    def __init__(self, model_path, scaler_path, encoders_path):
        self.model = tf.keras.models.load_model(model_path)
        
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        with open(encoders_path, 'rb') as f:
            self.encoders = pickle.load(f)
        
        self.session_buffer = []
        self.sequence_length = 10
        
        # Performance metrics
        self.total_sessions = 0
        self.anomalies_detected = 0
        self.processing_times = []
    
    def process_session(self, session_json):
        """Process a TLS session from JSON input"""
        
        start_time = datetime.now()
        
        try:
            # Parse JSON input
            session_data = json.loads(session_json) if isinstance(session_json, str) else session_json
            
            # Detect anomaly
            is_anomaly, confidence = self.detect_anomaly(session_data)
            
            # Update metrics
            self.total_sessions += 1
            if is_anomaly:
                self.anomalies_detected += 1
            
            processing_time = (datetime.now() - start_time).total_seconds()
            self.processing_times.append(processing_time)
            
            # Prepare response
            response = {
                'session_id': session_data.get('session_id', f'session_{self.total_sessions}'),
                'timestamp': datetime.now().isoformat(),
                'is_anomaly': bool(is_anomaly) if is_anomaly is not None else None,
                'confidence': float(confidence),
                'processing_time_ms': processing_time * 1000,
                'status': 'processed' if is_anomaly is not None else 'buffering'
            }
            
            return response
            
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'status': 'error'
            }
    
    def detect_anomaly(self, session_data):
        """Core anomaly detection logic"""
        
        features = self._extract_features(session_data)
        self.session_buffer.append(features)
        
        if len(self.session_buffer) > self.sequence_length:
            self.session_buffer.pop(0)
        
        if len(self.session_buffer) < self.sequence_length:
            return None, 0.0
        
        sequence = np.array(self.session_buffer).reshape(1, self.sequence_length, -1)
        sequence_scaled = self.scaler.transform(
            sequence.reshape(-1, sequence.shape[-1])
        ).reshape(sequence.shape)
        
        prediction_proba = self.model.predict(sequence_scaled, verbose=0)[0][0]
        is_anomaly = prediction_proba > 0.5
        
        return is_anomaly, prediction_proba
    
    def _extract_features(self, session_data):
        """Extract features from session data"""
        
        return [
            session_data.get('handshake_time', 0.15),
            session_data.get('cert_size', 2048),
            session_data.get('session_duration', 30),
            session_data.get('bytes_sent', 5000),
            session_data.get('bytes_received', 15000),
            session_data.get('src_port', 443),
            self._encode_cipher_suite(session_data.get('cipher_suite', 'TLS_AES_256_GCM_SHA384')),
            self._encode_tls_version(session_data.get('tls_version', 'TLSv1.3')),
            datetime.now().hour,
            datetime.now().weekday(),
            int(session_data.get('src_ip', '192.168.1.100').split('.')[-1]),
            int(session_data.get('dst_ip', '10.0.1.1').split('.')[0])
        ]
    
    def _encode_cipher_suite(self, cipher_suite):
        try:
            return self.encoders['cipher'].transform([cipher_suite])[0]
        except:
            return 0
    
    def _encode_tls_version(self, tls_version):
        try:
            return self.encoders['tls'].transform([tls_version])[0]
        except:
            return 0
    
    def get_statistics(self):
        """Get detector performance statistics"""
        
        avg_processing_time = np.mean(self.processing_times) if self.processing_times else 0
        
        return {
            'total_sessions_processed': self.total_sessions,
            'anomalies_detected': self.anomalies_detected,
            'anomaly_rate': self.anomalies_detected / self.total_sessions if self.total_sessions > 0 else 0,
            'average_processing_time_ms': avg_processing_time * 1000,
            'max_processing_time_ms': max(self.processing_times) * 1000 if self.processing_times else 0,
            'min_processing_time_ms': min(self.processing_times) * 1000 if self.processing_times else 0
        }

# Test deployment
if __name__ == "__main__":
    # Initialize deployment detector
    detector = TLSAnomalyDetectorDeployment(
        'data/lstm_tls_anomaly_model.h5',
        'data/scaler.pkl',
        'data/encoders.pkl'
    )
    
    # Test with sample sessions
    test_sessions = [
        {
            'session_id': 'test_001',
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.1.50',
            'handshake_time': 0.12,
            'cert_size': 2048,
            'cipher_suite': 'TLS_AES_256_GCM_SHA384',
            'tls_version': 'TLSv1.3'
        },
        {
            'session_id': 'test_002',
            'src_ip': '192.168.1.101',
            'dst_ip': '10.0.1.51',
            'handshake_time': 3.5,  # Suspicious
            'cert_size': 512,       # Suspicious
            'cipher_suite': 'TLS_RSA_WITH_RC4_128_MD5',  # Weak cipher
            'tls_version': 'TLSv1.2'
        }
    ]
    
    print("Testing deployment detector...")
    for session in test_sessions:
        result = detector.process_session(session)
        print(f"Session {session['session_id']}: {result}")
    
    print("\nDetector Statistics:")
    stats = detector.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
