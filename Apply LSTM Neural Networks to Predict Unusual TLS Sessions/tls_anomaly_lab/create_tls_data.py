import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

def generate_tls_sessions(num_sessions=10000):
    """Generate synthetic TLS session data"""
    
    # Normal session patterns
    normal_handshake_times = np.random.normal(0.15, 0.05, int(num_sessions * 0.85))
    normal_cert_sizes = np.random.normal(2048, 512, int(num_sessions * 0.85))
    normal_cipher_suites = np.random.choice([
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256'
    ], int(num_sessions * 0.85))
    
    # Anomalous session patterns
    anomaly_handshake_times = np.random.normal(2.5, 1.0, int(num_sessions * 0.15))
    anomaly_cert_sizes = np.random.normal(512, 128, int(num_sessions * 0.15))
    anomaly_cipher_suites = np.random.choice([
        'TLS_RSA_WITH_RC4_128_MD5',
        'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        'SSL_RSA_WITH_NULL_MD5'
    ], int(num_sessions * 0.15))
    
    # Combine data
    handshake_times = np.concatenate([normal_handshake_times, anomaly_handshake_times])
    cert_sizes = np.concatenate([normal_cert_sizes, anomaly_cert_sizes])
    cipher_suites = np.concatenate([normal_cipher_suites, anomaly_cipher_suites])
    
    # Create labels (0 = normal, 1 = anomaly)
    labels = np.concatenate([
        np.zeros(int(num_sessions * 0.85)),
        np.ones(int(num_sessions * 0.15))
    ])
    
    # Generate additional features
    data = []
    base_time = datetime.now()
    
    for i in range(num_sessions):
        session = {
            'timestamp': base_time + timedelta(seconds=i*10),
            'src_ip': f"192.168.1.{random.randint(1, 254)}",
            'dst_ip': f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            'src_port': random.randint(1024, 65535),
            'dst_port': 443,
            'handshake_time': handshake_times[i],
            'cert_size': int(cert_sizes[i]),
            'cipher_suite': cipher_suites[i],
            'tls_version': random.choice(['TLSv1.2', 'TLSv1.3']),
            'session_duration': np.random.exponential(30),
            'bytes_sent': np.random.exponential(5000),
            'bytes_received': np.random.exponential(15000),
            'is_anomaly': int(labels[i])
        }
        data.append(session)
    
    # Shuffle data
    random.shuffle(data)
    return pd.DataFrame(data)

# Generate and save data
df = generate_tls_sessions(10000)
df.to_csv('data/tls_sessions.csv', index=False)
print(f"Generated {len(df)} TLS sessions")
print(f"Normal sessions: {len(df[df['is_anomaly'] == 0])}")
print(f"Anomalous sessions: {len(df[df['is_anomaly'] == 1])}")
