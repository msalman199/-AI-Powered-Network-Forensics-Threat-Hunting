import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta

def generate_http_sessions(num_sessions=5000):
    np.random.seed(42)
    random.seed(42)
    
    sessions = []
    
    # Normal session patterns
    normal_methods = ['GET', 'POST', 'PUT', 'DELETE']
    normal_status_codes = [200, 201, 204, 301, 302, 404]
    normal_user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ]
    
    # Suspicious patterns
    suspicious_methods = ['TRACE', 'OPTIONS', 'CONNECT']
    suspicious_status_codes = [403, 500, 502, 503]
    suspicious_user_agents = [
        'sqlmap/1.0',
        'Nikto/2.1.6',
        'python-requests/2.25.1',
        'curl/7.68.0'
    ]
    
    for i in range(num_sessions):
        # Determine if session is suspicious (30% chance)
        is_suspicious = random.random() < 0.3
        
        if is_suspicious:
            # Generate suspicious session
            method = random.choice(suspicious_methods + normal_methods)
            status_code = random.choice(suspicious_status_codes + [200])
            user_agent = random.choice(suspicious_user_agents)
            request_size = np.random.normal(2000, 1000)  # Larger requests
            response_size = np.random.normal(500, 200)   # Smaller responses
            duration = np.random.exponential(5)          # Longer duration
            requests_per_session = np.random.poisson(50) # More requests
            unique_paths = np.random.poisson(30)         # More unique paths
            error_rate = np.random.beta(3, 2)            # Higher error rate
            label = 1  # Suspicious
        else:
            # Generate normal session
            method = random.choice(normal_methods)
            status_code = random.choice(normal_status_codes)
            user_agent = random.choice(normal_user_agents)
            request_size = np.random.normal(800, 300)    # Normal requests
            response_size = np.random.normal(1500, 500)  # Normal responses
            duration = np.random.exponential(2)          # Shorter duration
            requests_per_session = np.random.poisson(10) # Fewer requests
            unique_paths = np.random.poisson(5)          # Fewer unique paths
            error_rate = np.random.beta(1, 10)           # Lower error rate
            label = 0  # Normal
        
        # Ensure positive values
        request_size = max(100, request_size)
        response_size = max(50, response_size)
        duration = max(0.1, duration)
        requests_per_session = max(1, requests_per_session)
        unique_paths = max(1, unique_paths)
        error_rate = max(0, min(1, error_rate))
        
        session = {
            'session_id': f'session_{i:05d}',
            'method_encoded': hash(method) % 100,
            'status_code': status_code,
            'user_agent_encoded': hash(user_agent) % 1000,
            'avg_request_size': request_size,
            'avg_response_size': response_size,
            'session_duration': duration,
            'requests_per_session': requests_per_session,
            'unique_paths': unique_paths,
            'error_rate': error_rate,
            'is_suspicious': label
        }
        
        sessions.append(session)
    
    return pd.DataFrame(sessions)

# Generate and save dataset
print("Generating HTTP session dataset...")
df = generate_http_sessions(5000)
df.to_csv('http_sessions.csv', index=False)
print(f"Generated {len(df)} HTTP sessions")
print(f"Normal sessions: {len(df[df['is_suspicious'] == 0])}")
print(f"Suspicious sessions: {len(df[df['is_suspicious'] == 1])}")
print("\nDataset saved as 'http_sessions.csv'")
print("\nFirst 5 rows:")
print(df.head())
