import pandas as pd
import numpy as np
import random

def generate_new_test_sessions(num_sessions=100):
    """Generate new HTTP sessions for testing the trained model"""
    np.random.seed(123)  # Different seed for test data
    random.seed(123)
    
    sessions = []
    
    # Simulate various attack patterns and normal behavior
    attack_patterns = [
        # SQL Injection attempts
        {'method_encoded': 15, 'status_code': 500, 'user_agent_encoded': 250, 
         'avg_request_size': 3000, 'requests_per_session': 80, 'error_rate': 0.7},
        
        # Directory traversal
        {'method_encoded': 25, 'status_code': 403, 'user_agent_encoded': 150, 
         'avg_request_size': 1500, 'requests_per_session': 60, 'error_rate': 0.8},
        
        # Brute force login
        {'method_encoded': 35, 'status_code': 401, 'user_agent_encoded': 350, 
         'avg_request_size': 800, 'requests_per_session': 200, 'error_rate': 0.9},
    ]
    
    normal_patterns = [
        # Regular browsing
        {'method_encoded': 45, 'status_code': 200, 'user_agent_encoded': 450, 
         'avg_request_size': 900, 'requests_per_session': 8, 'error_rate': 0.05},
        
        # API usage
        {'method_encoded': 55, 'status_code': 201, 'user_agent_encoded': 550, 
         'avg_request_size': 600, 'requests_per_session': 15, 'error_rate': 0.02},
    ]
    
    for i in range(num_sessions):
        # 40% chance of suspicious activity for testing
        is_suspicious = random.random() < 0.4
        
        if is_suspicious:
            base_pattern = random.choice(attack_patterns)
            # Add some variation
            session = {
                'session_id': f'test_session_{i:03d}',
                'method_encoded': base_pattern['method_encoded'] + random.randint(-5, 5),
                'status_code': base_pattern['status_code'],
                'user_agent_encoded': base_pattern['user_agent_encoded'] + random.randint(-50, 50),
                'avg_request_size': base_pattern['avg_request_size'] + random.randint(-200, 200),
                'avg_response_size': np.random.normal(400, 100),
                'session_duration': np.random.exponential(4),
                'requests_per_session': base_pattern['requests_per_session'] + random.randint(-10, 10),
                'unique_paths': np.random.poisson(25),
                'error_rate': base_pattern['error_rate'] + random.uniform(-0.1, 0.1),
                'actual_label': 1  # Ground truth for evaluation
            }
        else:
            base_pattern = random.choice(normal_patterns)
            session = {
                'session_id': f'test_session_{i:03d}',
                'method_encoded': base_pattern['method_encoded'] + random.randint(-5, 5),
                'status_code': base_pattern['status_code'],
                'user_agent_encoded': base_pattern['user_agent_encoded'] + random.randint(-50, 50),
                'avg_request_size': base_pattern['avg_request_size'] + random.randint(-100, 100),
                'avg_response_size': np.random.normal(1200, 300),
                'session_duration': np.random.exponential(1.5),
                'requests_per_session': base_pattern['requests_per_session'] + random.randint(-3, 3),
                'unique_paths': np.random.poisson(4),
                'error_rate': base_pattern['error_rate'] + random.uniform(-0.01, 0.01),
                'actual_label': 0  # Ground truth for evaluation
            }
        
        # Ensure positive values and valid ranges
        session['avg_response_size'] = max(50, session['avg_response_size'])
        session['session_duration'] = max(0.1, session['session_duration'])
        session['requests_per_session'] = max(1, session['requests_per_session'])
        session['unique_paths'] = max(1, session['unique_paths'])
        session['error_rate'] = max(0, min(1, session['error_rate']))
        
        sessions.append(session)
    
    return pd.DataFrame(sessions)

# Generate test data
print("Generating new test HTTP sessions...")
test_df = generate_new_test_sessions(100)
test_df.to_csv('new_test_sessions.csv', index=False)

print(f"Generated {len(test_df)} test sessions")
print(f"Normal sessions: {len(test_df[test_df['actual_label'] == 0])}")
print(f"Suspicious sessions: {len(test_df[test_df['actual_label'] == 1])}")
print("\nTest dataset saved as 'new_test_sessions.csv'")
print("\nFirst 5 rows:")
print(test_df.head())
