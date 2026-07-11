import pandas as pd
import numpy as np
import tensorflow as tf
import joblib
import time
import random

def simulate_realtime_session():
    """Simulate a real-time HTTP session"""
    # Randomly generate either normal or suspicious session
    is_attack = random.random() < 0.3
    
    if is_attack:
        # Simulate attack patterns
        attack_type = random.choice(['sql_injection', 'directory_traversal', 'brute_force'])
        
        if attack_type == 'sql_injection':
            session = {
                'method_encoded': random.randint(10, 20),
                'status_code': random.choice([500, 403, 200]),
                'user_agent_encoded': random.randint(200, 300),
                'avg_request_size': random.randint(2000, 4000),
                'avg_response_size': random.randint(300, 600),
                'session_duration': random.uniform(3, 8),
                'requests_per_session': random.randint(50, 100),
                'unique_paths': random.randint(20, 40),
                'error_rate': random.uniform(0.5, 0.9),
                'attack_type': 'SQL Injection'
            }
        elif attack_type == 'directory_traversal':
            session = {
                'method_encoded': random.randint(20, 30),
                'status_code': random.choice([403, 404, 200]),
                'user_agent_encoded': random.randint(100, 200),
                'avg_request_size': random.randint(1200, 2000),
                'avg_response_size': random.randint(200, 400),
                'session_duration': random.uniform(2, 6),
                'requests_per_session': random.randint(40, 80),
                'unique_paths': random.randint(15, 35),
                'error_rate': random.uniform(0.6, 0.8),
                'attack_type': 'Directory Traversal'
            }
        else:  # brute_force
            session = {
                'method_encoded': random.randint(30, 40),
                'status_code': random.choice([401, 403, 200]),
                'user_agent_encoded': random.randint(300, 400),
                'avg_request_size': random.randint(600, 1000),
                'avg_response_size': random.randint(100, 300),
                'session_duration': random.uniform(5, 12),
                'requests_per_session': random.randint(100, 300),
                'unique_paths': random.randint(1, 5),
                'error_rate': random.uniform(0.8, 0.95),
                'attack_type': 'Brute Force'
            }
    else:
        # Normal session
        session = {
            'method_encoded': random.randint(40, 60),
            'status_code': random.choice([200, 201, 301, 302]),
            'user_agent_encoded': random.randint(400, 600),
            'avg_request_size': random.randint(600, 1200),
            'avg_response_size': random.randint(1000, 2000),
            'session_duration': random.uniform(0.5, 3),
            'requests_per_session': random.randint(3, 15),
            'unique_paths': random.randint(2, 8),
            'error_rate': random.uniform(0, 0.1),
            'attack_type': 'Normal'
        }
    
    return session

def classify_session(model, scaler, session_data):
    """Classify a single session"""
    feature_columns = [
        'method_encoded', 'status_code', 'user_agent_encoded',
        'avg_request_size', 'avg_response_size', 'session_duration',
        'requests_per_session', 'unique_paths', 'error_rate'
    ]
    
    # Prepare features
    features = np.array([[session_data[col] for col in feature_columns]])
    features_scaled = scaler.transform(features)
    
    # Make prediction
    prediction_prob = model.predict(features_scaled, verbose=0)[0][0]
    prediction_label = 1 if prediction_prob > 0.5 else 0
    
    return prediction_prob, prediction_label

def main():
    print("Loading trained model for real-time classification...")
    
    # Load model and scaler
    model = tf.keras.models.load_model('http_classifier_model.h5')
    scaler = joblib.load('scaler.pkl')
    
    print("Starting real-time HTTP session classification demo...")
    print("Press Ctrl+C to stop\n")
    
    session_count = 0
    correct_predictions = 0
    
    try:
        while True:
            # Simulate incoming session
            session = simulate_realtime_session()
            session_count += 1
            
            # Classify the session
            prob, pred_label = classify_session(model, scaler, session)
            
            # Determine if prediction is correct
            actual_suspicious = 1 if session['attack_type'] != 'Normal' else 0
            is_correct = pred_label == actual_suspicious
            if is_correct:
                correct_predictions += 1
            
            # Display results
            status = "✓ CORRECT" if is_correct else "✗ INCORRECT"
            risk_level = "HIGH" if prob > 0.8 else "MEDIUM" if prob > 0.5 else "LOW"
            
            print(f"Session #{session_count:03d} | {status}")
            print(f"  Actual: {session['attack_type']}")
            print(f"  Predicted: {'SUSPICIOUS' if pred_label == 1 else 'NORMAL'} (Risk: {risk_level})")
            print(f"  Confidence: {prob:.3f}")
            print(f"  Requests: {session['requests_per_session']}, Error Rate: {session['error_rate']:.2f}")
            print(f"  Running Accuracy: {correct_predictions/session_count:.3f} ({correct_predictions}/{session_count})")
            print("-" * 60)
            
            # Wait before next session
            time.sleep(2)
            
    except KeyboardInterrupt:
        print(f"\nDemo stopped. Final accuracy: {correct_predictions/session_count:.3f}")
        print(f"Classified {session_count} sessions with {correct_predictions} correct predictions.")

if __name__ == "__main__":
    main()
