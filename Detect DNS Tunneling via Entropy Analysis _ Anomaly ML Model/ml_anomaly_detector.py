#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import matplotlib.pyplot as plt

class DNSAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.features = ['entropy', 'length', 'entropy_per_char', 'digit_ratio', 'vowel_ratio']
    
    def extract_features(self, df):
        """Extract additional features for ML model"""
        # Calculate digit ratio
        df['digit_ratio'] = df['subdomain'].apply(
            lambda x: sum(c.isdigit() for c in x) / len(x) if len(x) > 0 else 0
        )
        
        # Calculate vowel ratio
        vowels = 'aeiou'
        df['vowel_ratio'] = df['subdomain'].apply(
            lambda x: sum(c.lower() in vowels for c in x) / len(x) if len(x) > 0 else 0
        )
        
        return df[self.features]
    
    def train(self, df):
        """Train the anomaly detection model"""
        # Extract features
        X = self.extract_features(df)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled)
        
        # Get anomaly scores
        anomaly_scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)
        
        # Add results to dataframe
        df['anomaly_score'] = anomaly_scores
        df['is_anomaly'] = predictions == -1
        
        return df
    
    def predict(self, df):
        """Predict anomalies on new data"""
        X = self.extract_features(df)
        X_scaled = self.scaler.transform(X)
        
        anomaly_scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)
        
        df['anomaly_score'] = anomaly_scores
        df['is_anomaly'] = predictions == -1
        
        return df
    
    def save_model(self, filename):
        """Save trained model"""
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'features': self.features
        }, filename)
    
    def load_model(self, filename):
        """Load trained model"""
        data = joblib.load(filename)
        self.model = data['model']
        self.scaler = data['scaler']
        self.features = data['features']

def create_training_data():
    """Create synthetic training data with known normal and anomalous patterns"""
    normal_patterns = [
        "www", "mail", "ftp", "blog", "shop", "news", "support", "api",
        "cdn", "static", "images", "videos", "docs", "help", "about"
    ]
    
    # Generate normal DNS queries
    normal_data = []
    for pattern in normal_patterns:
        for domain in ["example.com", "test.org", "sample.net"]:
            query = f"{pattern}.{domain}"
            normal_data.append({
                'query': query,
                'subdomain': pattern,
                'label': 'normal'
            })
    
    # Generate anomalous DNS queries (high entropy)
    anomalous_data = []
    np.random.seed(42)
    for _ in range(20):
        # High entropy random string
        random_str = ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), 
                                            size=np.random.randint(20, 40)))
        query = f"{random_str}.tunnel.com"
        anomalous_data.append({
            'query': query,
            'subdomain': random_str,
            'label': 'anomaly'
        })
    
    # Combine data
    all_data = normal_data + anomalous_data
    df = pd.DataFrame(all_data)
    
    # Calculate entropy and other features
    df['entropy'] = df['subdomain'].apply(calculate_entropy)
    df['length'] = df['subdomain'].apply(len)
    df['entropy_per_char'] = df['entropy'] / df['length']
    
    return df

def calculate_entropy(data):
    """Calculate Shannon entropy"""
    if len(data) == 0:
        return 0
    
    from collections import Counter
    counter = Counter(data)
    length = len(data)
    
    entropy = 0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * np.log2(probability)
    
    return entropy

if __name__ == "__main__":
    # Load real DNS data if available
    try:
        real_df = pd.read_csv('dns_entropy_results.csv')
        print("Using real DNS data from previous analysis")
    except FileNotFoundError:
        print("Creating synthetic training data...")
        real_df = create_training_data()
    
    # Initialize detector
    detector = DNSAnomalyDetector()
    
    # Train model
    print("Training anomaly detection model...")
    results_df = detector.train(real_df)
    
    # Display results
    print("\nAnomaly Detection Results:")
    print("=" * 50)
    print(results_df[['query', 'entropy', 'anomaly_score', 'is_anomaly']].to_string(index=False))
    
    # Show anomalies
    anomalies = results_df[results_df['is_anomaly']]
    print(f"\nDetected {len(anomalies)} anomalies:")
    if len(anomalies) > 0:
        print(anomalies[['query', 'entropy', 'anomaly_score']].to_string(index=False))
    
    # Save model
    detector.save_model('dns_anomaly_model.pkl')
    print("\nModel saved as 'dns_anomaly_model.pkl'")
    
    # Save results
    results_df.to_csv('anomaly_detection_results.csv', index=False)
    print("Results saved to 'anomaly_detection_results.csv'")
