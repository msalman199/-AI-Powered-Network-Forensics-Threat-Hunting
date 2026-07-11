#!/usr/bin/env python3
import json
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
import matplotlib.pyplot as plt
import seaborn as sns

class MLThreatHunter:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.label_encoders = {}
        self.tfidf_vectorizer = TfidfVectorizer(max_features=100)
        
    def load_events(self, filename):
        """Load events from JSON file"""
        events = []
        with open(filename, 'r') as f:
            for line in f:
                events.append(json.loads(line.strip()))
        return pd.DataFrame(events)
    
    def preprocess_data(self, df):
        """Preprocess data for ML analysis"""
        # Handle missing values
        df = df.fillna('unknown')
        
        # Encode categorical variables
        categorical_cols = ['process_name', 'parent_process', 'user']
        for col in categorical_cols:
            if col in df.columns:
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                    df[f'{col}_encoded'] = self.label_encoders[col].fit_transform(df[col])
                else:
                    df[f'{col}_encoded'] = self.label_encoders[col].transform(df[col])
        
        # Process command line with TF-IDF
        if 'command_line' in df.columns:
            command_features = self.tfidf_vectorizer.fit_transform(df['command_line'])
            command_df = pd.DataFrame(command_features.toarray(), 
                                    columns=[f'cmd_feature_{i}' for i in range(command_features.shape[1])])
            df = pd.concat([df.reset_index(drop=True), command_df], axis=1)
        
        return df
    
    def detect_anomalies(self, df):
        """Detect anomalies using Isolation Forest"""
        # Select numeric features for anomaly detection
        numeric_cols = [col for col in df.columns if col.endswith('_encoded') or col.startswith('cmd_feature_')]
        
        if len(numeric_cols) > 0:
            X = df[numeric_cols]
            anomaly_scores = self.isolation_forest.fit_predict(X)
            df['anomaly_score'] = anomaly_scores
            df['is_anomaly'] = anomaly_scores == -1
        else:
            df['anomaly_score'] = 0
            df['is_anomaly'] = False
            
        return df
    
    def generate_report(self, df):
        """Generate threat hunting report"""
        print("=== ML-Enhanced Threat Hunting Report ===")
        print(f"Total Events Analyzed: {len(df)}")
        print(f"Anomalies Detected: {df['is_anomaly'].sum()}")
        print(f"Anomaly Rate: {df['is_anomaly'].mean():.2%}")
        
        if df['is_anomaly'].sum() > 0:
            print("\n=== Suspicious Events ===")
            suspicious_events = df[df['is_anomaly'] == True]
            for idx, event in suspicious_events.iterrows():
                print(f"\nEvent {idx + 1}:")
                print(f"  Process: {event.get('process_name', 'N/A')}")
                print(f"  Command: {event.get('command_line', 'N/A')}")
                print(f"  User: {event.get('user', 'N/A')}")
                print(f"  Timestamp: {event.get('timestamp', 'N/A')}")

if __name__ == "__main__":
    hunter = MLThreatHunter()
    
    # Load and analyze events
    df = hunter.load_events('sample_events.json')
    df_processed = hunter.preprocess_data(df)
    df_analyzed = hunter.detect_anomalies(df_processed)
    
    # Generate report
    hunter.generate_report(df_analyzed)
    
    # Save results
    df_analyzed.to_csv('threat_hunting_results.csv', index=False)
    print("\nResults saved to threat_hunting_results.csv")
