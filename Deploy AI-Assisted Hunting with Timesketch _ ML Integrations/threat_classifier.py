import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import joblib

class ThreatClassifier:
    def __init__(self):
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=1000, stop_words='english')),
            ('classifier', MultinomialNB())
        ])
        self.threat_categories = [
            'lateral_movement', 'privilege_escalation', 'data_exfiltration', 
            'command_control', 'persistence', 'normal'
        ]
    
    def create_training_data(self):
        """Create synthetic training data for threat classification"""
        training_data = [
            ("powershell.exe -enc base64command", "command_control"),
            ("net user admin password123 /add", "privilege_escalation"),
            ("schtasks /create /tn backdoor", "persistence"),
            ("psexec \\\\target cmd.exe", "lateral_movement"),
            ("copy sensitive.txt \\\\external", "data_exfiltration"),
            ("user login successful", "normal"),
            ("file access granted", "normal"),
            ("wmic process call create", "command_control"),
            ("reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "persistence"),
            ("net share admin$ /grant:everyone,full", "privilege_escalation")
        ]
        
        # Expand training data
        expanded_data = []
        for text, label in training_data:
            expanded_data.extend([(text, label)] * 10)  # Duplicate for better training
        
        return expanded_data
    
    def train_model(self):
        """Train the threat classification model"""
        training_data = self.create_training_data()
        texts, labels = zip(*training_data)
        
        self.pipeline.fit(texts, labels)
        joblib.dump(self.pipeline, 'threat_classifier.pkl')
        print("Threat classification model trained and saved")
    
    def classify_events(self, events_file):
        """Classify security events"""
        df = pd.read_csv(events_file)
        
        if 'message' not in df.columns:
            print("No message column found for classification")
            return df
        
        # Load or train model
        try:
            self.pipeline = joblib.load('threat_classifier.pkl')
        except:
            self.train_model()
        
        # Classify events
        predictions = self.pipeline.predict(df['message'])
        probabilities = self.pipeline.predict_proba(df['message'])
        
        df['threat_category'] = predictions
        df['confidence'] = np.max(probabilities, axis=1)
        
        return df

if __name__ == "__main__":
    classifier = ThreatClassifier()
    classifier.train_model()
    
    # Classify Windows security events
    print("\nClassifying Windows Security Events...")
    classified_events = classifier.classify_events('/home/ubuntu/security_logs/windows_security.csv')
    
    # Display results
    threat_summary = classified_events['threat_category'].value_counts()
    print("\nThreat Classification Summary:")
    for category, count in threat_summary.items():
        print(f"  {category}: {count}")
    
    # Show high-confidence threats
    threats = classified_events[
        (classified_events['threat_category'] != 'normal') & 
        (classified_events['confidence'] > 0.7)
    ]
    
    print(f"\nHigh-Confidence Threats Detected: {len(threats)}")
    for _, event in threats.iterrows():
        print(f"  - {event['threat_category']}: {event['message']} (Confidence: {event['confidence']:.2f})")
    
    # Save results
    classified_events.to_csv('classified_events.csv', index=False)
    print("\nResults saved to classified_events.csv")
