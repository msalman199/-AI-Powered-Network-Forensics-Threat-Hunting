#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

class ObfuscationDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = None
    
    def load_data(self, csv_file):
        """Load and prepare training data"""
        df = pd.read_csv(csv_file)
        
        # Select feature columns (exclude non-numeric and target)
        feature_cols = ['entropy', 'base64_ratio', 'hex_ratio', 'printable_ratio', 
                       'compression_ratio', 'suspicious_patterns', 'payload_length']
        
        # Handle missing values
        df[feature_cols] = df[feature_cols].fillna(0)
        
        self.feature_columns = feature_cols
        X = df[feature_cols]
        y = df['label']
        
        return X, y
    
    def train_model(self, X, y):
        """Train the obfuscation detection model"""
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test_scaled)
        
        print("Model Performance:")
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Obfuscated']))
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': self.feature_columns,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nFeature Importance:")
        print(feature_importance)
        
        # Plot confusion matrix
        self.plot_confusion_matrix(y_test, y_pred)
        
        return X_test_scaled, y_test, y_pred
    
    def plot_confusion_matrix(self, y_true, y_pred):
        """Plot confusion matrix"""
        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=['Normal', 'Obfuscated'],
                   yticklabels=['Normal', 'Obfuscated'])
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.savefig('results/confusion_matrix.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("Confusion matrix saved to results/confusion_matrix.png")
    
    def save_model(self, model_path="models/obfuscation_detector.pkl"):
        """Save trained model and scaler"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns
        }
        joblib.dump(model_data, model_path)
        print(f"Model saved to {model_path}")
    
    def load_model(self, model_path="models/obfuscation_detector.pkl"):
        """Load trained model and scaler"""
        model_data = joblib.load(model_path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_columns = model_data['feature_columns']
        print(f"Model loaded from {model_path}")
    
    def predict(self, features):
        """Predict obfuscation for new features"""
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        features_scaled = self.scaler.transform(features)
        predictions = self.model.predict(features_scaled)
        probabilities = self.model.predict_proba(features_scaled)
        
        return predictions, probabilities

# Train the model
if __name__ == "__main__":
    detector = ObfuscationDetector()
    
    # Load data
    X, y = detector.load_data("data/extracted_features.csv")
    print(f"Loaded {len(X)} samples with {len(X.columns)} features")
    
    # Train model
    X_test, y_test, y_pred = detector.train_model(X, y)
    
    # Save model
    detector.save_model()
