import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

class PhishingDetector:
    def __init__(self):
        self.models = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'Logistic Regression': LogisticRegression(random_state=42, max_iter=1000),
            'SVM': SVC(random_state=42, probability=True)
        }
        self.scaler = StandardScaler()
        self.best_model = None
        self.feature_names = None
    
    def prepare_features(self, df):
        """Prepare features for ML training"""
        
        # Select relevant features
        feature_columns = [
            'text_length', 'word_count', 'sentence_count',
            'exclamation_count', 'question_count', 'caps_ratio',
            'url_count', 'has_suspicious_url', 'phishing_keyword_count',
            'phishing_keyword_ratio', 'person_entities', 'org_entities',
            'money_entities', 'sender_domain_suspicious', 'sender_domain_length',
            'urgency_score'
        ]
        
        # Convert boolean columns to int
        df['has_suspicious_url'] = df['has_suspicious_url'].astype(int)
        df['sender_domain_suspicious'] = df['sender_domain_suspicious'].astype(int)
        
        X = df[feature_columns]
        y = df['is_phishing']
        
        self.feature_names = feature_columns
        
        return X, y
    
    def train_models(self, X, y):
        """Train multiple ML models and compare performance"""
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        results = {}
        
        print("=== Model Training and Evaluation ===")
        
        for name, model in self.models.items():
            print(f"\nTraining {name}...")
            
            # Train model
            if name == 'SVM':
                model.fit(X_train_scaled, y_train)
                y_pred = model.predict(X_test_scaled)
                y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
            else:
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            # Evaluate model
            accuracy = accuracy_score(y_test, y_pred)
            
            # Cross-validation
            if name == 'SVM':
                cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5)
            else:
                cv_scores = cross_val_score(model, X_train, y_train, cv=5)
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'y_test': y_test,
                'y_pred': y_pred,
                'y_pred_proba': y_pred_proba
            }
            
            print(f"Accuracy: {accuracy:.4f}")
            print(f"CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred))
        
        # Select best model
        best_model_name = max(results.keys(), key=lambda k: results[k]['cv_mean'])
        self.best_model = results[best_model_name]['model']
        
        print(f"\nBest Model: {best_model_name}")
        
        return results, X_test, y_test
    
    def visualize_results(self, results):
        """Visualize model performance"""
        
        plt.figure(figsize=(15, 10))
        
        # Plot 1: Model comparison
        plt.subplot(2, 3, 1)
        model_names = list(results.keys())
        accuracies = [results[name]['accuracy'] for name in model_names]
        cv_scores = [results[name]['cv_mean'] for name in model_names]
        
        x = np.arange(len(model_names))
        width = 0.35
        
        plt.bar(x - width/2, accuracies, width, label='Test Accuracy', alpha=0.8)
        plt.bar(x + width/2, cv_scores, width, label='CV Score', alpha=0.8)
        plt.xlabel('Models')
        plt.ylabel('Score')
        plt.title('Model Performance Comparison')
        plt.xticks(x, model_names, rotation=45)
        plt.legend()
        
        # Plot confusion matrices
        for i, (name, result) in enumerate(results.items()):
            plt.subplot(2, 3, i + 2)
            cm = confusion_matrix(result['y_test'], result['y_pred'])
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=plt.gca())
            plt.title(f'{name} - Confusion Matrix')
            plt.ylabel('True Label')
            plt.xlabel('Predicted Label')
        
        plt.tight_layout()
        plt.savefig('model_performance.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def feature_importance_analysis(self):
        """Analyze feature importance"""
        
        if hasattr(self.best_model, 'feature_importances_'):
            importances = self.best_model.feature_importances_
            
            # Create feature importance plot
            plt.figure(figsize=(10, 8))
            indices = np.argsort(importances)[::-1]
            
            plt.bar(range(len(importances)), importances[indices])
            plt.title('Feature Importance (Random Forest)')
            plt.xlabel('Features')
            plt.ylabel('Importance')
            plt.xticks(range(len(importances)), 
                      [self.feature_names[i] for i in indices], 
                      rotation=45, ha='right')
            
            plt.tight_layout()
            plt.savefig('feature_importance.png', dpi=300, bbox_inches='tight')
            plt.show()
            
            print("\n=== Top 10 Most Important Features ===")
            for i in range(min(10, len(importances))):
                idx = indices[i]
                print(f"{i+1}. {self.feature_names[idx]}: {importances[idx]:.4f}")
    
    def save_model(self, filename='phishing_detector_model.pkl'):
        """Save the trained model"""
        
        model_data = {
            'model': self.best_model,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }
        
        joblib.dump(model_data, filename)
        print(f"\nModel saved as '{filename}'")
    
    def predict_email(self, email_features):
        """Predict if an email is phishing"""
        
        # Ensure features are in correct order
        feature_vector = [email_features.get(feature, 0) for feature in self.feature_names]
        feature_vector = np.array(feature_vector).reshape(1, -1)
        
        # Scale if using SVM
        if isinstance(self.best_model, SVC):
            feature_vector = self.scaler.transform(feature_vector)
        
        prediction = self.best_model.predict(feature_vector)[0]
        probability = self.best_model.predict_proba(feature_vector)[0]
        
        return {
            'is_phishing': bool(prediction),
            'phishing_probability': probability[1],
            'legitimate_probability': probability[0]
        }

def main():
    # Load processed data
    df = pd.read_csv('processed_email_features.csv')
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Prepare features
    X, y = detector.prepare_features(df)
    
    print("Feature preparation complete!")
    print(f"Features shape: {X.shape}")
    print(f"Target distribution: {y.value_counts().to_dict()}")
    
    # Train models
    results, X_test, y_test = detector.train_models(X, y)
    
    # Visualize results
    detector.visualize_results(results)
    
    # Feature importance analysis
    detector.feature_importance_analysis()
    
    # Save model
    detector.save_model()
    
    # Test prediction on sample
    print("\n=== Sample Prediction ===")
    sample_features = {
        'text_length': 150,
        'word_count': 25,
        'sentence_count': 3,
        'exclamation_count': 2,
        'question_count': 0,
        'caps_ratio': 0.1,
        'url_count': 1,
        'has_suspicious_url': 1,
        'phishing_keyword_count': 3,
        'phishing_keyword_ratio': 0.12,
        'person_entities': 0,
        'org_entities': 1,
        'money_entities': 1,
        'sender_domain_suspicious': 1,
        'sender_domain_length': 15,
        'urgency_score': 2
    }
    
    prediction = detector.predict_email(sample_features)
    print(f"Prediction: {'PHISHING' if prediction['is_phishing'] else 'LEGITIMATE'}")
    print(f"Phishing Probability: {prediction['phishing_probability']:.4f}")

if __name__ == "__main__":
    main()
