import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

class ProtocolClassifier:
    def __init__(self, csv_file="protocol_features.csv"):
        self.df = pd.read_csv(csv_file)
        self.models = {}
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names = []
        
    def prepare_data(self):
        """Prepare data for machine learning"""
        print("Preparing data for machine learning...")
        
        # Remove unknown protocols and non-feature columns
        self.df_clean = self.df[self.df['protocol_label'] != 'Unknown'].copy()
        
        if len(self.df_clean) == 0:
            raise ValueError("No labeled protocols found for training!")
        
        # Select features (exclude packet_id and protocol_label)
        feature_cols = [col for col in self.df_clean.columns 
                       if col not in ['packet_id', 'protocol_label']]
        
        X = self.df_clean[feature_cols].values
        y = self.df_clean['protocol_label'].values
        
        # Handle any NaN values
        X = np.nan_to_num(X)
        
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        self.feature_names = feature_cols
        
        print(f"Data shape: {X_scaled.shape}")
        print(f"Classes: {self.label_encoder.classes_}")
        print(f"Class distribution: {np.bincount(y_encoded)}")
        
        return X_scaled, y_encoded
    
    def train_models(self, X, y):
        """Train multiple classification models"""
        print("\nTraining classification models...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        # Define models
        models = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'SVM': SVC(kernel='rbf', random_state=42),
            'Naive Bayes': GaussianNB()
        }
        
        # Train and evaluate models
        results = {}
        
        for name, model in models.items():
            print(f"\nTraining {name}...")
            
            # Train model
            model.fit(X_train, y_train)
            
            # Make predictions
            y_pred = model.predict(X_test)
            
            # Calculate accuracy
            accuracy = accuracy_score(y_test, y_pred)
            
            # Cross-validation score
            cv_scores = cross_val_score(model, X_train, y_train, cv=5)
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'y_test': y_test,
                'y_pred': y_pred
            }
            
            print(f"Accuracy: {accuracy:.4f}")
            print(f"CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        self.models = results
        return X_test, y_test
    
    def evaluate_best_model(self):
        """Find and evaluate the best performing model"""
        print("\n=== Model Evaluation Results ===")
        
        best_model_name = max(self.models.keys(), 
                             key=lambda k: self.models[k]['accuracy'])
        best_model_info = self.models[best_model_name]
        
        print(f"\nBest Model: {best_model_name}")
        print(f"Accuracy: {best_model_info['accuracy']:.4f}")
        
        # Detailed classification report
        y_test = best_model_info['y_test']
        y_pred = best_model_info['y_pred']
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, 
                                  target_names=self.label_encoder.classes_))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        plt.figure(figsize=(12, 5))
        
        # Plot confusion matrix
        plt.subplot(1, 2, 1)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=self.label_encoder.classes_,
                   yticklabels=self.label_encoder.classes_)
        plt.title(f'Confusion Matrix - {best_model_name}')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        
        # Plot model comparison
        plt.subplot(1, 2, 2)
        model_names = list(self.models.keys())
        accuracies = [self.models[name]['accuracy'] for name in model_names]
        cv_means = [self.models[name]['cv_mean'] for name in model_names]
        
        x = np.arange(len(model_names))
        width = 0.35
        
        plt.bar(x - width/2, accuracies, width, label='Test Accuracy', alpha=0.8)
        plt.bar(x + width/2, cv_means, width, label='CV Mean', alpha=0.8)
        
        plt.xlabel('Models')
        plt.ylabel('Accuracy')
        plt.title('Model Performance Comparison')
        plt.xticks(x, model_names, rotation=45)
        plt.legend()
        plt.ylim(0, 1)
        
        plt.tight_layout()
        plt.savefig('model_evaluation.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        return best_model_name, best_model_info['model']
    
    def feature_importance_analysis(self, best_model_name, best_model):
        """Analyze feature importance"""
        print("\n=== Feature Importance Analysis ===")
        
        if hasattr(best_model, 'feature_importances_'):
            importances = best_model.feature_importances_
            
            # Create feature importance dataframe
            feature_imp = pd.DataFrame({
                'feature': self.feature_names,
                'importance': importances
            }).sort_values('importance', ascending=False)
            
            print("\nTop 10 Most Important Features:")
            print(feature_imp.head(10))
            
            # Plot feature importance
            plt.figure(figsize=(10, 6))
            top_features = feature_imp.head(15)
            plt.barh(range(len(top_features)), top_features['importance'])
            plt.yticks(range(len(top_features)), top_features['feature'])
            plt.xlabel('Feature Importance')
            plt.title(f'Feature Importance - {best_model_name}')
            plt.gca().invert_yaxis()
            plt.tight_layout()
            plt.savefig('feature_importance.png', dpi=300, bbox_inches='tight')
            plt.show()
        
        else:
            print(f"{best_model_name} does not support feature importance analysis")
    
    def save_model(self, model, model_name):
        """Save the trained model"""
        model_filename = f"protocol_classifier_{model_name.lower().replace(' ', '_')}.joblib"
        scaler_filename = "feature_scaler.joblib"
        encoder_filename = "label_encoder.joblib"
        
        joblib.dump(model, model_filename)
        joblib.dump(self.scaler, scaler_filename)
        joblib.dump(self.label_encoder, encoder_filename)
        
        print(f"\nModel saved as: {model_filename}")
        print(f"Scaler saved as: {scaler_filename}")
        print(f"Label encoder saved as: {encoder_filename}")
        
        return model_filename

def main():
    # Initialize classifier
    classifier = ProtocolClassifier()
    
    # Prepare data
    X, y = classifier.prepare_data()
    
    # Train models
    X_test, y_test = classifier.train_models(X, y)
    
    # Evaluate models
    best_model_name, best_model = classifier.evaluate_best_model()
    
    # Feature importance analysis
    classifier.feature_importance_analysis(best_model_name, best_model)
    
    # Save best model
    model_file = classifier.save_model(best_model, best_model_name)
    
    print(f"\n=== Training Complete ===")
    print(f"Best model: {best_model_name}")
    print(f"Model file: {model_file}")

if __name__ == "__main__":
    main()
