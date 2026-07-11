import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import GridSearchCV
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

def load_preprocessed_data():
    """Load the preprocessed features and labels"""
    X = np.load('X_features.npy')
    y = np.load('y_labels.npy')
    return X, y

def train_and_evaluate_models(X, y):
    """Train multiple models and compare performance"""
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Define models
    models = {
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
        'Logistic Regression': LogisticRegression(random_state=42, max_iter=1000),
        'SVM': SVC(random_state=42, probability=True)
    }
    
    results = {}
    
    print("Training and evaluating models...")
    print("=" * 50)
    
    for name, model in models.items():
        print(f"\nTraining {name}...")
        
        # Train model
        if name == 'SVM':
            # Use subset for SVM due to computational complexity
            subset_size = min(10000, len(X_train_scaled))
            indices = np.random.choice(len(X_train_scaled), subset_size, replace=False)
            model.fit(X_train_scaled[indices], y_train[indices])
        else:
            model.fit(X_train_scaled, y_train)
        
        # Make predictions
        y_pred = model.predict(X_test_scaled)
        y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
        
        # Calculate metrics
        auc_score = roc_auc_score(y_test, y_pred_proba)
        
        # Store results
        results[name] = {
            'model': model,
            'predictions': y_pred,
            'probabilities': y_pred_proba,
            'auc_score': auc_score
        }
        
        print(f"{name} AUC Score: {auc_score:.4f}")
        print(f"\nClassification Report for {name}:")
        print(classification_report(y_test, y_pred))
        print("-" * 50)
    
    # Save best model (highest AUC)
    best_model_name = max(results.keys(), key=lambda k: results[k]['auc_score'])
    best_model = results[best_model_name]['model']
    
    joblib.dump(best_model, 'best_model.pkl')
    joblib.dump(scaler, 'scaler.pkl')
    
    print(f"\nBest model: {best_model_name} (AUC: {results[best_model_name]['auc_score']:.4f})")
    
    return results, X_test, y_test, scaler

def plot_confusion_matrices(results, y_test):
    """Plot confusion matrices for all models"""
    fig, axes = plt.subplots(1, len(results), figsize=(15, 4))
    
    for idx, (name, result) in enumerate(results.items()):
        cm = confusion_matrix(y_test, result['predictions'])
        sns.heatmap(cm, annot=True, fmt='d', ax=axes[idx], cmap='Blues')
        axes[idx].set_title(f'{name}\nAUC: {result["auc_score"]:.3f}')
        axes[idx].set_xlabel('Predicted')
        axes[idx].set_ylabel('Actual')
    
    plt.tight_layout()
    plt.savefig('confusion_matrices.png', dpi=300, bbox_inches='tight')
    plt.show()
    print("Confusion matrices saved as 'confusion_matrices.png'")

if __name__ == "__main__":
    # Load data
    X, y = load_preprocessed_data()
    
    # Train and evaluate models
    results, X_test, y_test, scaler = train_and_evaluate_models(X, y)
    
    # Plot results
    plot_confusion_matrices(results, y_test)
