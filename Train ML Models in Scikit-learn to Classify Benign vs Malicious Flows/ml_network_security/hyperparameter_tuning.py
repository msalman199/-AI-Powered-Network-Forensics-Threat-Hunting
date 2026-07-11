import numpy as np
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import joblib

def tune_random_forest():
    """Perform hyperparameter tuning for Random Forest"""
    
    # Load data
    X = np.load('X_features.npy')
    y = np.load('y_labels.npy')
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Define parameter grid
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_depth': [10, 20, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4]
    }
    
    # Create Random Forest classifier
    rf = RandomForestClassifier(random_state=42)
    
    # Perform grid search
    print("Performing hyperparameter tuning...")
    grid_search = GridSearchCV(
        rf, param_grid, cv=3, scoring='roc_auc', 
        n_jobs=-1, verbose=1
    )
    
    grid_search.fit(X_train_scaled, y_train)
    
    # Get best model
    best_rf = grid_search.best_estimator_
    
    # Evaluate on test set
    y_pred = best_rf.predict(X_test_scaled)
    y_pred_proba = best_rf.predict_proba(X_test_scaled)[:, 1]
    auc_score = roc_auc_score(y_test, y_pred_proba)
    
    print(f"\nBest parameters: {grid_search.best_params_}")
    print(f"Best cross-validation AUC: {grid_search.best_score_:.4f}")
    print(f"Test set AUC: {auc_score:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Save tuned model
    joblib.dump(best_rf, 'tuned_model.pkl')
    joblib.dump(scaler, 'tuned_scaler.pkl')
    
    return best_rf, scaler

if __name__ == "__main__":
    best_model, scaler = tune_random_forest()
    print("Hyperparameter tuning completed!")
