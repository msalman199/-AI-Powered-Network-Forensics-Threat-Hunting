import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler

def load_model():
    """Load the trained model and scaler"""
    try:
        model = joblib.load('tuned_model.pkl')
        scaler = joblib.load('tuned_scaler.pkl')
        print("Loaded tuned model")
    except:
        model = joblib.load('best_model.pkl')
        scaler = joblib.load('scaler.pkl')
        print("Loaded best model")
    
    return model, scaler

def predict_single_flow(model, scaler, flow_features):
    """Predict if a single network flow is malicious"""
    
    # Ensure input is 2D array
    if len(flow_features.shape) == 1:
        flow_features = flow_features.reshape(1, -1)
    
    # Scale features
    flow_scaled = scaler.transform(flow_features)
    
    # Make prediction
    prediction = model.predict(flow_scaled)[0]
    probability = model.predict_proba(flow_scaled)[0]
    
    return prediction, probability

def demo_predictions():
    """Demonstrate predictions on sample data"""
    
    # Load model
    model, scaler = load_model()
    
    # Load test data for demonstration
    X = np.load('X_features.npy')
    y = np.load('y_labels.npy')
    
    # Select random samples for demonstration
    np.random.seed(42)
    sample_indices = np.random.choice(len(X), 5, replace=False)
    
    print("=" * 60)
    print("NETWORK FLOW CLASSIFICATION DEMO")
    print("=" * 60)
    
    for i, idx in enumerate(sample_indices):
        flow = X[idx]
        actual_label = y[idx]
        
        prediction, probabilities = predict_single_flow(model, scaler, flow)
        
        print(f"\nSample {i+1}:")
        print(f"Actual Label: {'Malicious' if actual_label == 1 else 'Benign'}")
        print(f"Predicted Label: {'Malicious' if prediction == 1 else 'Benign'}")
        print(f"Confidence - Benign: {probabilities[0]:.3f}, Malicious: {probabilities[1]:.3f}")
        print(f"Correct: {'✓' if prediction == actual_label else '✗'}")
        print("-" * 40)

if __name__ == "__main__":
    demo_predictions()
