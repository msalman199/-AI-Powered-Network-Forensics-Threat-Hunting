import numpy as np
import tensorflow as tf
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
import matplotlib.pyplot as plt
import seaborn as sns
import pickle

# Load test data and model
X_test = np.load('data/X_test.npy')
y_test = np.load('data/y_test.npy')
model = tf.keras.models.load_model('data/lstm_tls_anomaly_model.h5')

print("Model loaded successfully!")
print(f"Test data shape: {X_test.shape}")

# Make predictions
print("\nMaking predictions...")
y_pred_proba = model.predict(X_test)
y_pred = (y_pred_proba > 0.5).astype(int).flatten()

print(f"Predictions shape: {y_pred.shape}")
print(f"Prediction probabilities range: {y_pred_proba.min():.4f} - {y_pred_proba.max():.4f}")
# Continue in evaluate_model.py

def plot_evaluation_results(y_true, y_pred, y_pred_proba, cm, auc_score):
    """Plot comprehensive evaluation results"""
    
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    
    # Confusion Matrix
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Normal', 'Anomaly'],
                yticklabels=['Normal', 'Anomaly'],
                ax=axes[0, 0])
    axes[0, 0].set_title('Confusion Matrix')
    axes[0, 0].set_xlabel('Predicted')
    axes[0, 0].set_ylabel('Actual')
    
    # ROC Curve
    fpr, tpr, _ = roc_curve(y_true, y_pred_proba)
    axes[0, 1].plot(fpr, tpr, label=f'ROC Curve (AUC = {auc_score:.4f})')
    axes[0, 1].plot([0, 1], [0, 1], 'k--', label='Random')
    axes[0, 1].set_xlabel('False Positive Rate')
    axes[0, 1].set_ylabel('True Positive Rate')
    axes[0, 1].set_title('ROC Curve')
    axes[0, 1].legend()
    axes[0, 1].grid(True)
    
    # Prediction Distribution
    axes[1, 0].hist(y_pred_proba[y_true == 0], bins=50, alpha=0.7, 
                    label='Normal Sessions', color='blue')
    axes[1, 0].hist(y_pred_proba[y_true == 1], bins=50, alpha=0.7, 
                    label='Anomalous Sessions', color='red')
    axes[1, 0].axvline(x=0.5, color='black', linestyle='--', label='Threshold')
    axes[1, 0].set_xlabel('Prediction Probability')
    axes[1, 0].set_ylabel('Frequency')
    axes[1, 0].set_title('Prediction Probability Distribution')
    axes[1, 0].legend()
    
    # Feature Importance (simplified visualization)
    # Show prediction confidence over time
    axes[1, 1].plot(y_pred_proba[:100], label='Prediction Confidence')
    axes[1, 1].scatter(range(100), y_true[:100], c=y_true[:100], 
                       cmap='coolwarm', alpha=0.6, label='True Labels')
    axes[1, 1].axhline(y=0.5, color='black', linestyle='--', alpha=0.5)
    axes[1, 1].set_xlabel('Sample Index')
    axes[1, 1].set_ylabel('Prediction Probability')
    axes[1, 1].set_title('Prediction Confidence (First 100 samples)')
    axes[1, 1].legend()
    
    plt.tight_layout()
    plt.savefig('data/evaluation_results.png', dpi=300, bbox_inches='tight')
    plt.show()

# Plot results
plot_evaluation_results(y_test, y_pred, y_pred_proba, cm, auc_score)
# Continue in evaluate_model.py

def analyze_anomalies(X_test, y_test, y_pred, y_pred_proba):
    """Analyze detected anomalies"""
    
    # Find false positives and false negatives
    fp_indices = np.where((y_test == 0) & (y_pred == 1))[0]
    fn_indices = np.where((y_test == 1) & (y_pred == 0))[0]
    tp_indices = np.where((y_test == 1) & (y_pred == 1))[0]
    tn_indices = np.where((y_test == 0) & (y_pred == 0))[0]
    
    print(f"\nAnomaly Detection Analysis:")
    print(f"True Positives: {len(tp_indices)}")
    print(f"True Negatives: {len(tn_indices)}")
    print(f"False Positives: {len(fp_indices)}")
    print(f"False Negatives: {len(fn_indices)}")
    
    # Calculate detection rates
    total_anomalies = np.sum(y_test == 1)
    total_normal = np.sum(y_test == 0)
    
    detection_rate = len(tp_indices) / total_anomalies if total_anomalies > 0 else 0
    false_alarm_rate = len(fp_indices) / total_normal if total_normal > 0 else 0
    
    print(f"\nDetection Rate: {detection_rate:.4f} ({detection_rate*100:.2f}%)")
    print(f"False Alarm Rate: {false_alarm_rate:.4f} ({false_alarm_rate*100:.2f}%)")
    
    # Show confidence distribution for different prediction types
    if len(tp_indices) > 0:
        print(f"\nTrue Positive Confidence: {np.mean(y_pred_proba[tp_indices]):.4f} ± {np.std(y_pred_proba[tp_indices]):.4f}")
    if len(fp_indices) > 0:
        print(f"False Positive Confidence: {np.mean(y_pred_proba[fp_indices]):.4f} ± {np.std(y_pred_proba[fp_indices]):.4f}")
    if len(fn_indices) > 0:
        print(f"False Negative Confidence: {np.mean(y_pred_proba[fn_indices]):.4f} ± {np.std(y_pred_proba[fn_indices]):.4f}")

# Analyze anomalies
analyze_anomalies(X_test, y_test, y_pred, y_pred_proba)

print("\nModel evaluation completed!")

