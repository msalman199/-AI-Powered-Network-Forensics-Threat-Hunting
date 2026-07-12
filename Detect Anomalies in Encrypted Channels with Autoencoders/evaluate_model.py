# evaluate_model.py
import tensorflow as tf
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
import pickle
import seaborn as sns

class ModelEvaluator:
    def __init__(self):
        self.model = tf.keras.models.load_model('anomaly_autoencoder.h5')
        with open('threshold.pkl', 'rb') as f:
            self.threshold = pickle.load(f)
    
    def evaluate_performance(self, X_test, y_test):
        """Evaluate the autoencoder's anomaly detection performance"""
        # Get predictions
        predictions = self.model.predict(X_test)
        mse = np.mean(np.power(X_test - predictions, 2), axis=1)
        y_pred = (mse > self.threshold).astype(int)
        
        # Print classification report
        print("Classification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=['Normal', 'Anomaly']))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=['Normal', 'Anomaly'],
                   yticklabels=['Normal', 'Anomaly'])
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        # ROC curve
        fpr, tpr, _ = roc_curve(y_test, mse)
        roc_auc = auc(fpr, tpr)
        
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (AUC = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curve for Anomaly Detection')
        plt.legend(loc="lower right")
        plt.savefig('roc_curve.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        return mse, y_pred, roc_auc
    
    def analyze_reconstruction_errors(self, X_test, y_test, mse):
        """Analyze reconstruction errors for different traffic types"""
        plt.figure(figsize=(12, 8))
        
        # Plot reconstruction errors
        normal_errors = mse[y_test == 0]
        anomaly_errors = mse[y_test == 1]
        
        plt.subplot(2, 2, 1)
        plt.hist(normal_errors, bins=50, alpha=0.7, label='Normal Traffic', color='blue')
        plt.hist(anomaly_errors, bins=50, alpha=0.7, label='Anomalous Traffic', color='red')
        plt.axvline(self.threshold, color='black', linestyle='--', label='Threshold')
        plt.xlabel('Reconstruction Error (MSE)')
        plt.ylabel('Frequency')
        plt.title('Distribution of Reconstruction Errors')
        plt.legend()
        
        # Box plot
        plt.subplot(2, 2, 2)
        data_to_plot = [normal_errors, anomaly_errors]
        plt.boxplot(data_to_plot, labels=['Normal', 'Anomaly'])
        plt.axhline(self.threshold, color='red', linestyle='--', label='Threshold')
        plt.ylabel('Reconstruction Error (MSE)')
        plt.title('Reconstruction Error Distribution')
        plt.legend()
        
        # Error over samples
        plt.subplot(2, 1, 2)
        plt.plot(mse, alpha=0.7)
        plt.axhline(self.threshold, color='red', linestyle='--', label='Threshold')
        colors = ['blue' if label == 0 else 'red' for label in y_test]
        plt.scatter(range(len(mse)), mse, c=colors, alpha=0.6, s=10)
        plt.xlabel('Sample Index')
        plt.ylabel('Reconstruction Error (MSE)')
        plt.title('Reconstruction Errors Across Test Samples')
        plt.legend(['Reconstruction Error', 'Threshold', 'Normal', 'Anomaly'])
        
        plt.tight_layout()
        plt.savefig('reconstruction_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()

# Load test data
X_test = np.load('X_test.npy')
y_test = np.load('y_test.npy')

# Evaluate model
evaluator = ModelEvaluator()
mse, y_pred, roc_auc = evaluator.evaluate_performance(X_test, y_test)

print(f"\nModel Performance Summary:")
print(f"ROC AUC Score: {roc_auc:.3f}")
print(f"Threshold used: {evaluator.threshold:.6f}")

# Analyze reconstruction errors
evaluator.analyze_reconstruction_errors(X_test, y_test, mse)

print("Evaluation complete. Check generated plots for detailed analysis.")
