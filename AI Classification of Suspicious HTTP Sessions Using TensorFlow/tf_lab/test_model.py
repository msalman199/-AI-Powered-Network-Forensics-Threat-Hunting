import pandas as pd
import numpy as np
import tensorflow as tf
import joblib
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
import matplotlib.pyplot as plt
import seaborn as sns

print("Loading trained model and test data...")

# Load the trained model and scaler
model = tf.keras.models.load_model('http_classifier_model.h5')
scaler = joblib.load('scaler.pkl')

# Load test data
test_df = pd.read_csv('new_test_sessions.csv')

print(f"Loaded test data with {len(test_df)} sessions")

# Prepare test features
feature_columns = [
    'method_encoded', 'status_code', 'user_agent_encoded',
    'avg_request_size', 'avg_response_size', 'session_duration',
    'requests_per_session', 'unique_paths', 'error_rate'
]

X_test = test_df[feature_columns].values
y_true = test_df['actual_label'].values

# Scale the test features
X_test_scaled = scaler.transform(X_test)

print("\nMaking predictions on new test data...")

# Make predictions
y_pred_prob = model.predict(X_test_scaled)
y_pred = (y_pred_prob > 0.5).astype(int).flatten()

# Calculate metrics
accuracy = np.mean(y_pred == y_true)
auc_score = roc_auc_score(y_true, y_pred_prob)

print(f"\nModel Performance on New Test Data:")
print(f"Accuracy: {accuracy:.4f}")
print(f"AUC Score: {auc_score:.4f}")

# Detailed classification report
print("\nDetailed Classification Report:")
print(classification_report(y_true, y_pred, target_names=['Normal', 'Suspicious']))

# Create visualizations
plt.figure(figsize=(15, 10))

# Confusion Matrix
plt.subplot(2, 3, 1)
cm = confusion_matrix(y_true, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Normal', 'Suspicious'],
            yticklabels=['Normal', 'Suspicious'])
plt.title('Confusion Matrix')
plt.xlabel('Predicted')
plt.ylabel('Actual')

# ROC Curve
plt.subplot(2, 3, 2)
fpr, tpr, _ = roc_curve(y_true, y_pred_prob)
plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {auc_score:.3f})')
plt.plot([0, 1], [0, 1], 'k--', label='Random Classifier')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend()

# Prediction Probability Distribution
plt.subplot(2, 3, 3)
plt.hist(y_pred_prob[y_true == 0], alpha=0.7, label='Normal', bins=20)
plt.hist(y_pred_prob[y_true == 1], alpha=0.7, label='Suspicious', bins=20)
plt.xlabel('Prediction Probability')
plt.ylabel('Frequency')
plt.title('Prediction Probability Distribution')
plt.legend()

# Feature Importance Analysis (using prediction variance)
plt.subplot(2, 3, 4)
feature_importance = []
baseline_pred = model.predict(X_test_scaled)

for i, feature in enumerate(feature_columns):
    X_test_modified = X_test_scaled.copy()
    X_test_modified[:, i] = np.random.permutation(X_test_modified[:, i])
    modified_pred = model.predict(X_test_modified)
    importance = np.mean(np.abs(baseline_pred - modified_pred))
    feature_importance.append(importance)

feature_df = pd.DataFrame({
    'feature': feature_columns,
    'importance': feature_importance
}).sort_values('importance', ascending=True)

plt.barh(feature_df['feature'], feature_df['importance'])
plt.xlabel('Feature Importance')
plt.title('Feature Importance Analysis')
plt.tight_layout()

# Session Analysis
plt.subplot(2, 3, 5)
session_analysis = test_df.copy()
session_analysis['predicted_prob'] = y_pred_prob.flatten()
session_analysis['predicted_label'] = y_pred

# Show distribution of predictions by actual label
normal_sessions = session_analysis[session_analysis['actual_label'] == 0]
suspicious_sessions = session_analysis[session_analysis['actual_label'] == 1]

plt.scatter(normal_sessions['requests_per_session'], normal_sessions['error_rate'], 
           c=normal_sessions['predicted_prob'], cmap='RdYlBu_r', alpha=0.6, label='Normal')
plt.scatter(suspicious_sessions['requests_per_session'], suspicious_sessions['error_rate'], 
           c=suspicious_sessions['predicted_prob'], cmap='RdYlBu_r', alpha=0.6, marker='^', label='Suspicious')
plt.xlabel('Requests per Session')
plt.ylabel('Error Rate')
plt.title('Session Classification Visualization')
plt.colorbar(label='Prediction Probability')
plt.legend()

# Model Confidence Analysis
plt.subplot(2, 3, 6)
confidence_scores = np.maximum(y_pred_prob, 1 - y_pred_prob).flatten()
correct_predictions = (y_pred == y_true)

plt.hist(confidence_scores[correct_predictions], alpha=0.7, label='Correct', bins=20)
plt.hist(confidence_scores[~correct_predictions], alpha=0.7, label='Incorrect', bins=20)
plt.xlabel('Model Confidence')
plt.ylabel('Frequency')
plt.title('Model Confidence Analysis')
plt.legend()

plt.tight_layout()
plt.savefig('test_results.png', dpi=300, bbox_inches='tight')
plt.show()

# Detailed session analysis
print("\nDetailed Session Analysis:")
print("\nTop 5 Most Suspicious Sessions (by prediction probability):")
top_suspicious = session_analysis.nlargest(5, 'predicted_prob')[
    ['session_id', 'predicted_prob', 'actual_label', 'requests_per_session', 'error_rate']
]
print(top_suspicious)

print("\nTop 5 Most Normal Sessions (by prediction probability):")
top_normal = session_analysis.nsmallest(5, 'predicted_prob')[
    ['session_id', 'predicted_prob', 'actual_label', 'requests_per_session', 'error_rate']
]
print(top_normal)

# Identify misclassified sessions
misclassified = session_analysis[session_analysis['predicted_label'] != session_analysis['actual_label']]
if len(misclassified) > 0:
    print(f"\nMisclassified Sessions ({len(misclassified)} total):")
    print(misclassified[['session_id', 'predicted_prob', 'predicted_label', 'actual_label', 
                        'requests_per_session', 'error_rate']].head(10))

print(f"\nTesting complete! Results saved as 'test_results.png'")
