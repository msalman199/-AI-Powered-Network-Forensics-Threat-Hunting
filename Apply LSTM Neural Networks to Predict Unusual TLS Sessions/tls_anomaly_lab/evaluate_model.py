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
