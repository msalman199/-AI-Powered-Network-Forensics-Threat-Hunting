import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix
import pickle

class AnomalyAutoencoder:
    def __init__(self, input_dim):
        self.input_dim = input_dim
        self.model = None
        self.threshold = None
        
    def build_model(self):
        """Build the autoencoder architecture"""
        # Encoder
        input_layer = keras.Input(shape=(self.input_dim,))
        encoded = layers.Dense(32, activation='relu')(input_layer)
        encoded = layers.Dense(16, activation='relu')(encoded)
        encoded = layers.Dense(8, activation='relu')(encoded)  # Bottleneck
        
        # Decoder
        decoded = layers.Dense(16, activation='relu')(encoded)
        decoded = layers.Dense(32, activation='relu')(decoded)
        decoded = layers.Dense(self.input_dim, activation='linear')(decoded)
        
        # Create autoencoder
        self.model = keras.Model(input_layer, decoded)
        self.model.compile(optimizer='adam', loss='mse', metrics=['mae'])
        
        return self.model
    
    def train(self, X_train, epochs=100, batch_size=32, validation_split=0.2):
        """Train the autoencoder"""
        if self.model is None:
            self.build_model()
        
        # Add early stopping
        early_stopping = keras.callbacks.EarlyStopping(
            monitor='val_loss', patience=10, restore_best_weights=True
        )
        
        # Train the model
        history = self.model.fit(
            X_train, X_train,  # Autoencoder learns to reconstruct input
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            callbacks=[early_stopping],
            verbose=1
        )
        
        return history
    
    def calculate_threshold(self, X_train, percentile=95):
        """Calculate anomaly threshold based on reconstruction error"""
        predictions = self.model.predict(X_train)
        mse = np.mean(np.power(X_train - predictions, 2), axis=1)
        self.threshold = np.percentile(mse, percentile)
        return self.threshold
    
    def predict_anomalies(self, X_test):
        """Predict anomalies based on reconstruction error"""
        predictions = self.model.predict(X_test)
        mse = np.mean(np.power(X_test - predictions, 2), axis=1)
        anomalies = mse > self.threshold
        return anomalies, mse

# Load preprocessed data
X_train = np.load('X_train.npy')
X_test = np.load('X_test.npy')
y_test = np.load('y_test.npy')

print(f"Training autoencoder with {X_train.shape[0]} normal samples...")

# Create and train autoencoder
autoencoder = AnomalyAutoencoder(input_dim=X_train.shape[1])
model = autoencoder.build_model()

print("Model Architecture:")
model.summary()

# Train the model
history = autoencoder.train(X_train, epochs=50, batch_size=32)

# Calculate threshold
threshold = autoencoder.calculate_threshold(X_train, percentile=95)
print(f"Anomaly threshold: {threshold:.6f}")

# Save the trained model
model.save('anomaly_autoencoder.h5')
with open('threshold.pkl', 'wb') as f:
    pickle.dump(threshold, f)

print("Model training complete and saved.")
