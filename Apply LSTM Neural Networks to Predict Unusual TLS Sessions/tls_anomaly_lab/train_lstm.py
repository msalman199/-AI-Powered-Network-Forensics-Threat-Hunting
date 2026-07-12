import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, BatchNormalization
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Load preprocessed data
X_train = np.load('data/X_train.npy')
X_test = np.load('data/X_test.npy')
y_train = np.load('data/y_train.npy')
y_test = np.load('data/y_test.npy')

print(f"Training data shape: {X_train.shape}")
print(f"Test data shape: {X_test.shape}")

def build_lstm_model(input_shape):
    """Build LSTM model for anomaly detection"""
    
    model = Sequential([
        # First LSTM layer
        LSTM(64, return_sequences=True, input_shape=input_shape),
        BatchNormalization(),
        Dropout(0.3),
        
        # Second LSTM layer
        LSTM(32, return_sequences=False),
        BatchNormalization(),
        Dropout(0.3),
        
        # Dense layers
        Dense(16, activation='relu'),
        Dropout(0.2),
        Dense(1, activation='sigmoid')
    ])
    
    # Compile model
    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy', 'precision', 'recall']
    )
    
    return model

# Build model
input_shape = (X_train.shape[1], X_train.shape[2])
model = build_lstm_model(input_shape)

print("\nModel architecture:")


# Define callbacks
callbacks = [
    EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True
    ),
    ReduceLROnPlateau(
        monitor='val_loss',
        factor=0.5,
        patience=5,
        min_lr=0.0001
    )
]

# Train model
print("\nTraining LSTM model...")
history = model.fit(
    X_train, y_train,
    batch_size=32,
    epochs=50,
    validation_split=0.2,
    callbacks=callbacks,
    verbose=1
)

# Save trained model
model.save('data/lstm_tls_anomaly_model.h5')
print("\nModel saved successfully!")
