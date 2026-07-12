import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
import pickle

class DataPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.feature_columns = ['packet_size', 'inter_arrival_time', 
                               'flow_duration', 'bytes_per_second', 'entropy']
    
    def prepare_data(self, filepath):
        """Load and preprocess the traffic data"""
        df = pd.read_csv(filepath)
        
        # Extract features (exclude label for unsupervised learning)
        X = df[self.feature_columns].values
        y = df['label'].values
        
        # Handle any infinite or NaN values
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        # Split data - use only normal traffic for training autoencoder
        X_train_full, X_test, y_train_full, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        # For autoencoder training, use only normal traffic
        normal_mask = y_train_full == 0
        X_train_normal = X_train_full[normal_mask]
        
        # Scale the data
        X_train_scaled = self.scaler.fit_transform(X_train_normal)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Save scaler for later use
        with open('scaler.pkl', 'wb') as f:
            pickle.dump(self.scaler, f)
        
        return X_train_scaled, X_test_scaled, y_test, X_train_normal.shape[0]

# Preprocess the data
preprocessor = DataPreprocessor()
X_train, X_test, y_test, normal_samples = preprocessor.prepare_data('encrypted_traffic_dataset.csv')

print(f"Training samples (normal only): {X_train.shape[0]}")
print(f"Test samples: {X_test.shape[0]}")
print(f"Feature dimensions: {X_train.shape[1]}")

# Save preprocessed data
np.save('X_train.npy', X_train)
np.save('X_test.npy', X_test)
np.save('y_test.npy', y_test)

print("Data preprocessing complete.")
