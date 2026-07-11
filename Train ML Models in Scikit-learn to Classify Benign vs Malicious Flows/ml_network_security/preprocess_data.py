import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split

# Define column names for KDD dataset
columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
           'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
           'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
           'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
           'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
           'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
           'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
           'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
           'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
           'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type', 'difficulty']

def load_and_preprocess_data():
    # Load training data
    train_data = pd.read_csv('kdd_train.txt', names=columns, header=None)
    test_data = pd.read_csv('kdd_test.txt', names=columns, header=None)
    
    # Combine datasets for consistent preprocessing
    combined_data = pd.concat([train_data, test_data], ignore_index=True)
    
    # Create binary classification: normal vs attack
    combined_data['is_malicious'] = (combined_data['attack_type'] != 'normal').astype(int)
    
    # Remove unnecessary columns
    features_to_drop = ['attack_type', 'difficulty']
    X = combined_data.drop(features_to_drop + ['is_malicious'], axis=1)
    y = combined_data['is_malicious']
    
    # Handle categorical variables
    categorical_columns = ['protocol_type', 'service', 'flag']
    label_encoders = {}
    
    for col in categorical_columns:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        label_encoders[col] = le
    
    # Handle missing values
    X = X.fillna(X.median())
    
    print(f"Dataset shape: {X.shape}")
    print(f"Malicious samples: {y.sum()}")
    print(f"Benign samples: {len(y) - y.sum()}")
    
    return X, y, label_encoders

if __name__ == "__main__":
    X, y, encoders = load_and_preprocess_data()
    
    # Save preprocessed data
    np.save('X_features.npy', X.values)
    np.save('y_labels.npy', y.values)
    
    print("Data preprocessing completed successfully!")
