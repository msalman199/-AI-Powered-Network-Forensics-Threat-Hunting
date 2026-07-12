
def preprocess_features(df):
    """Preprocess TLS session features for LSTM"""
    
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Extract time-based features
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    
    # Encode categorical features
    le_cipher = LabelEncoder()
    le_tls_version = LabelEncoder()
    
    df['cipher_suite_encoded'] = le_cipher.fit_transform(df['cipher_suite'])
    df['tls_version_encoded'] = le_tls_version.fit_transform(df['tls_version'])
    
    # Create IP-based features (simplified)
    df['src_ip_last_octet'] = df['src_ip'].str.split('.').str[-1].astype(int)
    df['dst_ip_class'] = df['dst_ip'].str.split('.').str[0].astype(int)
    
    # Select numerical features for LSTM
    feature_columns = [
        'handshake_time', 'cert_size', 'session_duration',
        'bytes_sent', 'bytes_received', 'src_port',
        'cipher_suite_encoded', 'tls_version_encoded',
        'hour', 'day_of_week', 'src_ip_last_octet', 'dst_ip_class'
    ]
    
    return df[feature_columns + ['is_anomaly']], le_cipher, le_tls_version

# Preprocess data
processed_df, cipher_encoder, tls_encoder = preprocess_features(df)
print("\nProcessed features shape:", processed_df.shape)
print("\nFeature columns:", processed_df.columns.tolist())

# Save encoders for later use
import pickle
with open('data/encoders.pkl', 'wb') as f:
    pickle.dump({'cipher': cipher_encoder, 'tls': tls_encoder}, f)

def create_sequences(data, sequence_length=10):
    """Create sequences for LSTM training"""
    
    features = data.drop('is_anomaly', axis=1).values
    labels = data['is_anomaly'].values
    
    # Normalize features
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    # Create sequences
    X, y = [], []
    for i in range(len(features_scaled) - sequence_length + 1):
        X.append(features_scaled[i:(i + sequence_length)])
        y.append(labels[i + sequence_length - 1])
    
    return np.array(X), np.array(y), scaler

# Create sequences
sequence_length = 10
X, y, scaler = create_sequences(processed_df, sequence_length)

print(f"\nSequence shape: {X.shape}")
print(f"Labels shape: {y.shape}")

# Save scaler
with open('data/scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"\nTraining set: {X_train.shape}, {y_train.shape}")
print(f"Test set: {X_test.shape}, {y_test.shape}")

# Save processed data
np.save('data/X_train.npy', X_train)
np.save('data/X_test.npy', X_test)
np.save('data/y_train.npy', y_train)
np.save('data/y_test.npy', y_test)

print("\nData preprocessing completed!")
