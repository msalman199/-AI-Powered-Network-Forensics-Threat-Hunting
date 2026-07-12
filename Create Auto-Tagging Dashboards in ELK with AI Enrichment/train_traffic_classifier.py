import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
import json

# Generate synthetic network traffic data for training
np.random.seed(42)
n_samples = 10000

# Create synthetic features
data = {
    'src_port': np.random.randint(1, 65536, n_samples),
    'dst_port': np.random.randint(1, 65536, n_samples),
    'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n_samples),
    'bytes': np.random.exponential(1000, n_samples),
    'packets': np.random.poisson(10, n_samples),
    'duration': np.random.exponential(5, n_samples)
}

df = pd.DataFrame(data)

# Create labels based on port patterns (simplified classification)
def classify_traffic(row):
    if row['dst_port'] in [80, 443, 8080, 8443]:
        return 'web'
    elif row['dst_port'] in [22, 23, 3389]:
        return 'remote_access'
    elif row['dst_port'] in [25, 110, 143, 993, 995]:
        return 'email'
    elif row['dst_port'] in [53]:
        return 'dns'
    elif row['dst_port'] in [21, 22]:
        return 'file_transfer'
    elif row['bytes'] > 10000 and row['packets'] > 100:
        return 'bulk_transfer'
    elif row['packets'] < 5 and row['duration'] < 1:
        return 'scan'
    else:
        return 'other'

df['traffic_type'] = df.apply(classify_traffic, axis=1)

# Encode categorical variables
le_protocol = LabelEncoder()
df['protocol_encoded'] = le_protocol.fit_transform(df['protocol'])

# Prepare features and target
features = ['src_port', 'dst_port', 'protocol_encoded', 'bytes', 'packets', 'duration']
X = df[features]
y = df['traffic_type']

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# Save model and encoders
joblib.dump(rf_model, 'traffic_classifier.pkl')
joblib.dump(le_protocol, 'protocol_encoder.pkl')

print(f"Model trained with accuracy: {rf_model.score(X_test, y_test):.3f}")
print("Model saved as traffic_classifier.pkl")
