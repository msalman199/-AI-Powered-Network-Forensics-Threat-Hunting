import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns

# Load data
df = pd.read_csv('data/tls_sessions.csv')
print("Dataset shape:", df.shape)
print("\nDataset info:")
print(df.info())
print("\nAnomaly distribution:")
print(df['is_anomaly'].value_counts())

# Display first few rows
print("\nFirst 5 rows:")
print(df.head())
