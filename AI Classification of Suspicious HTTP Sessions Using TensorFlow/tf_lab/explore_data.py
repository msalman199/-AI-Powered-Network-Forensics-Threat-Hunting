import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the dataset
df = pd.read_csv('http_sessions.csv')

print("Dataset Information:")
print(f"Shape: {df.shape}")
print(f"Columns: {list(df.columns)}")
print("\nDataset Statistics:")
print(df.describe())

print("\nClass Distribution:")
print(df['is_suspicious'].value_counts())

# Create visualizations
plt.figure(figsize=(15, 10))

# Plot 1: Class distribution
plt.subplot(2, 3, 1)
df['is_suspicious'].value_counts().plot(kind='bar')
plt.title('Class Distribution')
plt.xlabel('Class (0=Normal, 1=Suspicious)')
plt.ylabel('Count')

# Plot 2: Request size distribution
plt.subplot(2, 3, 2)
plt.hist(df[df['is_suspicious']==0]['avg_request_size'], alpha=0.7, label='Normal', bins=30)
plt.hist(df[df['is_suspicious']==1]['avg_request_size'], alpha=0.7, label='Suspicious', bins=30)
plt.title('Average Request Size Distribution')
plt.xlabel('Request Size')
plt.ylabel('Frequency')
plt.legend()

# Plot 3: Session duration
plt.subplot(2, 3, 3)
plt.hist(df[df['is_suspicious']==0]['session_duration'], alpha=0.7, label='Normal', bins=30)
plt.hist(df[df['is_suspicious']==1]['session_duration'], alpha=0.7, label='Suspicious', bins=30)
plt.title('Session Duration Distribution')
plt.xlabel('Duration')
plt.ylabel('Frequency')
plt.legend()

# Plot 4: Requests per session
plt.subplot(2, 3, 4)
plt.hist(df[df['is_suspicious']==0]['requests_per_session'], alpha=0.7, label='Normal', bins=30)
plt.hist(df[df['is_suspicious']==1]['requests_per_session'], alpha=0.7, label='Suspicious', bins=30)
plt.title('Requests per Session Distribution')
plt.xlabel('Requests per Session')
plt.ylabel('Frequency')
plt.legend()

# Plot 5: Error rate
plt.subplot(2, 3, 5)
plt.hist(df[df['is_suspicious']==0]['error_rate'], alpha=0.7, label='Normal', bins=30)
plt.hist(df[df['is_suspicious']==1]['error_rate'], alpha=0.7, label='Suspicious', bins=30)
plt.title('Error Rate Distribution')
plt.xlabel('Error Rate')
plt.ylabel('Frequency')
plt.legend()

# Plot 6: Correlation heatmap
plt.subplot(2, 3, 6)
correlation_matrix = df.select_dtypes(include=[np.number]).corr()
sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0, fmt='.2f')
plt.title('Feature Correlation Heatmap')

plt.tight_layout()
plt.savefig('data_exploration.png', dpi=300, bbox_inches='tight')
plt.show()

print("\nData exploration complete. Visualization saved as 'data_exploration.png'")
