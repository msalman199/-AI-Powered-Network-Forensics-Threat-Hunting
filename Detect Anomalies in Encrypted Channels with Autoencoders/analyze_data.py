import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load and examine the dataset
df = pd.read_csv('encrypted_traffic_dataset.csv')

print("Dataset Overview:")
print(df.describe())
print("\nClass Distribution:")
print(df['label'].value_counts())

# Visualize feature distributions
fig, axes = plt.subplots(2, 3, figsize=(15, 10))
features = ['packet_size', 'inter_arrival_time', 'flow_duration', 
           'bytes_per_second', 'entropy']

for i, feature in enumerate(features):
    row, col = i // 3, i % 3
    
    # Plot normal vs anomaly distributions
    normal_data = df[df['label'] == 0][feature]
    anomaly_data = df[df['label'] == 1][feature]
    
    axes[row, col].hist(normal_data, alpha=0.7, label='Normal', bins=30)
    axes[row, col].hist(anomaly_data, alpha=0.7, label='Anomaly', bins=30)
    axes[row, col].set_title(f'{feature} Distribution')
    axes[row, col].legend()

plt.tight_layout()
plt.savefig('traffic_analysis.png', dpi=300, bbox_inches='tight')
plt.show()

print("Analysis complete. Check traffic_analysis.png for visualizations.")
