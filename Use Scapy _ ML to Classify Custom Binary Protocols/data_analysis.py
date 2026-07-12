# Create file: data_analysis.py
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def analyze_protocol_features(csv_file="protocol_features.csv"):
    """Analyze extracted protocol features"""
    df = pd.read_csv(csv_file)
    
    print("=== Protocol Feature Analysis ===")
    print(f"Total packets: {len(df)}")
    print(f"Features per packet: {len(df.columns) - 2}")  # Exclude packet_id and label
    
    # Protocol distribution
    print("\nProtocol Distribution:")
    protocol_counts = df['protocol_label'].value_counts()
    print(protocol_counts)
    
    # Remove Unknown protocols for cleaner analysis
    df_clean = df[df['protocol_label'] != 'Unknown'].copy()
    
    if len(df_clean) == 0:
        print("No labeled protocols found!")
        return df
    
    # Statistical summary by protocol
    print("\n=== Feature Statistics by Protocol ===")
    numeric_cols = df_clean.select_dtypes(include=[np.number]).columns
    numeric_cols = [col for col in numeric_cols if col not in ['packet_id']]
    
    for protocol in df_clean['protocol_label'].unique():
        print(f"\n--- {protocol} ---")
        proto_data = df_clean[df_clean['protocol_label'] == protocol][numeric_cols]
        print(f"Packets: {len(proto_data)}")
        print(f"Avg payload length: {proto_data['payload_len'].mean():.2f}")
        print(f"Avg entropy: {proto_data['payload_entropy'].mean():.2f}")
        print(f"Avg packet size: {proto_data['packet_size'].mean():.2f}")
    
    # Create visualizations
    plt.figure(figsize=(15, 10))
    
    # Protocol distribution pie chart
    plt.subplot(2, 3, 1)
    protocol_counts.plot(kind='pie', autopct='%1.1f%%')
    plt.title('Protocol Distribution')
    plt.ylabel('')
    
    # Payload length distribution
    plt.subplot(2, 3, 2)
    for protocol in df_clean['protocol_label'].unique():
        data = df_clean[df_clean['protocol_label'] == protocol]['payload_len']
        plt.hist(data, alpha=0.7, label=protocol, bins=10)
    plt.xlabel('Payload Length')
    plt.ylabel('Frequency')
    plt.title('Payload Length Distribution')
    plt.legend()
    
    # Entropy distribution
    plt.subplot(2, 3, 3)
    for protocol in df_clean['protocol_label'].unique():
        data = df_clean[df_clean['protocol_label'] == protocol]['payload_entropy']
        plt.hist(data, alpha=0.7, label=protocol, bins=10)
    plt.xlabel('Payload Entropy')
    plt.ylabel('Frequency')
    plt.title('Payload Entropy Distribution')
    plt.legend()
    
    # Packet size vs payload length scatter
    plt.subplot(2, 3, 4)
    for protocol in df_clean['protocol_label'].unique():
        data = df_clean[df_clean['protocol_label'] == protocol]
        plt.scatter(data['packet_size'], data['payload_len'], 
                   alpha=0.6, label=protocol, s=30)
    plt.xlabel('Packet Size')
    plt.ylabel('Payload Length')
    plt.title('Packet Size vs Payload Length')
    plt.legend()
    
    # Port usage
    plt.subplot(2, 3, 5)
    port_data = df_clean.groupby(['protocol_label', 'dst_port']).size().unstack(fill_value=0)
    port_data.plot(kind='bar', stacked=True)
    plt.title('Port Usage by Protocol')
    plt.xlabel('Protocol')
    plt.ylabel('Packet Count')
    plt.xticks(rotation=45)
    
    # Feature correlation heatmap
    plt.subplot(2, 3, 6)
    correlation_features = ['packet_size', 'payload_len', 'payload_entropy', 
                           'payload_mean', 'unique_bytes']
    corr_matrix = df_clean[correlation_features].corr()
    sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', center=0, 
                square=True, fmt='.2f')
    plt.title('Feature Correlation Matrix')
    
    plt.tight_layout()
    plt.savefig('protocol_analysis.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    return df_clean

if __name__ == "__main__":
    df = analyze_protocol_features()
    print("\nAnalysis completed! Check 'protocol_analysis.png' for visualizations.")
