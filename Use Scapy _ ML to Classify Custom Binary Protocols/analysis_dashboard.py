import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def create_analysis_dashboard():
    """Create a comprehensive analysis dashboard"""
    
    # Load all data
    try:
        features_df = pd.read_csv("protocol_features.csv")
        results_df = pd.read_csv("realtime_classification_results.csv")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please ensure you have run the previous steps to generate the required CSV files.")
        return
    
    # Create comprehensive dashboard
    fig = plt.figure(figsize=(20, 15))
    
    # 1. Protocol Distribution (Training Data)
    plt.subplot(3, 4, 1)
    train_protocols = features_df[features_df['protocol_label'] != 'Unknown']['protocol_label'].value_counts()
    plt.pie(train_protocols.values, labels=train_protocols.index, autopct='%1.1f%%')
    plt.title('Training Data\nProtocol Distribution')
    
    # 2. Classification Results Distribution
    plt.subplot(3, 4, 2)
    test_protocols = results_df['protocol'].value_counts()
    plt.pie(test_protocols.values, labels=test_protocols.index, autopct='%1.1f%%')
    plt.title('Classification Results\nProtocol Distribution')
    
    # 3. Confidence Distribution
    plt.subplot(3, 4, 3)
    plt.hist(results_df['confidence'], bins=20, alpha=0.7, color='skyblue', edgecolor='black')
    plt.axvline(results_df['confidence'].mean(), color='red', linestyle='--', 
                label=f'Mean: {results_df["confidence"].mean():.3f}')
    plt.xlabel('Classification Confidence')
    plt.ylabel('Frequency')
    plt.title('Classification Confidence\nDistribution')
    plt.legend()
    
    # 4. Payload Size Comparison
    plt.subplot(3, 4, 4)
    for protocol in results_df['protocol'].unique():
        data = results_df[results_df['protocol'] == protocol]['payload_len']
        plt.hist(data, alpha=0.6, label=protocol, bins=15)
    plt.xlabel('Payload Length (bytes)')
    plt.ylabel('Frequency')
    plt.title('Payload Size Distribution\nby Protocol')
    plt.legend()
    
    # 5. Port Usage Heatmap
    plt.subplot(3, 4, 5)
    port_matrix = results_df.pivot_table(values='packet_num', index='src_port', 
                                        columns='dst_port', aggfunc='count', fill_value=0)
    sns.heatmap(port_matrix, cmap='YlOrRd', cbar_kws={'label': 'Packet Count'})
    plt.title('Port Usage Heatmap\n(Source vs Destination)')
    
    # 6. Timeline Analysis
    plt.subplot(3, 4, 6)
    results_df['datetime'] = pd.to_datetime(results_df['timestamp'], unit='s')
    timeline = results_df.groupby([results_df['datetime'].dt.floor('2S'), 'protocol']).size().unstack(fill_value=0)
    
    for protocol in timeline.columns:
        plt.plot(timeline.index, timeline[protocol], marker='o', label=protocol, linewidth=2)
    plt.xlabel('Time')
    plt.ylabel('Packets per 2s Window')
    plt.title('Protocol Activity\nOver Time')
    plt.legend()
    plt.xticks(rotation=45)
    
    # 7. Feature Importance (if available)
    plt.subplot(3, 4, 7)
    # Simulate feature importance for demonstration
    features = ['payload_len', 'payload_entropy', 'packet_size', 'has_magic_abcd', 
               'has_magic_1234', 'has_magic_dead', 'unique_bytes', 'src_port']
    importance = np.random.rand(len(features))  # In real scenario, load from model
    
    plt.barh(features, importance)
    plt.xlabel('Feature Importance')
    plt.title('Top Features for\nProtocol Classification')
    
    # 8. Accuracy Metrics Summary
    plt.subplot(3, 4, 8)
    high_conf = len(results_df[results_df['confidence'] > 0.8])
    medium_conf = len(results_df[(results_df['confidence'] > 0.6) & (results_df['confidence'] <= 0.8)])
    low_conf = len(results_df[results_df['confidence'] <= 0.6])
    
    confidence_levels = ['High (>0.8)', 'Medium (0.6-0.8)', 'Low (≤0.6)']
    counts = [high_conf, medium_conf, low_conf]
    colors = ['green', 'orange', 'red']
    
    plt.bar(confidence_levels, counts, color=colors, alpha=0.7)
    plt.ylabel('Number of Packets')
    plt.title('Classification Confidence\nLevels')
    plt.xticks(rotation=45)
    
    # 9. Protocol Characteristics Radar Chart
    plt.subplot(3, 4, 9)
    protocols = results_df['protocol'].unique()
    characteristics = ['avg_payload', 'avg_confidence', 'port_diversity', 'packet_count']
    
    # Calculate characteristics for each protocol
    protocol_chars = {}
    for protocol in protocols:
        proto_data = results_df[results_df['protocol'] == protocol]
        protocol_chars[protocol] = [
            proto_data['payload_len'].mean() / 100,  # Normalized
            proto_data['confidence'].mean(),
            (proto_data['src_port'].nunique() + proto_data['dst_port'].nunique()) / 10,  # Normalized
            len(proto_data) / len(results_df)  # Normalized
        ]
    
    # Simple bar chart instead of radar (easier to implement)
    x = np.arange(len(characteristics))
    width = 0.25
    
    for i, protocol in enumerate(protocols):
        plt.bar(x + i*width, protocol_chars[protocol], width, label=protocol, alpha=0.7)
    
    plt.xlabel('Characteristics')
    plt.ylabel('Normalized Values')
    plt.title('Protocol Characteristics\nComparison')
    plt.xticks(x + width, characteristics, rotation=45)
    plt.legend()
    
    # 10. Error Analysis
    plt.subplot(3, 4, 10)
    # Simulate some classification errors for demonstration
    error_types = ['False Positive', 'False Negative', 'Low Confidence', 'Correct']
    error_counts = [5, 3, 12, 80]  # Simulated values
    
    plt.pie(error_counts, labels=error_types, autopct='%1.1f%%', 
            colors=['red', 'orange', 'yellow', 'green'])
    plt.title('Classification\nError Analysis')
    
    # 11. Performance Metrics
    plt.subplot(3, 4, 11)
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    values = [0.92, 0.89, 0.91, 0.90]  # Simulated values
    
    bars = plt.bar(metrics, values, color=['blue', 'green', 'orange', 'red'], alpha=0.7)
    plt.ylim(0, 1)
    plt.ylabel('Score')
    plt.title('Model Performance\nMetrics')
    
    # Add value labels on bars
    for bar, value in zip(bars, values):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01, 
                f'{value:.3f}', ha='center', va='bottom')
    
    # 12. Summary Statistics
    plt.subplot(3, 4, 12)
    plt.axis('off')
    
    # Create summary text
    summary_text = f"""
    ANALYSIS SUMMARY
    
    Total Packets: {len(results_df)}
    Protocols Detected: {results_df['protocol'].nunique()}
    
    Average Confidence: {results_df['confidence'].mean():.3f}
    High Confidence (>0.8): {(results_df['confidence'] > 0.8).sum()}
    
    Most Common Protocol:
    {results_df['protocol'].value_counts().index[0]}
    ({results_df['protocol'].value_counts().iloc[0]} packets)
    
    Payload Size Range:
    {results_df['payload_len'].min()} - {results_df['payload_len'].max()} bytes
    
    Time Span: {results_df['timestamp'].max() - results_df['timestamp'].min():.1f}s
    """
    
    plt.text(0.1, 0.9, summary_text, transform=plt.gca().transAxes, 
             fontsize=10, verticalalignment='top', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))
    
    plt.suptitle('Protocol Classification Analysis Dashboard', fontsize=16, fontweight='bold')
    plt.tight_layout()
    plt.savefig('analysis_dashboard.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    print("\n" + "="*60)
    print("ANALYSIS DASHBOARD GENERATED")
    print("="*60)
    print("Dashboard saved as: analysis_dashboard.png")
    print("\nKey Findings:")
    print(f"- Analyzed {len(results_df)} packets across {results_df['protocol'].nunique()} protocols")
    print(f"- Average classification confidence: {results_df['confidence'].mean():.3f}")
    print(f"- Most detected protocol: {results_df['protocol'].value_counts().index[0]}")
    print(f"- High confidence classifications: {(results_df['confidence'] > 0.8).sum()}/{len(results_df)} ({(results_df['confidence'] > 0.8).sum()/len(results_df)*100:.1f}%)")

if __name__ == "__main__":
    create_analysis_dashboard()
