import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from collections import defaultdict
import time

class ProtocolPatternAnalyzer:
    def __init__(self, results_file="realtime_classification_results.csv"):
        self.df = pd.read_csv(results_file)
        self.patterns = {}
        
    def temporal_analysis(self):
        """Analyze temporal patterns in protocol usage"""
        print("=== Temporal Pattern Analysis ===")
        
        # Convert timestamp to datetime
        self.df['datetime'] = pd.to_datetime(self.df['timestamp'], unit='s')
        
        # Time-based grouping
        self.df['time_window'] = self.df['datetime'].dt.floor('5S')  # 5-second windows
        
        # Protocol usage over time
        temporal_patterns = self.df.groupby(['time_window', 'protocol']).size().unstack(fill_value=0)
        
        plt.figure(figsize=(15, 8))
        
        # Plot temporal patterns
        plt.subplot(2, 2, 1)
        for protocol in temporal_patterns.columns:
            plt.plot(temporal_patterns.index, temporal_patterns[protocol], 
                    marker='o', label=protocol, linewidth=2)
        plt.title('Protocol Usage Over Time')
        plt.xlabel('Time Window')
        plt.ylabel('Packet Count')
        plt.legend()
        plt.xticks(rotation=45)
        
        # Protocol burst detection
        plt.subplot(2, 2, 2)
        protocol_rates = self.df.groupby(['protocol', 'time_window']).size().reset_index(name='count')
        
        for protocol in protocol_rates['protocol'].unique():
            proto_data = protocol_rates[protocol_rates['protocol'] == protocol]
            plt.hist(proto_data['count'], alpha=0.7, label=protocol, bins=10)
        
        plt.title('Protocol Burst Distribution')
        plt.xlabel('Packets per Time Window')
        plt.ylabel('Frequency')
        plt.legend()
        
        # Inter-arrival time analysis
        plt.subplot(2, 2, 3)
        for protocol in self.df['protocol'].unique():
            proto_data = self.df[self.df['protocol'] == protocol].sort_values('timestamp')
            if len(proto_data) > 1:
                inter_arrival = np.diff(proto_data['timestamp'])
                plt.hist(inter_arrival, alpha=0.7, label=f"{protocol} (avg: {np.mean(inter_arrival):.2f}s)", 
                        bins=15)
        
        plt.title('Inter-arrival Time Distribution')
        plt.xlabel('Time Between Packets (seconds)')
        plt.ylabel('Frequency')
        plt.legend()
        
        # Protocol switching patterns
        plt.subplot(2, 2, 4)
        protocol_sequence = self.df.sort_values('timestamp')['protocol'].tolist()
        transitions = defaultdict(int)
        
        for i in range(len(protocol_sequence) - 1):
            current = protocol_sequence[i]
            next_proto = protocol_sequence[i + 1]
            transitions[f"{current}->{next_proto}"] += 1
        
        if transitions:
            trans_df = pd.DataFrame(list(transitions.items()), columns=['Transition', 'Count'])
            trans_df = trans_df.sort_values('Count', ascending=True).tail(10)
            
            plt.barh(range(len(trans_df)), trans_df['Count'])
            plt.yticks(range(len(trans_df)), trans_df['Transition'])
            plt.title('Top Protocol Transitions')
            plt.xlabel('Frequency')
        
        plt.tight_layout()
        plt.savefig('temporal_patterns.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        return temporal_patterns
    
    def port_behavior_analysis(self):
        """Analyze port usage patterns"""
        print("\n=== Port Behavior Analysis ===")
        
        plt.figure(figsize=(15, 6))
        
        # Source port distribution by protocol
        plt.subplot(1, 3, 1)
        for protocol in self.df['protocol'].unique():
            proto_data = self.df[self.df['protocol'] == protocol]
            unique_src_ports = proto_data['src_port'].unique()
            plt.hist(unique_src_ports, alpha=0.7, label=f"{protocol} ({len(unique_src_ports)} ports)", 
                    bins=20)
        
        plt.title('Source Port Distribution')
        plt.xlabel('Port Number')
        plt.ylabel('Frequency')
        plt.legend()
        
        # Destination port distribution by protocol
        plt.subplot(1, 3, 2)
        for protocol in self.df['protocol'].unique():
            proto_data = self.df[self.df['protocol'] == protocol]
            unique_dst_ports = proto_data['dst_port'].unique()
            plt.hist(unique_dst_ports, alpha=0.7, label=f"{protocol} ({len(unique_dst_ports)} ports)", 
                    bins=20)
        
        plt.title('Destination Port Distribution')
        plt.xlabel('Port Number')
        plt.ylabel('Frequency')
        plt.legend()
        
        # Port pair analysis
        plt.subplot(1, 3, 3)
        self.df['port_pair'] = self.df['src_port'].astype(str) + '->' + self.df['dst_port'].astype(str)
        port_pair_counts = self.df['port_pair'].value_counts().head(10)
        
        plt.barh(range(len(port_pair_counts)), port_pair_counts.values)
        plt.yticks(range(len(port_pair_counts)), port_pair_counts.index)
        plt.title('Top Port Pairs')
        plt.xlabel('Frequency')
        
        plt.tight_layout()
        plt.savefig('port_patterns.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        # Print port statistics
        print("\nPort Usage Statistics:")
        for protocol in self.df['protocol'].unique():
            proto_data = self.df[self.df['protocol'] == protocol]
            print(f"\n{protocol}:")
            print(f"  Unique source ports: {proto_data['src_port'].nunique()}")
            print(f"  Unique destination ports: {proto_data['dst_port'].nunique()}")
            print(f"  Most common dst port: {proto_data['dst_port'].mode().iloc[0] if not proto_data['dst_port'].mode().empty else 'N/A'}")
    
    def payload_pattern_analysis(self):
        """Analyze payload size patterns"""
        print("\n=== Payload Pattern Analysis ===")
        
        plt.figure(figsize=(12, 8))
        
        # Payload size distribution
        plt.subplot(2, 2, 1)
        for protocol in self.df['protocol'].unique():
            proto_data = self.df[self.df['protocol'] == protocol]
            plt.hist(proto_data['payload_len'], alpha=0.7, label=protocol, bins=15)
        
        plt.title('Payload Size Distribution')
        plt.xlabel('Payload Length (bytes)')
        plt.ylabel('Frequency')
        plt.legend()
        
        # Box plot of payload sizes
        plt.subplot(2, 2, 2)
        protocols = []
        payload_sizes = []
        
        for protocol in self.df['protocol'].unique():
            proto_data = self.df[self.df['protocol'] == protocol]
            protocols.extend([protocol] * len(proto_data))
            payload_sizes.extend(proto_data['payload_len'].tolist())
        
        payload_df = pd.DataFrame({'Protocol': protocols, 'Payload_Size': payload_sizes})
        sns.boxplot(data=payload_df, x='Protocol', y='Payload_Size')
        plt.title('Payload Size Distribution by Protocol')
        plt.xticks(rotation=45)
        
        # Payload size over time
        plt.subplot(2, 2, 3)
        for protocol in self.df['protocol'].unique():
            proto_data = self.df[self.df['protocol'] == protocol].sort_values('timestamp')
            if len(proto_data) > 1:
                plt.scatter(proto_data['timestamp'], proto_data['payload_len'], 
                           alpha=0.6, label=protocol, s=30)
        
        plt.title('Payload Size Over Time')
        plt.xlabel('Timestamp')
        plt.ylabel('Payload Length (bytes)')
        plt.legend()
        
        # Confidence vs payload size
        plt.subplot(2, 2, 4)
        for protocol in self.df['protocol'].unique():
            proto_data = self.df[self.df['protocol'] == protocol]
            plt.scatter(proto_data['payload_len'], proto_data['confidence'], 
                       alpha=0.6, label=protocol, s=30)
        
        plt.title('Classification Confidence vs Payload Size')
        plt.xlabel('Payload Length (bytes)')
        plt.ylabel('Confidence')
        plt.legend()
        
        plt.tight_layout()
        plt.savefig('payload_patterns.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        # Print payload statistics
        print("\nPayload Statistics:")
        for protocol in self.df['protocol'].unique():
            proto_data = self.df[self.df['protocol'] == protocol]
            print(f"\n{protocol}:")
            print(f"  Mean payload size: {proto_data['payload_len'].mean():.2f} bytes")
            print(f"  Std payload size: {proto_data['payload_len'].std():.2f} bytes")
            print(f"  Min/Max payload size: {proto_data['payload_len'].min()}/{proto_data['payload_len'].max()} bytes")
    
    def clustering_analysis(self):
        """Perform clustering analysis on protocol behavior"""
        print("\n=== Clustering Analysis ===")
        
        # Prepare features for clustering
        feature_cols = ['src_port', 'dst_port', 'payload_len', 'confidence']
        X = self.df[feature_cols].values
        
        # Normalize features
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Perform K-means clustering
        n_clusters = len(self.df['protocol'].unique())
        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        cluster_labels = kmeans.fit_predict(X_scaled)
        
        # Add cluster labels to dataframe
        self.df['cluster'] = cluster_labels
        
        # PCA for visualization
        pca = PCA(n_components=2)
        X_pca = pca.fit_transform(X_scaled)
        
        plt.figure(figsize=(15, 5))
        
        # Plot clusters
        plt.subplot(1, 3, 1)
        scatter = plt.scatter(X_pca[:, 0], X_pca[:, 1], c=cluster_labels, cmap='viridis', alpha=0.6)
        plt.colorbar(scatter)
        plt.title('K-means Clustering (PCA)')
        plt.xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%} variance)')
        plt.ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%} variance)')
        
        # Plot actual protocols
        plt.subplot(1, 3, 2)
        protocol_colors = {protocol: i for i, protocol in enumerate(self.df['protocol'].unique())}
        colors = [protocol_colors[protocol] for protocol in self.df['protocol']]
        scatter = plt.scatter(X_pca[:, 0], X_pca[:, 1], c=colors, cmap='viridis', alpha=0.6)
        plt.colorbar(scatter, ticks=list(protocol_colors.values()), 
                    label='Protocol')
        plt.title('Actual Protocol Labels (PCA)')
        plt.xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%} variance)')
        plt.ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%} variance)')
        
        # Cluster vs Protocol comparison
        plt.subplot(1, 3, 3)
        cluster_protocol = pd.crosstab(self.df['cluster'], self.df['protocol'])
        sns.heatmap(cluster_protocol, annot=True, fmt='d', cmap='Blues')
        plt.title('Cluster vs Protocol Mapping')
        plt.xlabel('Protocol')
        plt.ylabel('Cluster')
        
        plt.tight_layout()
        plt.savefig('clustering_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        # Print clustering results
        print("\nClustering Results:")
        for cluster in range(n_clusters):
            cluster_data = self.df[self.df['cluster'] == cluster]
            dominant_protocol = cluster_data['protocol'].mode().iloc[0] if not cluster_data['protocol'].mode().empty else 'Mixed'
            print(f"Cluster {cluster}: {len(cluster_data)} packets, dominant protocol: {dominant_protocol}")
    
    def generate_comprehensive_report(self):
        """Generate a comprehensive analysis report"""
        print("\n" + "="*60)
        print("COMPREHENSIVE PROTOCOL BEHAVIOR ANALYSIS REPORT")
        print("="*60)
        
        # Basic statistics
        print(f"\nDataset Overview:")
        print(f"Total packets analyzed: {len(self.df)}")
        print(f"Unique protocols detected: {self.df['protocol'].nunique()}")
        print(f"Time span: {self.df['timestamp'].max() - self.df['timestamp'].min():.2f} seconds")
        print(f"Average classification confidence: {self.df['confidence'].mean():.3f}")
        
        # Run all analyses
        self.temporal_analysis()
        self.port_behavior_analysis()
        self.payload_pattern_analysis()
        self.clustering_analysis()
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)
        print("Generated visualizations:")
        print("- temporal_patterns.png")
        print("- port_patterns.png") 
        print("- payload_patterns.png")
        print("- clustering_analysis.png")

if __name__ == "__main__":
    analyzer = ProtocolPatternAnalyzer()
    analyzer.generate_comprehensive_report()
