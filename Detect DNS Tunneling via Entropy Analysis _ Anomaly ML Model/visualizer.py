#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def create_visualizations():
    """Create visualizations for DNS tunneling analysis"""
    try:
        df = pd.read_csv('tunneling_detection_results.csv')
    except FileNotFoundError:
        print("No results file found. Please run analysis first.")
        return
    
    # Create figure with subplots
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
    
    # 1. Entropy distribution
    normal = df[~df['is_suspicious']]['entropy']
    suspicious = df[df['is_suspicious']]['entropy']
    
    ax1.hist(normal, bins=20, alpha=0.7, label='Normal', color='blue')
    ax1.hist(suspicious, bins=20, alpha=0.7, label='Suspicious', color='red')
    ax1.set_xlabel('Entropy')
    ax1.set_ylabel('Frequency')
    ax1.set_title('Entropy Distribution')
    ax1.legend()
    
    # 2. Length vs Entropy scatter
    colors = ['red' if x else 'blue' for x in df['is_suspicious']]
    ax2.scatter(df['length'], df['entropy'], c=colors, alpha=0.6)
    ax2.set_xlabel('Subdomain Length')
    ax2.set_ylabel('Entropy')
    ax2.set_title('Length vs Entropy')
    
    # 3. Suspicion score distribution
    ax3.hist(df['suspicion_score'], bins=range(8), alpha=0.7, color='orange')
    ax3.set_xlabel('Suspicion Score')
    ax3.set_ylabel('Frequency')
    ax3.set_title('Suspicion Score Distribution')
    
    # 4. Detection indicators
    indicators = ['high_entropy', 'long_subdomain', 'suspicious_pattern', 
                 'high_digit_ratio', 'low_vowel_ratio', 'ml_anomaly']
    counts = [sum(df[indicator]) for indicator in indicators]
    
    ax4.bar(range(len(indicators)), counts, color='green', alpha=0.7)
    ax4.set_xlabel('Detection Indicators')
    ax4.set_ylabel('Count')
    ax4.set_title('Detection Indicators Frequency')
    ax4.set_xticks(range(len(indicators)))
    ax4.set_xticklabels([i.replace('_', '\n') for i in indicators], rotation=45)
    
    plt.tight_layout()
    plt.savefig('dns_tunneling_analysis.png', dpi=300, bbox_inches='tight')
    print("Visualization saved as 'dns_tunneling_analysis.png'")
    
    # Display summary statistics
    print("\nSummary Statistics:")
    print("=" * 30)
    print(f"Total queries: {len(df)}")
    print(f"Suspicious queries: {sum(df['is_suspicious'])}")
    print(f"Detection rate: {sum(df['is_suspicious'])/len(df)*100:.1f}%")
    print(f"Average entropy (normal): {df[~df['is_suspicious']]['entropy'].mean():.2f}")
    print(f"Average entropy (suspicious): {df[df['is_suspicious']]['entropy'].mean():.2f}")

if __name__ == "__main__":
    create_visualizations()
