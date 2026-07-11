import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
from datetime import datetime, timedelta
import numpy as np

def create_detection_dashboard():
    """Create a comprehensive detection dashboard"""
    
    # Load processed data
    df = pd.read_csv('processed_email_features.csv')
    
    # Create dashboard
    fig, axes = plt.subplots(3, 3, figsize=(20, 15))
    fig.suptitle('Phishing Detection Dashboard', fontsize=16, fontweight='bold')
    
    # 1. Email Classification Distribution
    ax1 = axes[0, 0]
    labels = ['Legitimate', 'Phishing']
    sizes = [len(df) - df['is_phishing'].sum(), df['is_phishing'].sum()]
    colors = ['#2ecc71', '#e74c3c']
    ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax1.set_title('Email Classification Distribution')
    
    # 2. Phishing Keywords Distribution
    ax2 = axes[0, 1]
    phishing_emails = df[df['is_phishing'] == 1]
    legitimate_emails = df[df['is_phishing'] == 0]
    
    ax2.hist([legitimate_emails['phishing_keyword_count'], phishing_emails['phishing_keyword_count']], 
             bins=10, alpha=0.7, label=['Legitimate', 'Phishing'], color=['#2ecc71', '#e74c3c'])
    ax2.set_xlabel('Phishing Keyword Count')
    ax2.set_ylabel('Frequency')
    ax2.set_title('Phishing Keywords Distribution')
    ax2.legend()
    
    # 3. URL Analysis
    ax3 = axes[0, 2]
    url_data = df.groupby('is_phishing')['url_count'].mean()
    ax3.bar(['Legitimate', 'Phishing'], url_data.values, color=['#2ecc71', '#e74c3c'])
    ax3.set_ylabel('Average URL Count')
    ax3.set_title('Average URLs per Email Type')
    
    # 4. Text Length Analysis
    ax4 = axes[1, 0]
    ax4.boxplot([legitimate_emails['text_length'], phishing_emails['text_length']], 
                labels=['Legitimate', 'Phishing'])
    ax4.set_ylabel('Text Length')
    ax4.set_title('Text Length Distribution')
    
    # 5. Urgency Score Analysis
    ax5 = axes[1, 1]
    urgency_data = df.groupby('is_phishing')['urgency_score'].mean()
    ax5.bar(['Legitimate', 'Phishing'], urgency_data.values, color=['#2ecc71', '#e74c3c'])
    ax5.set_ylabel('Average Urgency Score')
    ax5.set_title('Urgency Language Analysis')
    
    # 6. Suspicious Domain Analysis
    ax6 = axes[1, 2]
    suspicious_domain_data = df.groupby('is_phishing')['sender_domain_suspicious'].sum()
    ax6.bar(['Legitimate', 'Phishing'], suspicious_domain_data.values, color=['#2ecc71', '#e74c3c'])
    ax6.set_ylabel('Count of Suspicious Domains')
    ax6.set_title('Suspicious Sender Domains')
    
    # 7. Feature Correlation Heatmap
    ax7 = axes[2, 0]
    correlation_features = ['phishing_keyword_count', 'url_count', 'urgency_score', 
                           'exclamation_count', 'text_length', 'is_phishing']
    corr_matrix = df[correlation_features].corr()
    sns.heatmap(corr_matrix, annot=True, cmap='RdYlBu_r', center=0, ax=ax7, 
                square=True, fmt='.2f')
    ax7.set_title('Feature Correlation Matrix')
    
    # 8. Detection Timeline (simulated)
    ax8 = axes[2, 1]
    # Create simulated timeline data
    dates = pd.date_range(start='2024-01-01', periods=30, freq='D')
    phishing_counts = np.random.poisson(2, 30)  # Simulate phishing detection counts
    legitimate_counts = np.random.poisson(8, 30)  # Simulate legitimate email counts
    
    ax8.plot(dates, phishing_counts, color='#e74c3c', marker='o', label='Phishing Detected')
    ax8.plot(dates, legitimate_counts, color='#2ecc71', marker='s', label='Legitimate Emails')
    ax8.set_xlabel('Date')
    ax8.set_ylabel('Email Count')
    ax8.set_title('Daily Email Detection Timeline')
    ax8.legend()
    ax8.tick_params(axis='x', rotation=45)
    
    # 9. Risk Score Distribution
    ax9 = axes[2, 2]
    # Calculate risk scores based on features
    df['risk_score'] = (
        df['phishing_keyword_count'] * 0.3 +
        df['url_count'] * 0.2 +
        df['urgency_score'] * 0.2 +
        df['has_suspicious_url'] * 0.3
    )
    
    ax9.hist([legitimate_emails['risk_score'], phishing_emails['risk_score']], 
             bins=15, alpha=0.7, label=['Legitimate', 'Phishing'], color=['#2ecc71', '#e74c3c'])
    ax9.set_xlabel('Risk Score')
    ax9.set_ylabel('Frequency')
    ax9.set_title('Email Risk Score Distribution')
    ax9.legend()
    
    plt.tight_layout()
    plt.savefig('phishing_detection_dashboard.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    # Generate summary report
    print("=== PHISHING DETECTION SUMMARY REPORT ===")
    print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Emails Analyzed: {len(df)}")
    print(f"Phishing Emails Detected: {df['is_phishing'].sum()}")
    print(f"Legitimate Emails: {len(df) - df['is_phishing'].sum()}")
    print(f"Phishing Detection Rate: {(df['is_phishing'].sum() / len(df)) * 100:.1f}%")
    
    print("\n=== KEY STATISTICS ===")
    print(f"Average Phishing Keywords (Phishing): {phishing_emails['phishing_keyword_count'].mean():.2f}")
    print(f"Average Phishing Keywords (Legitimate): {legitimate_emails['phishing_keyword_count'].mean():.2f}")
    print(f"Average URLs (Phishing): {phishing_emails['url_count'].mean():.2f}")
    print(f"Average URLs (Legitimate): {legitimate_emails['url_count'].mean():.2f}")
    print(f"Suspicious Domains in Phishing: {phishing_emails['sender_domain_suspicious'].sum()}")
    print(f"Suspicious Domains in Legitimate: {legitimate_emails['sender_domain_suspicious'].sum()}")
    
    print("\n=== RISK ASSESSMENT ===")
    high_risk = df[df['risk_score'] > 2]
    medium_risk = df[(df['risk_score'] > 1) & (df['risk_score'] <= 2)]
    low_risk = df[df['risk_score'] <= 1]
    
    print(f"High Risk Emails: {len(high_risk)} ({(len(high_risk)/len(df))*100:.1f}%)")
    print(f"Medium Risk Emails: {len(medium_risk)} ({(len(medium_risk)/len(df))*100:.1f}%)")
    print(f"Low Risk Emails: {len(low_risk)} ({(len(low_risk)/len(df))*100:.1f}%)")
    
    print("\nDashboard saved as 'phishing_detection_dashboard.png'")

if __name__ == "__main__":
    create_detection_dashboard()
