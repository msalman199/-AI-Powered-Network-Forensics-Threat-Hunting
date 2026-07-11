import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def analyze_features():
    """Analyze extracted NLP features"""
    
    # Load processed data
    df = pd.read_csv('processed_email_features.csv')
    
    print("=== Email Dataset Analysis ===")
    print(f"Total emails: {len(df)}")
    print(f"Phishing emails: {df['is_phishing'].sum()}")
    print(f"Legitimate emails: {len(df) - df['is_phishing'].sum()}")
    
    # Feature statistics by class
    print("\n=== Feature Statistics ===")
    numeric_features = ['text_length', 'word_count', 'exclamation_count', 
                       'url_count', 'phishing_keyword_count', 'urgency_score']
    
    for feature in numeric_features:
        phishing_mean = df[df['is_phishing'] == 1][feature].mean()
        legitimate_mean = df[df['is_phishing'] == 0][feature].mean()
        print(f"{feature}:")
        print(f"  Phishing: {phishing_mean:.2f}")
        print(f"  Legitimate: {legitimate_mean:.2f}")
    
    # Create visualizations
    plt.figure(figsize=(15, 10))
    
    # Plot 1: Feature distribution
    plt.subplot(2, 3, 1)
    df.boxplot(column='phishing_keyword_count', by='is_phishing', ax=plt.gca())
    plt.title('Phishing Keywords by Email Type')
    plt.suptitle('')
    
    # Plot 2: URL count distribution
    plt.subplot(2, 3, 2)
    df.boxplot(column='url_count', by='is_phishing', ax=plt.gca())
    plt.title('URL Count by Email Type')
    plt.suptitle('')
    
    # Plot 3: Text length distribution
    plt.subplot(2, 3, 3)
    df.boxplot(column='text_length', by='is_phishing', ax=plt.gca())
    plt.title('Text Length by Email Type')
    plt.suptitle('')
    
    # Plot 4: Urgency score
    plt.subplot(2, 3, 4)
    df.boxplot(column='urgency_score', by='is_phishing', ax=plt.gca())
    plt.title('Urgency Score by Email Type')
    plt.suptitle('')
    
    # Plot 5: Exclamation count
    plt.subplot(2, 3, 5)
    df.boxplot(column='exclamation_count', by='is_phishing', ax=plt.gca())
    plt.title('Exclamation Count by Email Type')
    plt.suptitle('')
    
    # Plot 6: Correlation heatmap
    plt.subplot(2, 3, 6)
    correlation_features = numeric_features + ['is_phishing']
    corr_matrix = df[correlation_features].corr()
    sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', center=0, ax=plt.gca())
    plt.title('Feature Correlation Matrix')
    
    plt.tight_layout()
    plt.savefig('nlp_feature_analysis.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    print("\nAnalysis complete! Visualization saved as 'nlp_feature_analysis.png'")

if __name__ == "__main__":
    analyze_features()
