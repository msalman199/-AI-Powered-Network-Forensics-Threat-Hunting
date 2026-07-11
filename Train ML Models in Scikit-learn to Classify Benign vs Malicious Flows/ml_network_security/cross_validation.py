import numpy as np
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt

def perform_cross_validation():
    """Perform k-fold cross-validation to assess model stability"""
    
    # Load data
    X = np.load('X_features.npy')
    y = np.load('y_labels.npy')
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Create model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    
    # Perform stratified k-fold cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    # Calculate cross-validation scores for different metrics
    scoring_metrics = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
    cv_results = {}
    
    print("Performing 5-fold cross-validation...")
    print("=" * 50)
    
    for metric in scoring_metrics:
        scores = cross_val_score(model, X_scaled, y, cv=cv, scoring=metric)
        cv_results[metric] = scores
        
        print(f"{metric.upper()}:")
        print(f"  Mean: {scores.mean():.4f} (+/- {scores.std() * 2:.4f})")
        print(f"  Scores: {[f'{score:.3f}' for score in scores]}")
        print()
    
    # Plot cross-validation results
    fig, ax = plt.subplots(figsize=(10, 6))
    
    metrics = list(cv_results.keys())
    means = [cv_results[metric].mean() for metric in metrics]
    stds = [cv_results[metric].std() for metric in metrics]
    
    x_pos = np.arange(len(metrics))
    ax.bar(x_pos, means, yerr=stds, capsize=5, alpha=0.7)
    ax.set_xlabel('Metrics')
    ax.set_ylabel('Score')
    ax.set_title('Cross-Validation Results (5-Fold)')
    ax.set_xticks(x_pos)
    ax.set_xticklabels([m.upper() for m in metrics])
    ax.grid(True, alpha=0.3)
    
    # Add value labels on bars
    for i, (mean, std) in enumerate(zip(means, stds)):
        ax.text(i, mean + std + 0.01, f'{mean:.3f}', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig('cross_validation_results.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    print("Cross-validation results saved as 'cross_validation_results.png'")
    
    return cv_results

if __name__ == "__main__":
    results = perform_cross_validation()
