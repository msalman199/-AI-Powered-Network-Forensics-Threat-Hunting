import numpy as np
import joblib
from datetime import datetime
import os

def generate_final_report():
    """Generate a comprehensive final report"""
    
    # Load data for statistics
    X = np.load('X_features.npy')
    y = np.load('y_labels.npy')
    
    # Create report
    report = f"""
NETWORK FLOW CLASSIFICATION - FINAL REPORT
==========================================
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

DATASET SUMMARY
---------------
Total samples: {len(X):,}
Features: {X.shape[1]}
Malicious flows: {y.sum():,} ({y.mean()*100:.1f}%)
Benign flows: {len(y) - y.sum():,} ({(1-y.mean())*100:.1f}%)

MODELS TRAINED
--------------
1. Random Forest Classifier
2. Logistic Regression
3. Support Vector Machine (SVM)

PREPROCESSING STEPS
-------------------
✓ Categorical variable encoding
✓ Feature scaling (StandardScaler)
✓ Missing value imputation
✓ Train/test split (80/20)

EVALUATION METRICS
------------------
The models were evaluated using:
- Accuracy
- Precision
- Recall
- F1-Score
- ROC-AUC Score
- Confusion Matrix Analysis

FILES GENERATED
---------------
"""
    
    # List generated files
    files = [
        'X_features.npy', 'y_labels.npy', 'best_model.pkl', 'scaler.pkl',
        'confusion_matrices.png', 'model_evaluation.png', 'cross_validation_results.png'
    ]
    
    for file in files:
        if os.path.exists(file):
            report += f"✓ {file}\n"
        else:
            report += f"✗ {file} (not found)\n"
    
    # Try to load model performance
    try:
        if os.path.exists('tuned_model.pkl'):
            report += "\nMODEL OPTIMIZATION\n"
            report += "------------------\n"
            report += "✓ Hyperparameter tuning completed\n"
            report += "✓ Optimized model saved as 'tuned_model.pkl'\n"
    except:
        pass
    
    report += f"""
NEXT STEPS
----------
1. Deploy the trained model in a production environment
2. Implement real-time network flow monitoring
3. Set up automated retraining pipeline
4. Monitor model performance over time
5. Consider ensemble methods for improved accuracy

TECHNICAL NOTES
---------------
- All models trained using scikit-learn
- Cross-validation performed for model stability assessment
- Feature importance analysis available for Random Forest
- Models saved in pickle format for easy deployment

END OF REPORT
=============
"""
    
    # Save report
    with open('final_report.txt', 'w') as f:
        f.write(report)
    
    print("Final report generated successfully!")
    print("Report saved as 'final_report.txt'")
    print("\nReport Summary:")
    print("-" * 40)
    print(report)

if __name__ == "__main__":
    generate_final_report()
