def evaluate_performance(y_true, y_pred, y_pred_proba):
    """Evaluate model performance with comprehensive metrics"""
    
    # Classification report
    print("\n" + "="*50)
    print("CLASSIFICATION REPORT")
    print("="*50)
    print(classification_report(y_true, y_pred, target_names=['Normal', 'Anomaly']))
    
    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    print("\nConfusion Matrix:")
    print(cm)
    
    # ROC AUC Score
    auc_score = roc_auc_score(y_true, y_pred_proba)
    print(f"\nROC AUC Score: {auc_score:.4f}")
    
    return cm, auc_score

# Evaluate performance
cm, auc_score = evaluate_performance(y_test, y_pred, y_pred_proba)
