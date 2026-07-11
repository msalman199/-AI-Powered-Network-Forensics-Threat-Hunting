<div align="center">

# 🤖 Train ML Models in Scikit-learn to Classify Benign vs Malicious Flows

### Blue Team / AI-Assisted Detection Track — Machine Learning for Network Security

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-150458?style=for-the-badge&logo=pandas&logoColor=white)
![NumPy](https://img.shields.io/badge/NumPy-013243?style=for-the-badge&logo=numpy&logoColor=white)
![Matplotlib](https://img.shields.io/badge/Matplotlib-Visualization-11557C?style=for-the-badge&logo=plotly&logoColor=white)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Classification-blueviolet?style=for-the-badge&logo=tensorflow&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-yellow?style=for-the-badge)
![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cybersecurity%20Labs-6C63FF?style=for-the-badge&logo=readthedocs&logoColor=white)

</div>

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [🧰 Technology Stack](#-technology-stack)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [⚙️ Task 1: Environment Setup and Data Preparation](#️-task-1-environment-setup-and-data-preparation)
- [🧠 Task 2: Train Machine Learning Models](#-task-2-train-machine-learning-models)
- [📊 Task 3: Model Evaluation and Performance Analysis](#-task-3-model-evaluation-and-performance-analysis)
- [🧪 Task 4: Model Validation and Testing](#-task-4-model-validation-and-testing)
- [✅ Verification and Testing](#-verification-and-testing)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Preprocess network flow data for machine learning analysis |
| 2 | Train classification models using Scikit-learn to detect malicious network traffic |
| 3 | Evaluate model performance using standard metrics and validation techniques |
| 4 | Implement feature engineering techniques for network security datasets |

---

## 🧰 Technology Stack

<div align="center">

| Tool / Library | Purpose | Badge |
|-----------------|---------|-------|
| **Linux (Ubuntu)** | Base lab operating system | ![Linux](https://img.shields.io/badge/OS-Linux-FCC624?logo=linux&logoColor=black) |
| **Python 3** | Core programming language | ![Python](https://img.shields.io/badge/lang-Python%203-3776AB?logo=python&logoColor=white) |
| **Scikit-learn** | ML model training & evaluation | ![Sklearn](https://img.shields.io/badge/ML-Scikit--learn-F7931E?logo=scikitlearn&logoColor=white) |
| **Pandas / NumPy** | Data preprocessing & manipulation | ![Pandas](https://img.shields.io/badge/data-Pandas%20%7C%20NumPy-150458) |
| **Matplotlib / Seaborn** | Visualization of metrics & results | ![Viz](https://img.shields.io/badge/viz-Matplotlib%20%7C%20Seaborn-11557C) |
| **imbalanced-learn** | Handling class imbalance | ![Imblearn](https://img.shields.io/badge/lib-imbalanced--learn-red) |
| **NSL-KDD Dataset** | Labeled network flow training data | ![Dataset](https://img.shields.io/badge/dataset-NSL--KDD-orange) |
| **joblib** | Model persistence/serialization | ![Joblib](https://img.shields.io/badge/serialization-joblib-green) |

</div>

---

## 📋 Prerequisites

| Requirement | Details |
|--------------|---------|
| 🐍 Python Programming | Basic understanding of Python scripting |
| 🧠 ML Fundamentals | Familiarity with classification, training/testing splits |
| 🌐 Networking Knowledge | Understanding of network protocols and traffic analysis |
| 🐧 Linux CLI Experience | Comfortable navigating and executing Linux commands |

---

## 🖥️ Lab Environment

> Al Nafi provides Linux-based cloud machines for this lab. Simply click **Start Lab** to access your dedicated environment. The provided Linux machine is bare metal with no pre-installed tools — you will install all required software during the lab.

---

## ⚙️ Task 1: Environment Setup and Data Preparation

### 🔹 Subtask 1.1: Install Required Tools

```bash
# 🔄 Update system packages
sudo apt update && sudo apt upgrade -y

# 🐍 Install Python and pip
sudo apt install python3 python3-pip python3-venv -y

# 📦 Install required Python packages
pip3 install pandas numpy scikit-learn matplotlib seaborn imbalanced-learn

# ✅ Verify installations
python3 -c "import pandas, numpy, sklearn; print('All packages installed successfully')"
```

### 🔹 Subtask 1.2: Download and Prepare Dataset

```bash
# 📁 Create working directory
mkdir ~/ml_network_security
cd ~/ml_network_security

# ⬇️ Download sample network flow dataset (using a public cybersecurity dataset)
wget https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt -O kdd_train.txt
wget https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt -O kdd_test.txt
```

```python
# 🐍 preprocess_data.py — TODO: review feature list against your dataset version
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split

# 🏷️ Define column names for KDD dataset
columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
           'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
           'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
           'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
           'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
           'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
           'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
           'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
           'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
           'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type', 'difficulty']

def load_and_preprocess_data():
    # 📥 Load training data
    train_data = pd.read_csv('kdd_train.txt', names=columns, header=None)
    test_data = pd.read_csv('kdd_test.txt', names=columns, header=None)

    # 🔗 Combine datasets for consistent preprocessing
    combined_data = pd.concat([train_data, test_data], ignore_index=True)

    # 🏷️ Create binary classification: normal vs attack
    combined_data['is_malicious'] = (combined_data['attack_type'] != 'normal').astype(int)

    # 🗑️ Remove unnecessary columns
    features_to_drop = ['attack_type', 'difficulty']
    X = combined_data.drop(features_to_drop + ['is_malicious'], axis=1)
    y = combined_data['is_malicious']

    # 🔤 Handle categorical variables
    categorical_columns = ['protocol_type', 'service', 'flag']
    label_encoders = {}

    for col in categorical_columns:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        label_encoders[col] = le

    # 🧹 Handle missing values
    X = X.fillna(X.median())

    print(f"Dataset shape: {X.shape}")
    print(f"Malicious samples: {y.sum()}")
    print(f"Benign samples: {len(y) - y.sum()}")

    return X, y, label_encoders

if __name__ == "__main__":
    X, y, encoders = load_and_preprocess_data()

    # 💾 Save preprocessed data
    np.save('X_features.npy', X.values)
    np.save('y_labels.npy', y.values)

    print("Data preprocessing completed successfully!")
```

```bash
# ▶️ Run preprocessing
python3 preprocess_data.py
```

---

## 🧠 Task 2: Train Machine Learning Models

### 🔹 Subtask 2.1: Create Training Script

```python
# 🐍 train_models.py — trains Random Forest, Logistic Regression, and SVM
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import GridSearchCV
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

def load_preprocessed_data():
    """Load the preprocessed features and labels"""
    X = np.load('X_features.npy')
    y = np.load('y_labels.npy')
    return X, y

def train_and_evaluate_models(X, y):
    """Train multiple models and compare performance"""

    # ✂️ Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 📏 Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 🧠 Define models
    models = {
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
        'Logistic Regression': LogisticRegression(random_state=42, max_iter=1000),
        'SVM': SVC(random_state=42, probability=True)
    }

    results = {}

    print("Training and evaluating models...")
    print("=" * 50)

    for name, model in models.items():
        print(f"\nTraining {name}...")

        # 🏋️ Train model
        if name == 'SVM':
            # Use subset for SVM due to computational complexity
            subset_size = min(10000, len(X_train_scaled))
            indices = np.random.choice(len(X_train_scaled), subset_size, replace=False)
            model.fit(X_train_scaled[indices], y_train[indices])
        else:
            model.fit(X_train_scaled, y_train)

        # 🔮 Make predictions
        y_pred = model.predict(X_test_scaled)
        y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

        # 📈 Calculate metrics
        auc_score = roc_auc_score(y_test, y_pred_proba)

        # 💾 Store results
        results[name] = {
            'model': model,
            'predictions': y_pred,
            'probabilities': y_pred_proba,
            'auc_score': auc_score
        }

        print(f"{name} AUC Score: {auc_score:.4f}")
        print(f"\nClassification Report for {name}:")
        print(classification_report(y_test, y_pred))
        print("-" * 50)

    # 🏆 Save best model (highest AUC)
    best_model_name = max(results.keys(), key=lambda k: results[k]['auc_score'])
    best_model = results[best_model_name]['model']

    joblib.dump(best_model, 'best_model.pkl')
    joblib.dump(scaler, 'scaler.pkl')

    print(f"\nBest model: {best_model_name} (AUC: {results[best_model_name]['auc_score']:.4f})")

    return results, X_test, y_test, scaler

def plot_confusion_matrices(results, y_test):
    """Plot confusion matrices for all models"""
    fig, axes = plt.subplots(1, len(results), figsize=(15, 4))

    for idx, (name, result) in enumerate(results.items()):
        cm = confusion_matrix(y_test, result['predictions'])
        sns.heatmap(cm, annot=True, fmt='d', ax=axes[idx], cmap='Blues')
        axes[idx].set_title(f'{name}\nAUC: {result["auc_score"]:.3f}')
        axes[idx].set_xlabel('Predicted')
        axes[idx].set_ylabel('Actual')

    plt.tight_layout()
    plt.savefig('confusion_matrices.png', dpi=300, bbox_inches='tight')
    plt.show()
    print("Confusion matrices saved as 'confusion_matrices.png'")

if __name__ == "__main__":
    # 📥 Load data
    X, y = load_preprocessed_data()

    # 🏋️ Train and evaluate models
    results, X_test, y_test, scaler = train_and_evaluate_models(X, y)

    # 📊 Plot results
    plot_confusion_matrices(results, y_test)
```

```bash
# ▶️ Run training
python3 train_models.py
```

### 🔹 Subtask 2.2: Hyperparameter Tuning

```python
# 🐍 hyperparameter_tuning.py — TODO: expand param_grid if compute budget allows
import numpy as np
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import joblib

def tune_random_forest():
    """Perform hyperparameter tuning for Random Forest"""

    # 📥 Load data
    X = np.load('X_features.npy')
    y = np.load('y_labels.npy')

    # ✂️ Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 📏 Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 🔧 Define parameter grid
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_depth': [10, 20, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4]
    }

    # 🌲 Create Random Forest classifier
    rf = RandomForestClassifier(random_state=42)

    # 🔍 Perform grid search
    print("Performing hyperparameter tuning...")
    grid_search = GridSearchCV(
        rf, param_grid, cv=3, scoring='roc_auc',
        n_jobs=-1, verbose=1
    )

    grid_search.fit(X_train_scaled, y_train)

    # 🏆 Get best model
    best_rf = grid_search.best_estimator_

    # 📈 Evaluate on test set
    y_pred = best_rf.predict(X_test_scaled)
    y_pred_proba = best_rf.predict_proba(X_test_scaled)[:, 1]
    auc_score = roc_auc_score(y_test, y_pred_proba)

    print(f"\nBest parameters: {grid_search.best_params_}")
    print(f"Best cross-validation AUC: {grid_search.best_score_:.4f}")
    print(f"Test set AUC: {auc_score:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    # 💾 Save tuned model
    joblib.dump(best_rf, 'tuned_model.pkl')
    joblib.dump(scaler, 'tuned_scaler.pkl')

    return best_rf, scaler

if __name__ == "__main__":
    best_model, scaler = tune_random_forest()
    print("Hyperparameter tuning completed!")
```

```bash
# ▶️ Run hyperparameter tuning
python3 hyperparameter_tuning.py
```

---

## 📊 Task 3: Model Evaluation and Performance Analysis

### 🔹 Subtask 3.1: Comprehensive Model Evaluation

```python
# 🐍 evaluate_model.py — generates ROC, PR curve, confusion matrix & feature importance
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (classification_report, confusion_matrix,
                           roc_curve, precision_recall_curve, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

def comprehensive_evaluation():
    """Perform comprehensive evaluation of the trained model"""

    # 📥 Load data and model
    X = np.load('X_features.npy')
    y = np.load('y_labels.npy')

    try:
        model = joblib.load('tuned_model.pkl')
        scaler = joblib.load('tuned_scaler.pkl')
        print("Using tuned model for evaluation")
    except:
        model = joblib.load('best_model.pkl')
        scaler = joblib.load('scaler.pkl')
        print("Using best model for evaluation")

    # ✂️ Split data (same split as training)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 📏 Scale test data
    X_test_scaled = scaler.transform(X_test)

    # 🔮 Make predictions
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

    # 📈 Calculate metrics
    auc_score = roc_auc_score(y_test, y_pred_proba)

    print("=" * 60)
    print("COMPREHENSIVE MODEL EVALUATION")
    print("=" * 60)
    print(f"Test Set Size: {len(y_test)}")
    print(f"AUC Score: {auc_score:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    # 📊 Plot evaluation metrics
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))

    # 🧮 Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', ax=axes[0,0], cmap='Blues')
    axes[0,0].set_title('Confusion Matrix')
    axes[0,0].set_xlabel('Predicted')
    axes[0,0].set_ylabel('Actual')

    # 📉 ROC Curve
    fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
    axes[0,1].plot(fpr, tpr, label=f'ROC Curve (AUC = {auc_score:.3f})')
    axes[0,1].plot([0, 1], [0, 1], 'k--', label='Random')
    axes[0,1].set_xlabel('False Positive Rate')
    axes[0,1].set_ylabel('True Positive Rate')
    axes[0,1].set_title('ROC Curve')
    axes[0,1].legend()
    axes[0,1].grid(True)

    # 📉 Precision-Recall Curve
    precision, recall, _ = precision_recall_curve(y_test, y_pred_proba)
    axes[1,0].plot(recall, precision)
    axes[1,0].set_xlabel('Recall')
    axes[1,0].set_ylabel('Precision')
    axes[1,0].set_title('Precision-Recall Curve')
    axes[1,0].grid(True)

    # ⭐ Feature Importance (if available)
    if hasattr(model, 'feature_importances_'):
        # Get top 10 most important features
        feature_importance = model.feature_importances_
        top_indices = np.argsort(feature_importance)[-10:]

        axes[1,1].barh(range(len(top_indices)), feature_importance[top_indices])
        axes[1,1].set_xlabel('Feature Importance')
        axes[1,1].set_title('Top 10 Feature Importances')
        axes[1,1].set_yticks(range(len(top_indices)))
        axes[1,1].set_yticklabels([f'Feature {i}' for i in top_indices])
    else:
        axes[1,1].text(0.5, 0.5, 'Feature importance\nnot available\nfor this model',
                      ha='center', va='center', transform=axes[1,1].transAxes)
        axes[1,1].set_title('Feature Importance')

    plt.tight_layout()
    plt.savefig('model_evaluation.png', dpi=300, bbox_inches='tight')
    plt.show()

    print(f"\nEvaluation plots saved as 'model_evaluation.png'")

    # 🧾 Performance summary
    tn, fp, fn, tp = cm.ravel()
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    f1_score = 2 * (precision * recall) / (precision + recall)

    print("\n" + "=" * 40)
    print("PERFORMANCE SUMMARY")
    print("=" * 40)
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1_score:.4f}")
    print(f"AUC:       {auc_score:.4f}")

    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score,
        'auc': auc_score
    }

if __name__ == "__main__":
    metrics = comprehensive_evaluation()
```

```bash
# ▶️ Run comprehensive evaluation
python3 evaluate_model.py
```

### 🔹 Subtask 3.2: Create Prediction Interface

```python
# 🐍 predict_flows.py — TODO: swap demo samples for live/streamed flow features
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler

def load_model():
    """Load the trained model and scaler"""
    try:
        model = joblib.load('tuned_model.pkl')
        scaler = joblib.load('tuned_scaler.pkl')
        print("Loaded tuned model")
    except:
        model = joblib.load('best_model.pkl')
        scaler = joblib.load('scaler.pkl')
        print("Loaded best model")

    return model, scaler

def predict_single_flow(model, scaler, flow_features):
    """Predict if a single network flow is malicious"""

    # 🔁 Ensure input is 2D array
    if len(flow_features.shape) == 1:
        flow_features = flow_features.reshape(1, -1)

    # 📏 Scale features
    flow_scaled = scaler.transform(flow_features)

    # 🔮 Make prediction
    prediction = model.predict(flow_scaled)[0]
    probability = model.predict_proba(flow_scaled)[0]

    return prediction, probability

def demo_predictions():
    """Demonstrate predictions on sample data"""

    # 📥 Load model
    model, scaler = load_model()

    # 📥 Load test data for demonstration
    X = np.load('X_features.npy')
    y = np.load('y_labels.npy')

    # 🎲 Select random samples for demonstration
    np.random.seed(42)
    sample_indices = np.random.choice(len(X), 5, replace=False)

    print("=" * 60)
    print("NETWORK FLOW CLASSIFICATION DEMO")
    print("=" * 60)

    for i, idx in enumerate(sample_indices):
        flow = X[idx]
        actual_label = y[idx]

        prediction, probabilities = predict_single_flow(model, scaler, flow)

        print(f"\nSample {i+1}:")
        print(f"Actual Label: {'Malicious' if actual_label == 1 else 'Benign'}")
        print(f"Predicted Label: {'Malicious' if prediction == 1 else 'Benign'}")
        print(f"Confidence - Benign: {probabilities[0]:.3f}, Malicious: {probabilities[1]:.3f}")
        print(f"Correct: {'✓' if prediction == actual_label else '✗'}")
        print("-" * 40)

if __name__ == "__main__":
    demo_predictions()
```

```bash
# ▶️ Run prediction demo
python3 predict_flows.py
```

---

## 🧪 Task 4: Model Validation and Testing

### 🔹 Subtask 4.1: Cross-Validation Analysis

```python
# 🐍 cross_validation.py — 5-fold stratified CV across multiple metrics
import numpy as np
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt

def perform_cross_validation():
    """Perform k-fold cross-validation to assess model stability"""

    # 📥 Load data
    X = np.load('X_features.npy')
    y = np.load('y_labels.npy')

    # 📏 Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 🌲 Create model
    model = RandomForestClassifier(n_estimators=100, random_state=42)

    # 🔀 Perform stratified k-fold cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    # 📊 Calculate cross-validation scores for different metrics
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

    # 📊 Plot cross-validation results
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

    # 🏷️ Add value labels on bars
    for i, (mean, std) in enumerate(zip(means, stds)):
        ax.text(i, mean + std + 0.01, f'{mean:.3f}', ha='center', va='bottom')

    plt.tight_layout()
    plt.savefig('cross_validation_results.png', dpi=300, bbox_inches='tight')
    plt.show()

    print("Cross-validation results saved as 'cross_validation_results.png'")

    return cv_results

if __name__ == "__main__":
    results = perform_cross_validation()
```

```bash
# ▶️ Run cross-validation
python3 cross_validation.py
```

### 🔹 Subtask 4.2: Generate Final Report

```python
# 🐍 generate_report.py — TODO: pipe report contents into your lab submission doc
import numpy as np
import joblib
from datetime import datetime
import os

def generate_final_report():
    """Generate a comprehensive final report"""

    # 📥 Load data for statistics
    X = np.load('X_features.npy')
    y = np.load('y_labels.npy')

    # 📝 Create report
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

    # 📄 List generated files
    files = [
        'X_features.npy', 'y_labels.npy', 'best_model.pkl', 'scaler.pkl',
        'confusion_matrices.png', 'model_evaluation.png', 'cross_validation_results.png'
    ]

    for file in files:
        if os.path.exists(file):
            report += f"✓ {file}\n"
        else:
            report += f"✗ {file} (not found)\n"

    # 🔍 Try to load model performance
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

    # 💾 Save report
    with open('final_report.txt', 'w') as f:
        f.write(report)

    print("Final report generated successfully!")
    print("Report saved as 'final_report.txt'")
    print("\nReport Summary:")
    print("-" * 40)
    print(report)

if __name__ == "__main__":
    generate_final_report()
```

```bash
# ▶️ Generate final report
python3 generate_report.py

# 📂 Display all generated files
echo "Generated files in the lab:"
ls -la *.py *.pkl *.npy *.png *.txt 2>/dev/null || echo "Some files may not exist if previous steps failed"
```

---

## ✅ Verification and Testing

### 🔹 Verify Lab Completion

```bash
# 🔎 Check if all required files exist
echo "Checking lab completion..."

required_files=("X_features.npy" "y_labels.npy" "best_model.pkl" "scaler.pkl" "final_report.txt")

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✓ $file exists"
    else
        echo "✗ $file missing"
    fi
done

# 🧪 Test model loading
python3 -c "
import joblib
import numpy as np
try:
    model = joblib.load('best_model.pkl')
    scaler = joblib.load('scaler.pkl')
    X = np.load('X_features.npy')
    print('✓ Model and data loading successful')
    print(f'✓ Model type: {type(model).__name__}')
    print(f'✓ Feature count: {X.shape[1]}')
except Exception as e:
    print(f'✗ Error: {e}')
"
```

> 💡 **TODO:** Attach a screenshot of your `model_evaluation.png` and `final_report.txt` output as evidence of lab completion.

---

## 🗺️ MITRE ATT&CK Mapping

The NSL-KDD dataset labels flows across several attack categories. This lab's classifier provides **ML-driven detection coverage** mapped to the following techniques:

| Technique ID | Technique Name | Tactic | Relevance to This Lab |
|--------------|-----------------|--------|-------------------------|
| T1046 | Network Service Discovery | Discovery | "Probe"-class flows in NSL-KDD (e.g., port scans) are learned as malicious patterns |
| T1498 | Network Denial of Service | Impact | "DoS"-class flows train the model to flag abnormal traffic volume/rate patterns |
| T1110 | Brute Force | Credential Access | "R2L" (Remote-to-Local) flows include failed-login and unauthorized access patterns |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation | "U2R" (User-to-Root) flows capture privilege escalation attempt signatures |
| T1071 | Application Layer Protocol | Command and Control | Protocol/service/flag features help the model generalize to anomalous protocol usage |

> 🧭 **Data Source Reference:** `DS0029 – Network Traffic` (MITRE ATT&CK) — enriched here with a supervised ML classification layer

---

## 🛠️ Troubleshooting

<details>
<summary>📦 <strong>Package Installation Failures</strong></summary>

If `pip3 install` fails on a package, upgrade pip first with `pip3 install --upgrade pip`, then retry. Ensure `python3-dev` is installed for packages requiring compilation.
</details>

<details>
<summary>⬇️ <strong>Dataset Download Issues</strong></summary>

If `wget` fails to retrieve the NSL-KDD files, verify internet connectivity in the lab VM and confirm the GitHub raw URL hasn't changed. Retry with `wget -c` to resume partial downloads.
</details>

<details>
<summary>🐌 <strong>SVM Training Taking Too Long</strong></summary>

SVM training on the full dataset can be slow. The script already subsets to 10,000 samples for SVM — reduce `subset_size` further if training still stalls on constrained lab hardware.
</details>

<details>
<summary>🧩 <strong>Model/Scaler File Not Found</strong></summary>

Ensure `train_models.py` completed successfully before running `evaluate_model.py` or `predict_flows.py` — these depend on `best_model.pkl`/`scaler.pkl` (or `tuned_model.pkl`/`tuned_scaler.pkl`) being present.
</details>

<details>
<summary>⚖️ <strong>Imbalanced Class Warnings</strong></summary>

If precision/recall look skewed, consider using `imbalanced-learn`'s `SMOTE` or class-weight parameters (`class_weight='balanced'`) to address dataset imbalance between benign and malicious samples.
</details>

---

## 🏁 Conclusion

In this lab, you successfully built a complete machine learning pipeline for **network flow classification**, from raw data preprocessing through model deployment-readiness.

### 🏆 Key Accomplishments

- 🧹 Preprocessed network flow data — encoding categorical variables, scaling features, and building binary labels
- 🧠 Trained multiple models (Random Forest, Logistic Regression, SVM) using Scikit-learn
- 📊 Evaluated performance using accuracy, precision, recall, F1-score, and ROC-AUC
- 🔧 Implemented hyperparameter tuning via `GridSearchCV` to optimize the Random Forest classifier
- 🔀 Performed 5-fold stratified cross-validation to assess model stability and generalization
- 🔮 Built a working prediction interface to classify new/unseen network flows

### 🌍 Real-World Applications

- The trained models form the foundation of a **Network Intrusion Detection System (NIDS)**
- ML-based classification complements signature-based tools like **Zeek** and **Suricata** by catching novel/unseen attack patterns
- Feature importance analysis helps SOC analysts understand *which* traffic characteristics drive alerts
- Cross-validated, tuned models are production-deployable for **real-time flow scoring** at the network edge

This hands-on experience mirrors real-world cybersecurity ML workflows — preparing you for roles in security analysis, threat detection, and network monitoring where automated, data-driven detection is increasingly essential.

---

<div align="center">

### 🎓 Al Nafi Cybersecurity Labs
**Blue Team / AI-Assisted Detection Track — Machine Learning for Network Security**

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Empowering%20Cyber%20Talent-6C63FF?style=for-the-badge)

*Building the next generation of security analysts, one lab at a time.*

</div>
