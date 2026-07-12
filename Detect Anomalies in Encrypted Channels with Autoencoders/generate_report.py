import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import json

class AnomalyDetectionReport:
    def __init__(self):
        self.report_data = {}
        
    def generate_comprehensive_report(self):
        """Generate a comprehensive anomaly detection report"""
        
        # Load results
        X_test = np.load('X_test.npy')
        y_test = np.load('y_test.npy')
        
        # Load model and make predictions
        import tensorflow as tf
        import pickle
        
        model = tf.keras.models.load_model('anomaly_autoencoder.h5')
        with open('threshold.pkl', 'rb') as f:
            threshold = pickle.load(f)
        
        predictions = model.predict(X_test)
        mse = np.mean(np.power(X_test - predictions, 2), axis=1)
        y_pred = (mse > threshold).astype(int)
        
        # Calculate metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        # Generate report
        report = f"""
# Encrypted Traffic Anomaly Detection Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
This report presents the results of anomaly detection in encrypted network traffic using autoencoder neural networks.

## Dataset Overview
- Total samples analyzed: {len(X_test)}
- Normal traffic samples: {len(y_test[y_test==0])}
- Anomalous traffic samples: {len(y_test[y_test==1])}
- Features analyzed: 5 (packet_size, inter_arrival_time, flow_duration, bytes_per_second, entropy)

## Model Performance
- **Accuracy**: {accuracy:.3f}
- **Precision**: {precision:.3f}
- **Recall**: {recall:.3f}
- **F1-Score**: {f1:.3f}
- **Detection Threshold**: {threshold:.6f}

## Key Findings

### 1. Normal Traffic Characteristics
- Average packet size: {np.mean(X_test[y_test==0][:, 0]):.2f} bytes
- Typical inter-arrival time: {np.mean(X_test[y_test==0][:, 1]):.4f} seconds
- Standard flow duration: {np.mean(X_test[y_test==0][:, 2]):.2f} seconds

### 2. Anomalous Traffic Patterns
- Unusual packet sizes detected
- Irregular timing patterns identified
- Abnormal flow durations observed

### 3. Detection Effectiveness
- Successfully identified {np.sum(y_pred[y_test==1])}/{np.sum(y_test)} actual anomalies
- False positive rate: {np.sum(y_pred[y_test==0])}/{len(y_test[y_test==0]):.3f}

## Recommendations

1. **Threshold Tuning**: Consider adjusting the detection threshold based on operational requirements
2. **Feature Enhancement**: Add additional traffic features for improved detection accuracy
3. **Model Updates**: Retrain the model periodically with new traffic patterns
4. **Integration**: Deploy the model in network monitoring systems for real-time detection

## Technical Details

### Autoencoder Architecture
- Input Layer: 5 features
- Encoder: 32 → 16 → 8 neurons
- Decoder: 8 → 16 → 32 → 5 neurons
- Activation: ReLU (hidden), Linear (output)
- Loss Function: Mean Squared Error

### Training Configuration
- Training samples: Normal traffic only
- Validation split: 20%
- Batch size: 32
- Early stopping: Enabled

## Conclusion
The autoencoder-based anomaly detection system demonstrates effective capability in identifying unusual patterns in encrypted network traffic. The model achieves a good balance between detection accuracy and false positive rates, making it suitable for deployment in cybersecurity monitoring systems.
        """
        
        # Save report
        with open('anomaly_detection_report.md', 'w') as f:
            f.write(report)
        
        # Save metrics as JSON
        metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'threshold': float(threshold),
            'total_samples': int(len(X_test)),
            'normal_samples': int(len(y_test[y_test==0])),
            'anomaly_samples': int(len(y_test[y_test==1])),
            'report_date': datetime.now().isoformat()
        }
        
        with open('detection_metrics.json', 'w') as f:
            json.dump(metrics, f, indent=2)
        
        print("Comprehensive report generated:")
        print("- anomaly_detection_report.md")
        print("- detection_metrics.json")
        
        return metrics

# Generate the report
reporter = AnomalyDetectionReport()
metrics = reporter.generate_comprehensive_report()

print("\nReport Summary:")
for key, value in metrics.items():
    if key != 'report_date':
        print(f"{key}: {value}")
