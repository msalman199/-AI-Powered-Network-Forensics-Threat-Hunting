# realtime_detection.py
import tensorflow as tf
import numpy as np
import pandas as pd
import pickle
import time
import matplotlib.pyplot as plt
from collections import deque

class RealTimeAnomalyDetector:
    def __init__(self):
        self.model = tf.keras.models.load_model('anomaly_autoencoder.h5')
        with open('threshold.pkl', 'rb') as f:
            self.threshold = pickle.load(f)
        with open('scaler.pkl', 'rb') as f:
            self.scaler = pickle.load(f)
        
        self.detection_history = deque(maxlen=100)
        self.error_history = deque(maxlen=100)
        
    def process_traffic_sample(self, sample):
        """Process a single traffic sample for anomaly detection"""
        # Scale the sample
        sample_scaled = self.scaler.transform([sample])
        
        # Get reconstruction
        reconstruction = self.model.predict(sample_scaled, verbose=0)
        
        # Calculate reconstruction error
        mse = np.mean(np.power(sample_scaled - reconstruction, 2))
        
        # Determine if anomaly
        is_anomaly = mse > self.threshold
        
        # Store in history
        self.detection_history.append(is_anomaly)
        self.error_history.append(mse)
        
        return is_anomaly, mse
    
    def simulate_realtime_detection(self, test_data, labels, delay=0.1):
        """Simulate real-time anomaly detection"""
        print("Starting real-time anomaly detection simulation...")
        print("Press Ctrl+C to stop\n")
        
        anomaly_count = 0
        total_count = 0
        
        try:
            for i, (sample, true_label) in enumerate(zip(test_data, labels)):
                is_anomaly, error = self.process_traffic_sample(sample)
                total_count += 1
                
                if is_anomaly:
                    anomaly_count += 1
                    status = "🚨 ANOMALY DETECTED"
                    print(f"Sample {i+1:4d}: {status} | Error: {error:.6f} | True: {'Anomaly' if true_label else 'Normal'}")
                else:
                    if i % 20 == 0:  # Print every 20th normal sample
                        print(f"Sample {i+1:4d}: Normal Traffic    | Error: {error:.6f} | True: {'Anomaly' if true_label else 'Normal'}")
                
                time.sleep(delay)
                
                # Print summary every 50 samples
                if (i + 1) % 50 == 0:
                    detection_rate = (anomaly_count / total_count) * 100
                    print(f"\n--- Summary after {i+1} samples ---")
                    print(f"Anomalies detected: {anomaly_count}/{total_count} ({detection_rate:.1f}%)")
                    print(f"Current threshold: {self.threshold:.6f}")
                    print("-" * 40 + "\n")
                    
        except KeyboardInterrupt:
            print("\nReal-time detection stopped by user.")
        
        return anomaly_count, total_count
    
    def plot_detection_history(self):
        """Plot the recent detection history"""
        if len(self.error_history) == 0:
            return
        
        plt.figure(figsize=(12, 6))
        
        plt.subplot(1, 2, 1)
        errors = list(self.error_history)
        detections = list(self.detection_history)
        
        colors = ['red' if det else 'blue' for det in detections]
        plt.scatter(range(len(errors)), errors, c=colors, alpha=0.7)
        plt.axhline(self.threshold, color='black', linestyle='--', label='Threshold')
        plt.xlabel('Sample Index')
        plt.ylabel('Reconstruction Error')
        plt.title('Recent Detection History')
        plt.legend()
        
        plt.subplot(1, 2, 2)
        anomaly_positions = [i for i, det in enumerate(detections) if det]
        plt.bar(range(len(detections)), [1 if det else 0 for det in detections], 
                color=['red' if det else 'blue' for det in detections], alpha=0.7)
        plt.xlabel('Sample Index')
        plt.ylabel('Anomaly Detected')
        plt.title('Anomaly Detection Timeline')
        
        plt.tight_layout()
        plt.savefig('realtime_detection_history.png', dpi=300, bbox_inches='tight')
        plt.show()

# Load test data for simulation
X_test = np.load('X_test.npy')
y_test = np.load('y_test.npy')

# Load original scaler to inverse transform for display
with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

X_test_original = scaler.inverse_transform(X_test)

# Create detector and run simulation
detector = RealTimeAnomalyDetector()

print("Real-time Anomaly Detection Simulation")
print("=" * 50)

# Run simulation on first 100 samples
sample_size = min(100, len(X_test_original))
anomaly_count, total_count = detector.simulate_realtime_detection(
    X_test_original[:sample_size], 
    y_test[:sample_size], 
    delay=0.05  # Faster for demo
)

print(f"\nFinal Results:")
print(f"Total samples processed: {total_count}")
print(f"Anomalies detected: {anomaly_count}")
print(f"Detection rate: {(anomaly_count/total_count)*100:.1f}%")

# Plot detection history
detector.plot_detection_history()
