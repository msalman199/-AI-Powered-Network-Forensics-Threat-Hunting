import json
import joblib
import pandas as pd
from nlp_processor import EmailNLPProcessor
import time

class RealtimePhishingDetector:
    def __init__(self, model_path='phishing_detector_model.pkl'):
        # Load trained model
        model_data = joblib.load(model_path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        
        # Initialize NLP processor
        self.nlp_processor = EmailNLPProcessor()
        
        print("Real-time Phishing Detector initialized!")
    
    def analyze_email(self, subject, body, sender):
        """Analyze a single email for phishing"""
        
        # Extract NLP features
        email_text = f"{subject} {body}"
        features = self.nlp_processor.extract_features(email_text, sender)
        
        # Prepare feature vector
        feature_vector = [features.get(feature, 0) for feature in self.feature_names]
        feature_vector = pd.DataFrame([feature_vector], columns=self.feature_names)
        
        # Convert boolean columns
        feature_vector['has_suspicious_url'] = feature_vector['has_suspicious_url'].astype(int)
        feature_vector['sender_domain_suspicious'] = feature_vector['sender_domain_suspicious'].astype(int)
        
        # Make prediction
        prediction = self.model.predict(feature_vector)[0]
        probability = self.model.predict_proba(feature_vector)[0]
        
        result = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'subject': subject,
            'sender': sender,
            'is_phishing': bool(prediction),
            'phishing_probability': float(probability[1]),
            'confidence': 'HIGH' if max(probability) > 0.8 else 'MEDIUM' if max(probability) > 0.6 else 'LOW',
            'features': features
        }
        
        return result
    
    def monitor_smtp_traffic(self, traffic_file):
        """Monitor SMTP traffic for phishing attempts"""
        
        print("=== Real-time SMTP Traffic Monitoring ===")
        print("Analyzing emails for phishing attempts...\n")
        
        with open(traffic_file, 'r') as f:
            traffic_data = json.load(f)
        
        phishing_detected = 0
        total_emails = len(traffic_data)
        
        for i, packet in enumerate(traffic_data):
            email_data = packet['email_data']
            
            # Analyze email
            result = self.analyze_email(
                email_data['subject'],
                email_data['body'],
                email_data['from']
            )
            
            # Display results
            print(f"Email {i+1}/{total_emails}")
            print(f"From: {result['sender']}")
            print(f"Subject: {result['subject'][:50]}...")
            print(f"Prediction: {'🚨 PHISHING' if result['is_phishing'] else '✅ LEGITIMATE'}")
            print(f"Confidence: {result['confidence']} ({result['phishing_probability']:.3f})")
            
            if result['is_phishing']:
                phishing_detected += 1
                print("⚠️  ALERT: Potential phishing email detected!")
                
                # Show key indicators
                features = result['features']
                indicators = []
                if features['phishing_keyword_count'] > 0:
                    indicators.append(f"Phishing keywords: {features['phishing_keyword_count']}")
                if features['url_count'] > 0:
                    indicators.append(f"URLs found: {features['url_count']}")
                if features['has_suspicious_url']:
                    indicators.append("Suspicious URL detected")
                if features['urgency_score'] > 0:
                    indicators.append(f"Urgency indicators: {features['urgency_score']}")
                
                if indicators:
                    print(f"Key indicators: {', '.join(indicators)}")
            
            print("-" * 60)
            
            # Simulate real-time processing delay
            time.sleep(0.5)
        
        print(f"\n=== Monitoring Summary ===")
        print(f"Total emails analyzed: {total_emails}")
        print(f"Phishing attempts detected: {phishing_detected}")
        print(f"Detection rate: {(phishing_detected/total_emails)*100:.1f}%")
    
    def interactive_email_checker(self):
        """Interactive email checker"""
        
        print("\n=== Interactive Email Phishing Checker ===")
        print("Enter email details to check for phishing (type 'quit' to exit)")
        
        while True:
            print("\n" + "="*50)
            sender = input("Sender email: ").strip()
            if sender.lower() == 'quit':
                break
                
            subject = input("Subject: ").strip()
            if subject.lower() == 'quit':
                break
                
            body = input("Body: ").strip()
            if body.lower() == 'quit':
                break
            
            # Analyze email
            result = self.analyze_email(subject, body, sender)
            
            print(f"\n📧 Analysis Result:")
            print(f"Prediction: {'🚨 PHISHING' if result['is_phishing'] else '✅ LEGITIMATE'}")
            print(f"Confidence: {result['confidence']}")
            print(f"Phishing Probability: {result['phishing_probability']:.3f}")
            
            if result['is_phishing']:
                print("\n⚠️  Warning Signs Detected:")
                features = result['features']
                if features['phishing_keyword_count'] > 0:
                    print(f"• Contains {features['phishing_keyword_count']} phishing keywords")
                if features['url_count'] > 0:
                    print(f"• Contains {features['url_count']} URLs")
                if features['has_suspicious_url']:
                    print("• Contains suspicious URLs")
                if features['urgency_score'] > 0:
                    print(f"• High urgency language detected (score: {features['urgency_score']})")
                if features['exclamation_count'] > 2:
                    print(f"• Excessive exclamation marks ({features['exclamation_count']})")

def main():
    try:
        # Initialize detector
        detector = RealtimePhishingDetector()
        
        # Monitor SMTP traffic
        detector.monitor_smtp_traffic('smtp_traffic.json')
        
        # Interactive checker
        detector.interactive_email_checker()
        
    except FileNotFoundError:
        print("Error: Model file not found. Please run ml_phishing_detector.py first.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
