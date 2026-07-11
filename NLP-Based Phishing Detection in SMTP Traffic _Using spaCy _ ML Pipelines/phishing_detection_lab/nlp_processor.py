import spacy
import pandas as pd
import json
import re
from collections import Counter

class EmailNLPProcessor:
    def __init__(self):
        # Load spaCy model
        self.nlp = spacy.load("en_core_web_sm")
        
        # Define phishing keywords
        self.phishing_keywords = [
            'urgent', 'verify', 'suspended', 'click here', 'winner', 'congratulations',
            'claim', 'prize', 'frozen', 'compromised', 'security alert', 'update',
            'confirm', 'expire', 'limited time', 'act now', 'free money'
        ]
        
        # Suspicious domains
        self.suspicious_domains = [
            'fake-bank.com', 'scam-lottery.com', 'paypal-fake.net', 
            'bank-phish.com', 'secure-update.net'
        ]
    
    def extract_features(self, email_text, sender_email):
        """Extract NLP features from email text"""
        
        # Combine subject and body for analysis
        full_text = email_text.lower()
        
        # Process with spaCy
        doc = self.nlp(full_text)
        
        features = {}
        
        # Basic text statistics
        features['text_length'] = len(full_text)
        features['word_count'] = len([token for token in doc if not token.is_space])
        features['sentence_count'] = len(list(doc.sents))
        
        # Linguistic features
        features['exclamation_count'] = full_text.count('!')
        features['question_count'] = full_text.count('?')
        features['caps_ratio'] = sum(1 for c in full_text if c.isupper()) / len(full_text) if full_text else 0
        
        # URL detection
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, email_text)
        features['url_count'] = len(urls)
        features['has_suspicious_url'] = any(domain in url for url in urls for domain in self.suspicious_domains)
        
        # Phishing keyword detection
        keyword_count = sum(1 for keyword in self.phishing_keywords if keyword in full_text)
        features['phishing_keyword_count'] = keyword_count
        features['phishing_keyword_ratio'] = keyword_count / features['word_count'] if features['word_count'] > 0 else 0
        
        # Named entity recognition
        entities = [ent.label_ for ent in doc.ents]
        entity_counter = Counter(entities)
        features['person_entities'] = entity_counter.get('PERSON', 0)
        features['org_entities'] = entity_counter.get('ORG', 0)
        features['money_entities'] = entity_counter.get('MONEY', 0)
        
        # Sender domain analysis
        sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ''
        features['sender_domain_suspicious'] = sender_domain in self.suspicious_domains
        features['sender_domain_length'] = len(sender_domain)
        
        # Sentiment and urgency indicators
        urgency_words = ['urgent', 'immediate', 'asap', 'quickly', 'hurry', 'deadline']
        features['urgency_score'] = sum(1 for word in urgency_words if word in full_text)
        
        return features
    
    def process_smtp_traffic(self, traffic_file):
        """Process SMTP traffic and extract features"""
        
        with open(traffic_file, 'r') as f:
            traffic_data = json.load(f)
        
        processed_data = []
        
        for packet in traffic_data:
            email_data = packet['email_data']
            
            # Combine subject and body
            email_text = f"{email_data['subject']} {email_data['body']}"
            
            # Extract features
            features = self.extract_features(email_text, email_data['from'])
            
            # Add metadata
            features['timestamp'] = packet['timestamp']
            features['sender'] = email_data['from']
            features['subject'] = email_data['subject']
            features['is_phishing'] = packet['is_phishing']
            
            processed_data.append(features)
        
        return pd.DataFrame(processed_data)

if __name__ == "__main__":
    processor = EmailNLPProcessor()
    df = processor.process_smtp_traffic('smtp_traffic.json')
    
    print("NLP Feature Extraction Complete!")
    print(f"Processed {len(df)} emails")
    print("\nFeature columns:")
    print(df.columns.tolist())
    
    # Save processed data
    df.to_csv('processed_email_features.csv', index=False)
    print("\nProcessed data saved to 'processed_email_features.csv'")
