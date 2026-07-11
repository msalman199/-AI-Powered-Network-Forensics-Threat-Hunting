import pandas as pd
import json
import random
from datetime import datetime, timedelta

def generate_smtp_traffic():
    """Generate simulated SMTP traffic with email data"""
    
    # Load sample emails
    emails_df = pd.read_csv('sample_emails.csv')
    
    smtp_traffic = []
    
    for index, row in emails_df.iterrows():
        # Simulate SMTP packet data
        packet = {
            'timestamp': (datetime.now() - timedelta(hours=random.randint(1, 24))).isoformat(),
            'src_ip': f"192.168.1.{random.randint(10, 100)}",
            'dst_ip': "192.168.1.25",  # Mail server
            'src_port': random.randint(1024, 65535),
            'dst_port': 25,
            'protocol': 'SMTP',
            'email_data': {
                'from': row['sender'],
                'to': f"user{random.randint(1, 10)}@company.com",
                'subject': row['subject'],
                'body': row['body'],
                'message_id': f"<{random.randint(100000, 999999)}@mail.server.com>"
            },
            'is_phishing': row['is_phishing']
        }
        smtp_traffic.append(packet)
    
    # Save to JSON file
    with open('smtp_traffic.json', 'w') as f:
        json.dump(smtp_traffic, f, indent=2)
    
    print(f"Generated {len(smtp_traffic)} SMTP traffic entries")
    return smtp_traffic

if __name__ == "__main__":
    generate_smtp_traffic()
