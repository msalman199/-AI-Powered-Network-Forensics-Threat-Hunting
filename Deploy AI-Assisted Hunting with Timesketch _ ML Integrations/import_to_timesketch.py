import pandas as pd
import json
from datetime import datetime

def convert_to_timesketch_format(csv_file, output_file):
    """Convert CSV data to Timesketch JSONL format"""
    df = pd.read_csv(csv_file)
    
    with open(output_file, 'w') as f:
        for _, row in df.iterrows():
            # Create Timesketch event
            event = {
                'datetime': row['timestamp'],
                'timestamp_desc': 'Event Time',
                'message': row.get('message', ''),
                'source_short': row.get('source', 'Unknown'),
                'source_long': f"{row.get('source', 'Unknown')} - {csv_file}",
                'data_type': 'security_log'
            }
            
            # Add additional fields
            for col in row.index:
                if col not in ['timestamp', 'message', 'source']:
                    event[col] = str(row[col])
            
            f.write(json.dumps(event) + '\n')

# Convert security logs to Timesketch format
print("Converting logs to Timesketch format...")
convert_to_timesketch_format('/home/ubuntu/security_logs/windows_security.csv', 'windows_security.jsonl')
convert_to_timesketch_format('/home/ubuntu/security_logs/network_traffic.csv', 'network_traffic.jsonl')

# Convert ML analysis results
if pd.io.common.file_exists('classified_events.csv'):
    convert_to_timesketch_format('classified_events.csv', 'classified_events.jsonl')

print("Timesketch import files created:")
print("  - windows_security.jsonl")
print("  - network_traffic.jsonl")
print("  - classified_events.jsonl")
EOF

# Run conversion
python import_to_timesketch.py

# Import data into Timesketch (manual step - would typically use API)
echo "To import data into Timesketch:"
echo "1. Access Timesketch web interface at http://localhost:5000"
echo "2. Login with admin/admin123"
echo "3. Create new sketch or use existing 'APT Hunt Lab'"
echo "4. Upload the generated .jsonl files"
