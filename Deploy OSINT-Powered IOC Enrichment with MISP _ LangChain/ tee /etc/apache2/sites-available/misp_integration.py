#!/usr/bin/env python3
import requests
import json
import sys

class MISPIntegration:
    def __init__(self, misp_url="http://localhost", misp_key=""):
        self.misp_url = misp_url
        self.misp_key = misp_key
        self.headers = {
            'Authorization': misp_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    
    def create_event(self, event_info):
        """Create a new MISP event"""
        event_data = {
            'Event': {
                'info': event_info,
                'distribution': '1',
                'threat_level_id': '2',
                'analysis': '1'
            }
        }
        
        try:
            response = requests.post(f"{self.misp_url}/events", 
                                   headers=self.headers, 
                                   data=json.dumps(event_data),
                                   verify=False)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error creating event: {response.status_code}")
                return None
        except Exception as e:
            print(f"Exception creating event: {e}")
            return None
    
    def add_attribute(self, event_id, attr_type, attr_value, comment=""):
        """Add attribute to MISP event"""
        attr_data = {
            'Attribute': {
                'type': attr_type,
                'value': attr_value,
                'comment': comment,
                'distribution': '1'
            }
        }
        
        try:
            response = requests.post(f"{self.misp_url}/attributes/add/{event_id}", 
                                   headers=self.headers, 
                                   data=json.dumps(attr_data),
                                   verify=False)
            return response.status_code == 200
        except Exception as e:
            print(f"Exception adding attribute: {e}")
            return False

def main():
    # Test MISP integration
    misp = MISPIntegration()
    
    # Create test event
    event = misp.create_event("OSINT Enrichment Test Event")
    if event:
        event_id = event['Event']['id']
        print(f"Created event with ID: {event_id}")
        
        # Add test attributes
        test_attributes = [
            {'type': 'ip-dst', 'value': '192.168.1.100', 'comment': 'Suspicious IP'},
            {'type': 'domain', 'value': 'malicious-domain.com', 'comment': 'C2 Domain'},
            {'type': 'md5', 'value': 'a1b2c3d4e5f6789012345678901234567', 'comment': 'Malware hash'}
        ]
        
        for attr in test_attributes:
            success = misp.add_attribute(event_id, attr['type'], attr['value'], attr['comment'])
            print(f"Added {attr['type']}: {attr['value']} - {'Success' if success else 'Failed'}")
    else:
        print("Failed to create event")

if __name__ == "__main__":
    main()
