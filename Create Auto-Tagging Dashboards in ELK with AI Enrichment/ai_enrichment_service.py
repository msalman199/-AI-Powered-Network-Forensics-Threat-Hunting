import json
import time
import joblib
import pandas as pd
from elasticsearch import Elasticsearch
import numpy as np
from datetime import datetime

class TrafficEnrichmentService:
    def __init__(self):
        self.es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
        self.model = joblib.load('traffic_classifier.pkl')
        self.protocol_encoder = joblib.load('protocol_encoder.pkl')
        
    def classify_traffic(self, traffic_data):
        """Classify traffic using trained ML model"""
        try:
            # Prepare features
            features = pd.DataFrame([{
                'src_port': traffic_data.get('src_port', 0),
                'dst_port': traffic_data.get('dst_port', 0),
                'protocol_encoded': self.encode_protocol(traffic_data.get('protocol', 'TCP')),
                'bytes': traffic_data.get('bytes', 0),
                'packets': traffic_data.get('packets', 1),
                'duration': traffic_data.get('duration', 1)
            }])
            
            # Predict
            prediction = self.model.predict(features)[0]
            confidence = np.max(self.model.predict_proba(features))
            
            return {
                'ai_classification': prediction,
                'confidence_score': float(confidence),
                'classification_timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'ai_classification': 'unknown',
                'confidence_score': 0.0,
                'error': str(e)
            }
    
    def encode_protocol(self, protocol):
        """Encode protocol string to numeric value"""
        try:
            return self.protocol_encoder.transform([protocol])[0]
        except:
            return 0  # Default for unknown protocols
    
    def detect_anomalies(self, traffic_data):
        """Simple anomaly detection based on traffic patterns"""
        anomalies = []
        
        # Check for unusual port combinations
        src_port = traffic_data.get('src_port', 0)
        dst_port = traffic_data.get('dst_port', 0)
        
        if src_port > 60000 and dst_port < 1024:
            anomalies.append('high_source_port_to_system_port')
        
        # Check for unusual traffic volume
        bytes_count = traffic_data.get('bytes', 0)
        if bytes_count > 100000000:  # 100MB
            anomalies.append('large_data_transfer')
        
        # Check for rapid connections
        packets = traffic_data.get('packets', 0)
        duration = traffic_data.get('duration', 1)
        if packets > 1000 and duration < 1:
            anomalies.append('rapid_packet_burst')
        
        return {
            'anomalies_detected': anomalies,
            'anomaly_count': len(anomalies),
            'risk_level': 'high' if len(anomalies) > 1 else 'medium' if len(anomalies) == 1 else 'low'
        }
    
    def enrich_traffic_data(self, traffic_data):
        """Main enrichment function"""
        enriched_data = traffic_data.copy()
        
        # Add AI classification
        classification = self.classify_traffic(traffic_data)
        enriched_data.update(classification)
        
        # Add anomaly detection
        anomaly_info = self.detect_anomalies(traffic_data)
        enriched_data.update(anomaly_info)
        
        # Add processing metadata
        enriched_data['ai_processed'] = True
        enriched_data['processing_timestamp'] = datetime.now().isoformat()
        
        return enriched_data

# Service runner
if __name__ == "__main__":
    service = TrafficEnrichmentService()
    print("AI Enrichment Service started...")
    
    # Monitor for new documents and enrich them
    while True:
        try:
            # Query for recent unprocessed documents
            query = {
                "query": {
                    "bool": {
                        "must_not": {
                            "exists": {
                                "field": "ai_processed"
                            }
                        },
                        "filter": {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-1m"
                                }
                            }
                        }
                    }
                },
                "size": 100
            }
            
            response = service.es.search(index="network-traffic-*", body=query)
            
            for hit in response['hits']['hits']:
                doc_id = hit['_id']
                index = hit['_index']
                source_data = hit['_source']
                
                # Enrich the data
                enriched_data = service.enrich_traffic_data(source_data)
                
                # Update document in Elasticsearch
                service.es.update(
                    index=index,
                    id=doc_id,
                    body={"doc": enriched_data}
                )
                
                print(f"Enriched document {doc_id} with classification: {enriched_data.get('ai_classification')}")
            
            time.sleep(10)  # Check every 10 seconds
            
        except Exception as e:
            print(f"Error in enrichment service: {e}")
            time.sleep(30)
