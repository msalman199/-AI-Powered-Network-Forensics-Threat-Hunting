#!/usr/bin/env python3
from scapy.all import *
import json
from collections import defaultdict, Counter
import pandas as pd

class PCAPAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)
        self.analysis_results = {}
    
    def basic_statistics(self):
        """Generate basic packet statistics"""
        total_packets = len(self.packets)
        protocols = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        ports = Counter()
        
        for packet in self.packets:
            if packet.haslayer(IP):
                src_ips[packet[IP].src] += 1
                dst_ips[packet[IP].dst] += 1
                
                if packet.haslayer(TCP):
                    protocols['TCP'] += 1
                    ports[packet[TCP].dport] += 1
                elif packet.haslayer(UDP):
                    protocols['UDP'] += 1
                    ports[packet[UDP].dport] += 1
                elif packet.haslayer(ICMP):
                    protocols['ICMP'] += 1
        
        return {
            'total_packets': total_packets,
            'protocols': dict(protocols.most_common()),
            'top_src_ips': dict(src_ips.most_common(10)),
            'top_dst_ips': dict(dst_ips.most_common(10)),
            'top_ports': dict(ports.most_common(10))
        }
    
    def detect_anomalies(self):
        """Detect potential network anomalies"""
        anomalies = []
        
        # Port scanning detection
        port_scans = defaultdict(set)
        for packet in self.packets:
            if packet.haslayer(TCP) and packet.haslayer(IP):
                if packet[TCP].flags == 2:  # SYN flag
                    port_scans[packet[IP].src].add(packet[TCP].dport)
        
        for src_ip, ports in port_scans.items():
            if len(ports) > 5:
                anomalies.append({
                    'type': 'Port Scan',
                    'source_ip': src_ip,
                    'ports_scanned': len(ports),
                    'severity': 'High' if len(ports) > 10 else 'Medium'
                })
        
        # DNS query frequency analysis
        dns_queries = defaultdict(int)
        for packet in self.packets:
            if packet.haslayer(DNS) and packet.haslayer(IP):
                if packet[DNS].qr == 0:  # Query
                    dns_queries[packet[IP].src] += 1
        
        for src_ip, query_count in dns_queries.items():
            if query_count > 10:
                anomalies.append({
                    'type': 'Excessive DNS Queries',
                    'source_ip': src_ip,
                    'query_count': query_count,
                    'severity': 'Medium'
                })
        
        # Large packet detection
        large_packets = []
        for packet in self.packets:
            if len(packet) > 1500:
                large_packets.append({
                    'size': len(packet),
                    'src': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                    'dst': packet[IP].dst if packet.haslayer(IP) else 'Unknown'
                })
        
        if large_packets:
            anomalies.append({
                'type': 'Large Packets Detected',
                'count': len(large_packets),
                'max_size': max(p['size'] for p in large_packets),
                'severity': 'Low'
            })
        
        return anomalies
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        stats = self.basic_statistics()
        anomalies = self.detect_anomalies()
        
        report = {
            'file_analyzed': self.pcap_file,
            'basic_statistics': stats,
            'anomalies_detected': anomalies,
            'summary': {
                'total_anomalies': len(anomalies),
                'high_severity': len([a for a in anomalies if a.get('severity') == 'High']),
                'medium_severity': len([a for a in anomalies if a.get('severity') == 'Medium']),
                'low_severity': len([a for a in anomalies if a.get('severity') == 'Low'])
            }
        }
        
        return report

if __name__ == "__main__":
    analyzer = PCAPAnalyzer('network_capture.pcap')
    report = analyzer.generate_report()
    
    # Save report to JSON
    with open('pcap_analysis_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("PCAP Analysis Complete!")
    print(f"Total packets analyzed: {report['basic_statistics']['total_packets']}")
    print(f"Anomalies detected: {report['summary']['total_anomalies']}")
    print("Detailed report saved to: pcap_analysis_report.json")
