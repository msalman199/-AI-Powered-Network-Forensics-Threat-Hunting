#!/bin/bash
echo "=== Baseline Traffic Summary ==="
echo "Capture file size: $(ls -lh ../tcpdump_captures/baseline_traffic.pcap | awk '{print $5}')"
echo "Raw packets captured: $(tcpdump -r ../tcpdump_captures/baseline_traffic.pcap 2>/dev/null | wc -l)"
echo "Zeek connections logged: $(tail -n +9 ../zeek_logs/conn.log | wc -l)"
echo "DNS queries detected: $(tail -n +9 ../zeek_logs/dns.log | wc -l)"
echo "HTTP sessions found: $(tail -n +9 ../zeek_logs/http.log | wc -l)"
