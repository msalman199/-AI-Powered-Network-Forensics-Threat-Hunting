#!/bin/bash
echo "=== DNS Analysis ==="
echo "Total DNS queries:"
tail -n +9 ../zeek_logs/dns.log | wc -l

echo -e "\nTop queried domains:"
tail -n +9 ../zeek_logs/dns.log | cut -f10 | sort | uniq -c | sort -nr | head -10

echo -e "\nQuery types:"
tail -n +9 ../zeek_logs/dns.log | cut -f14 | sort | uniq -c | sort -nr
