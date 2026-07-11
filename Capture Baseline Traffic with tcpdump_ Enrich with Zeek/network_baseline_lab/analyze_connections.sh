#!/bin/bash
echo "=== Connection Analysis ==="
echo "Total connections:"
tail -n +9 ../zeek_logs/conn.log | wc -l

echo -e "\nTop destination ports:"
tail -n +9 ../zeek_logs/conn.log | cut -f5 | sort | uniq -c | sort -nr | head -10

echo -e "\nTop protocols:"
tail -n +9 ../zeek_logs/conn.log | cut -f7 | sort | uniq -c | sort -nr
