#!/usr/bin/env python3
import socket
import struct
import random
import time
from datetime import datetime

def create_netflow_packet():
    # NetFlow v5 header
    version = 5
    count = 1
    sys_uptime = int(time.time() * 1000) % (2**32)
    unix_secs = int(time.time())
    unix_nsecs = 0
    flow_sequence = random.randint(0, 2**32-1)
    engine_type = 0
    engine_id = 0
    sampling_interval = 0
    
    header = struct.pack('!HHIIIIBBH', version, count, sys_uptime, unix_secs, 
                        unix_nsecs, flow_sequence, engine_type, engine_id, sampling_interval)
    
    # NetFlow v5 record
    srcaddr = socket.inet_aton(f"192.168.1.{random.randint(1, 254)}")
    dstaddr = socket.inet_aton(f"10.0.0.{random.randint(1, 254)}")
    nexthop = socket.inet_aton("0.0.0.0")
    input_iface = random.randint(1, 10)
    output_iface = random.randint(1, 10)
    dPkts = random.randint(1, 1000)
    dOctets = random.randint(64, 65535)
    first = sys_uptime - random.randint(1000, 10000)
    last = sys_uptime - random.randint(1, 1000)
    srcport = random.randint(1024, 65535)
    dstport = random.choice([80, 443, 22, 53, 25])
    pad1 = 0
    tcp_flags = random.randint(0, 255)
    prot = random.choice([6, 17, 1])  # TCP, UDP, ICMP
    tos = 0
    src_as = random.randint(1, 65535)
    dst_as = random.randint(1, 65535)
    src_mask = 24
    dst_mask = 24
    pad2 = 0
    
    record = struct.pack('!4s4s4sHHIIIIHHBBBBHHBBH', srcaddr, dstaddr, nexthop,
                        input_iface, output_iface, dPkts, dOctets, first, last,
                        srcport, dstport, pad1, tcp_flags, prot, tos, src_as,
                        dst_as, src_mask, dst_mask, pad2)
    
    return header + record

def send_netflow_data():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print("Starting NetFlow data generation...")
    for i in range(100):
        packet = create_netflow_packet()
        sock.sendto(packet, ('127.0.0.1', 2055))
        
        # Create some anomalous traffic patterns
        if i % 20 == 0:
            # High volume anomaly
            for _ in range(10):
                packet = create_netflow_packet()
                sock.sendto(packet, ('127.0.0.1', 2055))
        
        time.sleep(0.1)
    
    sock.close()
    print("NetFlow data generation completed")

if __name__ == "__main__":
    send_netflow_data()
