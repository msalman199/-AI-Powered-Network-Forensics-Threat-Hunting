from scapy.all import *
import time
import threading
import subprocess

def capture_traffic(interface="lo", duration=30, output_file="protocol_traffic.pcap"):
    """Capture network traffic for analysis"""
    print(f"Starting traffic capture on {interface} for {duration} seconds...")
    
    # Start packet capture
    packets = sniff(iface=interface, timeout=duration, filter="tcp or udp")
    
    # Save captured packets
    wrpcap(output_file, packets)
    print(f"Captured {len(packets)} packets and saved to {output_file}")
    
    return packets

def run_protocol_simulation():
    """Run the protocol simulators"""
    print("Starting protocol simulation...")
    subprocess.run(["python3", "protocol_simulators.py"])

if __name__ == "__main__":
    # Start protocol simulation in background
    sim_thread = threading.Thread(target=run_protocol_simulation)
    sim_thread.start()
    
    # Wait a moment for servers to start
    time.sleep(3)
    
    # Capture traffic
    packets = capture_traffic(duration=25)
    
    # Wait for simulation to complete
    sim_thread.join()
    
    print("Traffic capture completed successfully")
