import socket
import struct
import time
import random
import threading

class ProtocolA:
    """Simple request-response protocol"""
    def __init__(self, port=8001):
        self.port = port
        
    def create_packet(self, msg_type, seq_num, data):
        # Header: magic(2) + type(1) + seq(2) + length(2) + data
        magic = 0xABCD
        length = len(data)
        header = struct.pack('!HBHH', magic, msg_type, seq_num, length)
        return header + data.encode()
    
    def server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('localhost', self.port))
        sock.listen(1)
        
        while True:
            try:
                conn, addr = sock.accept()
                data = conn.recv(1024)
                if data:
                    # Send response
                    response = self.create_packet(2, random.randint(1, 1000), "ACK")
                    conn.send(response)
                conn.close()
            except:
                break
    
    def client(self):
        for i in range(10):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(('localhost', self.port))
                packet = self.create_packet(1, i, f"Request {i}")
                sock.send(packet)
                response = sock.recv(1024)
                sock.close()
                time.sleep(0.5)
            except:
                pass

class ProtocolB:
    """Heartbeat protocol"""
    def __init__(self, port=8002):
        self.port = port
    
    def create_packet(self, status, timestamp, node_id):
        # Header: magic(4) + status(1) + timestamp(4) + node_id(2)
        magic = 0x12345678
        packet = struct.pack('!IBIIH', magic, status, timestamp, node_id, 0xFFFF)
        return packet
    
    def server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('localhost', self.port))
        
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                # Send heartbeat response
                response = self.create_packet(1, int(time.time()), random.randint(100, 999))
                sock.sendto(response, addr)
            except:
                break
    
    def client(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(15):
            try:
                packet = self.create_packet(0, int(time.time()), 42)
                sock.sendto(packet, ('localhost', self.port))
                response, addr = sock.recvfrom(1024)
                time.sleep(1)
            except:
                pass
        sock.close()

class ProtocolC:
    """File transfer protocol"""
    def __init__(self, port=8003):
        self.port = port
    
    def create_packet(self, cmd, file_id, chunk_num, data):
        # Header: sync(2) + cmd(1) + file_id(4) + chunk(4) + size(2) + data
        sync = 0xDEAD
        size = len(data)
        header = struct.pack('!HBIIH', sync, cmd, file_id, chunk_num, size)
        return header + data
    
    def server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('localhost', self.port))
        sock.listen(1)
        
        while True:
            try:
                conn, addr = sock.accept()
                data = conn.recv(1024)
                if data:
                    # Send file chunk
                    chunk_data = b"File data chunk " + str(random.randint(1, 100)).encode()
                    response = self.create_packet(2, 1001, random.randint(1, 10), chunk_data)
                    conn.send(response)
                conn.close()
            except:
                break
    
    def client(self):
        for i in range(8):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(('localhost', self.port))
                data = b"Request chunk " + str(i).encode()
                packet = self.create_packet(1, 1001, i, data)
                sock.send(packet)
                response = sock.recv(1024)
                sock.close()
                time.sleep(0.3)
            except:
                pass

if __name__ == "__main__":
    # Start servers in background threads
    protocols = [ProtocolA(), ProtocolB(), ProtocolC()]
    
    for proto in protocols:
        server_thread = threading.Thread(target=proto.server, daemon=True)
        server_thread.start()
    
    time.sleep(2)  # Let servers start
    
    # Run clients
    for proto in protocols:
        client_thread = threading.Thread(target=proto.client)
        client_thread.start()
        client_thread.join()
    
    print("Protocol simulation completed")
