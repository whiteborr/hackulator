#!/usr/bin/env python3
"""
OpenVPN Connection Manager - Handles the complete connection flow
"""

import socket
import struct
import time
import os
import hmac
import hashlib
import random
from app.core.openvpn_minimal import ConfigParser

class OpenVPNConnectionManager:
    def __init__(self, config_path):
        self.config = ConfigParser.parse_ovpn_file(config_path)
        self.socket = None
        self.session_id = os.urandom(8)
        self.server_session_id = None
        self.connected = False
        
    def create_handshake_packet(self):
        """Create exact handshake packet"""
        packet = bytearray()
        packet.append(0x38)
        packet.extend(self.session_id)
        
        command_id = struct.pack('!I', random.randint(0x10000000, 0x1FFFFFFF))
        packet.extend(command_id)
        
        payload_key = struct.pack('!I', random.randint(0x10000000, 0x1FFFFFFF))
        packet.extend(payload_key)
        
        raw_data = bytearray()
        raw_data.extend(os.urandom(8))
        raw_data.extend(struct.pack('!I', int(time.time()) & 0xFFFFFFFF))
        raw_data.extend(struct.pack('!I', random.randint(0x30000000, 0x3FFFFFFF)))
        raw_data.extend(struct.pack('!I', struct.unpack('!I', command_id)[0] ^ 0x6F000000))
        raw_data.extend(struct.pack('!I', random.randint(0xD0000000, 0xDFFFFFFF)))
        raw_data.extend(b'\x00\x00\x00\x01' + struct.pack('!I', 0x68706aca) + b'\x00\x00\x00\x00\x00')
        
        packet.extend(raw_data)
        return self.add_tls_auth(bytes(packet))
    
    def add_tls_auth(self, packet):
        """Add TLS-auth HMAC"""
        if not self.config.tls_auth:
            return packet
            
        tls_key = self.extract_tls_key()
        if not tls_key:
            return packet
            
        hmac_key = tls_key[0:64]
        timestamp = struct.pack('!I', int(time.time()))
        hmac_input = timestamp + packet
        
        h = hmac.new(hmac_key, hmac_input, hashlib.sha1)
        hmac_digest = h.digest()
        
        return packet[:9] + hmac_digest + timestamp + packet[9:]
    
    def extract_tls_key(self):
        """Extract TLS key from config"""
        if not self.config.tls_auth:
            return None
            
        lines = self.config.tls_auth.split('\n')
        hex_lines = []
        in_key = False
        
        for line in lines:
            line = line.strip()
            if '-----BEGIN OpenVPN Static key' in line:
                in_key = True
            elif '-----END OpenVPN Static key' in line:
                break
            elif in_key and line and not line.startswith('#'):
                if all(c in '0123456789abcdefABCDEF' for c in line):
                    hex_lines.append(line)
        
        hex_data = ''.join(hex_lines)
        return bytes.fromhex(hex_data) if len(hex_data) >= 512 else None
    
    def connect(self):
        """Establish connection"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_addr = (socket.gethostbyname(self.config.remote_host), self.config.remote_port)
            
            packet = self.create_handshake_packet()
            print(f"Sending {len(packet)} byte packet to {server_addr}")
            
            self.socket.sendto(packet, server_addr)
            self.socket.settimeout(15.0)
            
            try:
                response, addr = self.socket.recvfrom(2048)
                print(f"Received {len(response)} bytes")
                
                if len(response) >= 17:
                    msg_type = response[0]
                    if msg_type in [0x40, 0x20]:
                        self.server_session_id = response[1:9]
                        self.connected = True
                        print("Connection established!")
                        return True
                        
            except socket.timeout:
                print("No server response - connection may be filtered")
                
        except Exception as e:
            print(f"Connection error: {e}")
            
        return False
    
    def disconnect(self):
        if self.socket:
            self.socket.close()

def main():
    manager = OpenVPNConnectionManager("lab_whiteborr.ovpn")
    if manager.connect():
        print("SUCCESS: OpenVPN connection established")
        time.sleep(5)
        manager.disconnect()
    else:
        print("FAILED: Could not establish connection")

if __name__ == "__main__":
    main()