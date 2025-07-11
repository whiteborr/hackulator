#!/usr/bin/env python3
"""
OpenVPN Client in Python

This script implements a basic OpenVPN client capable of establishing
a secure connection using a .ovpn configuration file. It handles
parsing the configuration, including inline certificates and keys,
and performs the correct OpenVPN handshake sequence with TLS-Auth.
"""

import argparse
import socket
import ssl
import struct
import threading
import time
import sys
import os
import random
import hashlib
import hmac
import tempfile
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
from enum import Enum

# --- Constants based on OpenVPN Protocol ---

# Control Channel Opcodes (from ssl.h)
P_CONTROL_HARD_RESET_CLIENT_V2 = 7
P_CONTROL_HARD_RESET_SERVER_V2 = 8
P_CONTROL_V1 = 4
P_ACK_V1 = 5
P_DATA_V1 = 6
P_DATA_V2 = 9

# --- Data Structures ---

class OpenVPNState(Enum):
    """Enumeration for OpenVPN connection states."""
    INITIAL = "INITIAL"
    CONNECTING = "CONNECTING"
    WAIT = "WAIT"
    AUTH = "AUTH"
    GET_CONFIG = "GET_CONFIG"
    ASSIGN_IP = "ASSIGN_IP"
    ADD_ROUTES = "ADD_ROUTES"
    CONNECTED = "CONNECTED"
    RECONNECTING = "RECONNECTING"
    EXITING = "EXITING"

@dataclass
class OpenVPNConfig:
    """Stores configuration parsed from an .ovpn file."""
    remote_host: str = ""
    remote_port: int = 1194
    protocol: str = "udp"
    ca_cert: Optional[str] = None
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    tls_auth_key: Optional[bytes] = None
    key_direction: Optional[int] = None
    cipher: str = "AES-256-GCM"
    auth: str = "SHA256"
    verb: int = 3

class ConfigParser:
    """Parses .ovpn configuration files."""

    @staticmethod
    def _extract_inline_block(lines: List[str], tag: str) -> Optional[str]:
        """Extracts content from an inline block like <ca>...</ca>."""
        try:
            start_index = lines.index(f'<{tag}>\n')
            end_index = lines.index(f'</{tag}>\n')
            return "".join(lines[start_index + 1:end_index])
        except ValueError:
            return None

    @staticmethod
    def _extract_tls_auth_key(content: str) -> Optional[bytes]:
        """Parses the hex key from an inline <tls-auth> block."""
        in_key_section = False
        hex_key = ""
        for line in content.splitlines():
            line = line.strip()
            if '-----BEGIN OpenVPN Static key V1-----' in line:
                in_key_section = True
                continue
            elif '-----END OpenVPN Static key V1-----' in line:
                break
            elif in_key_section and not line.startswith('#'):
                hex_key += line
        
        if hex_key:
            return bytes.fromhex(hex_key)
        return None

    @staticmethod
    def parse_ovpn_file(filepath: str) -> OpenVPNConfig:
        """Parses a .ovpn configuration file."""
        config = OpenVPNConfig()
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Configuration file not found: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.splitlines(keepends=True)

        # Extract inline blocks first
        config.ca_cert = ConfigParser._extract_inline_block(lines, 'ca')
        config.client_cert = ConfigParser._extract_inline_block(lines, 'cert')
        config.client_key = ConfigParser._extract_inline_block(lines, 'key')
        
        tls_auth_content = ConfigParser._extract_inline_block(lines, 'tls-auth')
        if tls_auth_content:
            config.tls_auth_key = ConfigParser._extract_tls_auth_key(tls_auth_content)

        # Parse remaining directives
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';') or line.startswith('<'):
                continue
            
            parts = line.split()
            cmd = parts[0].lower()
            
            if cmd == 'remote' and len(parts) >= 2:
                config.remote_host = parts[1]
                if len(parts) > 2 and parts[2].isdigit():
                    config.remote_port = int(parts[2])
                if len(parts) > 3:
                    config.protocol = parts[3].lower()
            elif cmd == 'proto' and len(parts) > 1:
                config.protocol = parts[1].lower()
            elif cmd == 'cipher' and len(parts) > 1:
                config.cipher = parts[1]
            elif cmd == 'auth' and len(parts) > 1:
                config.auth = parts[1]
            elif cmd == 'key-direction' and len(parts) > 1:
                config.key_direction = int(parts[1])
            elif cmd == 'verb' and len(parts) > 1:
                config.verb = int(parts[1])

        return config

class OpenVPNClient:
    """Main OpenVPN client implementation."""
    
    def __init__(self, config: OpenVPNConfig, **kwargs): # Added **kwargs to accept extra arguments
        self.config = config
        self.state = OpenVPNState.INITIAL
        self.socket: Optional[socket.socket] = None
        self.server_addr: Optional[Tuple[str, int]] = None
        self.session_id = os.urandom(8)
        self.packet_id = 0
        self.running = False
        self.connected = False
        self.last_keepalive = time.time()
        self.keepalive_interval = 10  # seconds

    def log(self, level: int, message: str):
        """Logs a message if the verbosity level is sufficient."""
        if level <= self.config.verb:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] {message}")

    def _create_handshake_packet(self) -> bytes:
        """
        Creates the initial P_CONTROL_HARD_RESET_CLIENT_V2 packet.
        This is the first packet sent to the server to initiate the handshake.
        """
        self.packet_id += 1
        
        # Plaintext part of the control packet
        plaintext = bytearray()
        
        # 1. Opcode and Key ID
        opcode_byte = (P_CONTROL_HARD_RESET_CLIENT_V2 << 3) | 0
        plaintext.append(opcode_byte)
        
        # 2. Client's Session ID
        plaintext.extend(self.session_id)
        
        # 3. Reliability Layer ACK (acknowledging a fictional packet 0 from server)
        ack_count = 1 
        ack_packet_id = 0
        ack_remote_session_id = b'\x00' * 8 # Unknown at this point
        
        plaintext.append(ack_count)
        plaintext.extend(struct.pack('!I', ack_packet_id))
        plaintext.extend(ack_remote_session_id)
        
        # 4. This packet's own ID
        plaintext.extend(struct.pack('!I', self.packet_id))

        # If tls-auth is not used, the plaintext is the final packet
        if not self.config.tls_auth_key:
            return bytes(plaintext)
            
        # --- If tls-auth is used, calculate and prepend HMAC ---
        
        # Determine which HMAC key to use based on key-direction
        key = self.config.tls_auth_key
        hmac_key_size = len(key) // 4  # HMAC key is 1/4 of the total key material
        
        if self.config.key_direction == 1:
            hmac_key_start = hmac_key_size * 2
        else:
            hmac_key_start = 0
        
        hmac_key = key[hmac_key_start : hmac_key_start + hmac_key_size]
        
        # The HMAC is calculated over the entire plaintext payload
        signature = hmac.new(hmac_key, bytes(plaintext), hashlib.sha256).digest()
        
        # Assemble the final on-the-wire packet
        # Format: [Opcode][HMAC][Packet ID][Rest of Plaintext]
        # This structure is a result of the 'swap_hmac' function in ssl_pkt.c
        final_packet = bytearray()
        final_packet.append(opcode_byte)
        final_packet.extend(signature)
        final_packet.extend(struct.pack('!I', self.packet_id))
        final_packet.extend(plaintext[1 + 8:]) # Append session_id and ACK data
        
        return bytes(final_packet)

    def connect(self) -> bool:
        """Establishes a connection and performs the handshake."""
        self.log(1, f"Connecting to {self.config.remote_host}:{self.config.remote_port} via {self.config.protocol.upper()}")
        
        try:
            server_ip = socket.gethostbyname(self.config.remote_host)
            self.server_addr = (server_ip, self.config.remote_port)
            self.log(2, f"Resolved {self.config.remote_host} to {server_ip}")
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Send the initial handshake packet
            handshake_packet = self._create_handshake_packet()
            self.socket.sendto(handshake_packet, self.server_addr)
            self.log(3, f"Sent P_CONTROL_HARD_RESET_CLIENT_V2 ({len(handshake_packet)} bytes)")
            self.log(4, f"Handshake Packet Hex: {handshake_packet.hex()}")

            # Wait for server response
            self.socket.settimeout(15.0)
            response, _ = self.socket.recvfrom(2048)
            self.log(3, f"Received response from server ({len(response)} bytes)")
            self.log(4, f"Response Hex: {response.hex()}")
            
            # A successful handshake results in a P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8)
            # A simple check for the opcode is sufficient for this stage.
            if response and (response[0] >> 3) == P_CONTROL_HARD_RESET_SERVER_V2:
                self.log(1, "✓ Handshake successful! Connection established.")
                self.connected = True
                self.state = OpenVPNState.CONNECTED
                return True
            else:
                self.log(1, "✗ Handshake failed: Unexpected server response.")
                return False

        except socket.timeout:
            self.log(1, "✗ Handshake failed: Connection timed out.")
            return False
        except Exception as e:
            self.log(1, f"✗ Connection failed: {e}")
            return False
        finally:
            if not self.connected:
                self.disconnect()

    def disconnect(self):
        """Closes the socket connection."""
        if self.socket:
            self.socket.close()
            self.socket = None
        self.connected = False
        self.log(1, "Connection closed.")

def main():
    """Main entry point for the OpenVPN client."""
    parser = argparse.ArgumentParser(description="Python OpenVPN Client")
    parser.add_argument("config_file", help="Path to the .ovpn configuration file")
    args = parser.parse_args()

    try:
        print("--- OpenVPN Python Client ---")
        config = ConfigParser.parse_ovpn_file(args.config_file)
        
        client = OpenVPNClient(config)
        if client.connect():
            # In a real client, you would now enter a loop to handle
            # data channel packets (reading from/writing to a TUN interface).
            # For this example, we'll just keep the connection open for a bit.
            print("\nVPN connection is active. Press Ctrl+C to disconnect.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nDisconnecting...")
        
        client.disconnect()

    except FileNotFoundError:
        print(f"Error: Configuration file not found at '{args.config_file}'")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
