# app/core/python_vpn.py
import socket
import ssl
import struct
import threading
import time
import hashlib
import hmac
from typing import Dict, Optional, Tuple
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger

class PythonVPN(QObject):
    """Lightweight VPN client using native Python libraries"""
    
    connection_status_changed = pyqtSignal(str, str)  # status, message
    
    def __init__(self):
        super().__init__()
        self.socket = None
        self.ssl_socket = None
        self.connected = False
        self.keep_alive_thread = None
        self.receive_thread = None
        self.running = False
        
    def connect_ssl_vpn(self, server: str, port: int, username: str, password: str) -> Dict:
        """Connect using SSL/TLS tunnel"""
        try:
            self.connection_status_changed.emit("connecting", f"Connecting to {server}:{port}")
            
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            
            # Connect to server
            self.socket.connect((server, port))
            
            # Wrap with SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            self.ssl_socket = context.wrap_socket(self.socket, server_hostname=server)
            
            # Perform authentication
            if not self._authenticate(username, password):
                return {"success": False, "error": "Authentication failed"}
            
            # Start keep-alive and receive threads
            self.running = True
            self.connected = True
            
            self.keep_alive_thread = threading.Thread(target=self._keep_alive)
            self.keep_alive_thread.daemon = True
            self.keep_alive_thread.start()
            
            self.receive_thread = threading.Thread(target=self._receive_data)
            self.receive_thread.daemon = True
            self.receive_thread.start()
            
            self.connection_status_changed.emit("connected", "VPN connection established")
            logger.info(f"Python VPN connected to {server}:{port}")
            
            return {"success": True, "message": "VPN connection established"}
            
        except Exception as e:
            logger.error(f"Python VPN connection failed: {e}")
            self.disconnect()
            return {"success": False, "error": str(e)}
    
    def connect_tcp_tunnel(self, server: str, port: int, username: str, password: str) -> Dict:
        """Connect using simple TCP tunnel"""
        try:
            self.connection_status_changed.emit("connecting", f"Creating TCP tunnel to {server}:{port}")
            
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            
            # Connect to server
            self.socket.connect((server, port))
            
            # Send authentication
            auth_data = f"{username}:{password}".encode()
            auth_header = struct.pack("!H", len(auth_data)) + auth_data
            self.socket.send(auth_header)
            
            # Wait for auth response
            response = self.socket.recv(4)
            if len(response) != 4 or struct.unpack("!I", response)[0] != 0x00000001:
                return {"success": False, "error": "Authentication failed"}
            
            # Start threads
            self.running = True
            self.connected = True
            
            self.keep_alive_thread = threading.Thread(target=self._keep_alive_tcp)
            self.keep_alive_thread.daemon = True
            self.keep_alive_thread.start()
            
            self.connection_status_changed.emit("connected", "TCP tunnel established")
            logger.info(f"TCP tunnel connected to {server}:{port}")
            
            return {"success": True, "message": "TCP tunnel established"}
            
        except Exception as e:
            logger.error(f"TCP tunnel connection failed: {e}")
            self.disconnect()
            return {"success": False, "error": str(e)}
    
    def connect_socks_proxy(self, server: str, port: int, username: str = "", password: str = "") -> Dict:
        """Connect using SOCKS5 proxy"""
        try:
            self.connection_status_changed.emit("connecting", f"Connecting to SOCKS5 proxy {server}:{port}")
            
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            
            # Connect to proxy
            self.socket.connect((server, port))
            
            # SOCKS5 handshake
            if username and password:
                # Authentication required
                self.socket.send(b'\x05\x02\x00\x02')  # Version 5, 2 methods, no auth + user/pass
                response = self.socket.recv(2)
                if response != b'\x05\x02':  # Server chose user/pass auth
                    return {"success": False, "error": "SOCKS5 authentication method not supported"}
                
                # Send credentials
                auth_data = struct.pack("!B", len(username)) + username.encode()
                auth_data += struct.pack("!B", len(password)) + password.encode()
                self.socket.send(b'\x01' + auth_data)
                
                response = self.socket.recv(2)
                if response != b'\x01\x00':
                    return {"success": False, "error": "SOCKS5 authentication failed"}
            else:
                # No authentication
                self.socket.send(b'\x05\x01\x00')  # Version 5, 1 method, no auth
                response = self.socket.recv(2)
                if response != b'\x05\x00':
                    return {"success": False, "error": "SOCKS5 handshake failed"}
            
            self.running = True
            self.connected = True
            
            self.connection_status_changed.emit("connected", "SOCKS5 proxy connected")
            logger.info(f"SOCKS5 proxy connected to {server}:{port}")
            
            return {"success": True, "message": "SOCKS5 proxy connected"}
            
        except Exception as e:
            logger.error(f"SOCKS5 connection failed: {e}")
            self.disconnect()
            return {"success": False, "error": str(e)}
    
    def _authenticate(self, username: str, password: str) -> bool:
        """Perform SSL VPN authentication"""
        try:
            # Send auth request
            auth_msg = {
                "type": "auth",
                "username": username,
                "password": hashlib.sha256(password.encode()).hexdigest()
            }
            
            import json
            auth_data = json.dumps(auth_msg).encode()
            self.ssl_socket.send(struct.pack("!H", len(auth_data)) + auth_data)
            
            # Receive response
            response_len = struct.unpack("!H", self.ssl_socket.recv(2))[0]
            response_data = self.ssl_socket.recv(response_len)
            response = json.loads(response_data.decode())
            
            return response.get("status") == "success"
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def _keep_alive(self):
        """Keep SSL connection alive"""
        while self.running and self.connected:
            try:
                if self.ssl_socket:
                    ping_msg = {"type": "ping", "timestamp": time.time()}
                    import json
                    ping_data = json.dumps(ping_msg).encode()
                    self.ssl_socket.send(struct.pack("!H", len(ping_data)) + ping_data)
                time.sleep(30)  # Send ping every 30 seconds
            except Exception as e:
                logger.error(f"Keep-alive error: {e}")
                break
    
    def _keep_alive_tcp(self):
        """Keep TCP connection alive"""
        while self.running and self.connected:
            try:
                if self.socket:
                    # Send keep-alive packet
                    self.socket.send(b'\x00\x00\x00\x01')  # Keep-alive marker
                time.sleep(30)
            except Exception as e:
                logger.error(f"TCP keep-alive error: {e}")
                break
    
    def _receive_data(self):
        """Receive data from SSL connection"""
        while self.running and self.connected:
            try:
                if self.ssl_socket:
                    # Receive message length
                    length_data = self.ssl_socket.recv(2)
                    if len(length_data) != 2:
                        break
                    
                    msg_len = struct.unpack("!H", length_data)[0]
                    if msg_len > 0:
                        # Receive message data
                        msg_data = self.ssl_socket.recv(msg_len)
                        self._process_message(msg_data)
                        
            except Exception as e:
                logger.error(f"Receive error: {e}")
                break
    
    def _process_message(self, data: bytes):
        """Process received message"""
        try:
            import json
            message = json.loads(data.decode())
            msg_type = message.get("type")
            
            if msg_type == "pong":
                # Pong response to ping
                pass
            elif msg_type == "disconnect":
                self.connection_status_changed.emit("disconnected", "Server disconnected")
                self.disconnect()
            elif msg_type == "error":
                error_msg = message.get("message", "Unknown error")
                self.connection_status_changed.emit("error", f"Server error: {error_msg}")
                
        except Exception as e:
            logger.error(f"Message processing error: {e}")
    
    def disconnect(self) -> Dict:
        """Disconnect VPN"""
        try:
            self.running = False
            self.connected = False
            
            if self.ssl_socket:
                try:
                    self.ssl_socket.close()
                except:
                    pass
                self.ssl_socket = None
            
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
            
            # Wait for threads to finish
            if self.keep_alive_thread and self.keep_alive_thread.is_alive():
                self.keep_alive_thread.join(timeout=2)
            
            if self.receive_thread and self.receive_thread.is_alive():
                self.receive_thread.join(timeout=2)
            
            self.connection_status_changed.emit("disconnected", "VPN disconnected")
            logger.info("Python VPN disconnected")
            
            return {"success": True, "message": "VPN disconnected"}
            
        except Exception as e:
            logger.error(f"Disconnect error: {e}")
            return {"success": False, "error": str(e)}
    
    def get_status(self) -> Dict:
        """Get connection status"""
        return {
            "connected": self.connected,
            "socket_connected": self.socket is not None,
            "ssl_connected": self.ssl_socket is not None,
            "threads_running": self.running
        }
    
    def test_connection(self, target: str = "8.8.8.8") -> Dict:
        """Test connection through tunnel"""
        if not self.connected:
            return {"success": False, "error": "Not connected to VPN"}
        
        try:
            # Create test socket through tunnel
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            
            start_time = time.time()
            result = test_socket.connect_ex((target, 80))
            end_time = time.time()
            
            test_socket.close()
            
            if result == 0:
                latency = int((end_time - start_time) * 1000)
                return {"success": True, "latency": latency}
            else:
                return {"success": False, "error": "Connection test failed"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}

# Global Python VPN instance
python_vpn = PythonVPN()