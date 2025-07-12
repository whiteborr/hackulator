# app/core/vpn_manager.py
import subprocess
import os
import time
import threading
import sys
from typing import Dict, Optional, List
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger

# Import the OpenVPN implementation
from app.core.openvpn_client import OpenVPNClient
from app.core.openvpn_ovpn_parser import OVPNConfigParser

class VPNManager(QObject):
    """VPN connection management for secure scanning"""
    
    connection_status_changed = pyqtSignal(str, str)  # status, message
    
    def __init__(self):
        super().__init__()
        self.current_connection = None
        self.openvpn_process = None
        self.openvpn_client = None
        self.connection_thread = None
        self.is_connected = False
        
    def connect_openvpn(self, config_file: str, username: str = "", password: str = "") -> Dict:
        """Connect using OpenVPN config file with Python implementation"""
        try:
            if not os.path.exists(config_file):
                return {"success": False, "error": "Config file not found"}

            # Parse OpenVPN configuration to get embedded certs
            parser = OVPNConfigParser(config_file)
            cert_files = parser.extract_embedded_blocks()

            # Certificates are handled by official OpenVPN client
            print("Using official OpenVPN client for certificate handling")

            # Example hardcoded values (you should get these dynamically!)
            server_ip = "38.46.226.73"
            server_port = 1337
            session_id = "8834c31d403239ab"
            command_id = 0x1178636e
            payload_key = 0x104bed3b

            # Create OpenVPN config object
            from app.core.openvpn_client import OpenVPNConfig
            config = OpenVPNConfig(
                remote_host=server_ip,
                remote_port=server_port
            )
            
            # Create OpenVPNClient with config file path
            self.openvpn_client = OpenVPNClient(config_file)
            print(f"Using command_id: {hex(command_id)}, payload_key: {hex(payload_key)}")

            # Start connection in separate thread
            self.connection_thread = threading.Thread(target=self._run_python_openvpn)
            self.connection_thread.daemon = True
            self.connection_thread.start()

            self.current_connection = {
                "type": "openvpn",
                "config": config_file,
                "username": username
            }

            self.connection_status_changed.emit("connecting", "Establishing VPN connection...")
            logger.info(f"OpenVPN connection started with config: {config_file}")

            return {"success": True, "message": "VPN connection initiated"}

        except Exception as e:
            logger.error(f"OpenVPN connection failed: {e}")
            return {"success": False, "error": str(e)}

    
    def connect_manual(self, server: str, port: int, protocol: str, username: str, password: str) -> Dict:
        """Connect using manual configuration"""
        try:
            # Create temporary config file
            config_content = f"""
client
dev tun
proto {protocol.lower()}
remote {server} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
verb 3
"""
            
            temp_config = "temp_vpn_config.ovpn"
            with open(temp_config, 'w') as f:
                f.write(config_content)
            
            return self.connect_openvpn(temp_config, username, password)
            
        except Exception as e:
            logger.error(f"Manual VPN connection failed: {e}")
            return {"success": False, "error": str(e)}
    
    def disconnect(self) -> Dict:
        """Disconnect VPN"""
        try:
            if hasattr(self, 'openvpn_client') and self.openvpn_client:
                self.openvpn_client = None
            
            if self.openvpn_process:
                self.openvpn_process.terminate()
                self.openvpn_process.wait(timeout=10)
                self.openvpn_process = None
            
            self.is_connected = False
            self.current_connection = None
            
            # Clean up temp files
            for temp_file in ["temp_auth.txt", "temp_vpn_config.ovpn"]:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            
            self.connection_status_changed.emit("disconnected", "VPN disconnected")
            logger.info("VPN connection terminated")
            
            return {"success": True, "message": "VPN disconnected"}
            
        except Exception as e:
            logger.error(f"VPN disconnect failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _run_python_openvpn(self):
        """Run the Python OpenVPN client"""
        try:
            # Attempt connection
            success = self.openvpn_client.connect()
            if success:
                self.is_connected = True
                self.connection_status_changed.emit("connected", "VPN handshake completed")
            else:
                raise Exception("Handshake failed")
            
            # Keep connection alive for a while
            time.sleep(30)
                
        except Exception as e:
            self.connection_status_changed.emit("error", f"Connection error: {str(e)}")
        finally:
            self.is_connected = False
            self.connection_status_changed.emit("disconnected", "VPN connection terminated")
    

    
    def get_status(self) -> Dict:
        """Get current VPN status"""
        process_running = False
        if hasattr(self, 'openvpn_client') and self.openvpn_client:
            process_running = True  # Client exists
        elif self.openvpn_process:
            process_running = self.openvpn_process.poll() is None
            
        return {
            "connected": self.is_connected,
            "connection": self.current_connection,
            "process_running": process_running
        }
    
    def test_connectivity(self, target: str = "8.8.8.8") -> Dict:
        """Test connectivity through VPN"""
        try:
            result = subprocess.run(
                ["ping", "-n", "1", target],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            success = result.returncode == 0
            return {
                "success": success,
                "latency": self._extract_latency(result.stdout) if success else None,
                "output": result.stdout
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _extract_latency(self, ping_output: str) -> Optional[int]:
        """Extract latency from ping output"""
        import re
        match = re.search(r'time[<=](\d+)ms', ping_output)
        return int(match.group(1)) if match else None
    
    def _find_openvpn_executable(self) -> Optional[str]:
        """Find OpenVPN executable on system"""
        import shutil
        
        # Common OpenVPN installation paths on Windows (prioritize CLI version)
        common_paths = [
            r"C:\Program Files\OpenVPN\bin\openvpn.exe",
            r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
            r"C:\OpenVPN\bin\openvpn.exe",
            # GUI versions (less preferred)
            r"C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe",
            r"C:\Program Files (x86)\OpenVPN Connect\OpenVPNConnect.exe"
        ]
        
        # Check common installation paths first
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        # Check system PATH for both executables
        for exe_name in ['openvpn', 'OpenVPNConnect']:
            exe_path = shutil.which(exe_name)
            if exe_path:
                return exe_path
        
        return None

# Global VPN manager instance
vpn_manager = VPNManager()