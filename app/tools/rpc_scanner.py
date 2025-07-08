# app/tools/rpc_scanner.py
import socket
import subprocess
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

class RPCSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)

class RPCEnumWorker(QRunnable):
    """RPC enumeration worker using native socket connections"""
    
    def __init__(self, target, username="", password=""):
        super().__init__()
        self.signals = RPCSignals()
        self.target = target
        self.username = username
        self.password = password
        self.is_running = True
        self.results = {}
        
    def test_rpc_port(self, port=135):
        """Test if RPC port is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def enumerate_rpc_services(self):
        """Enumerate RPC services using Windows net commands"""
        services = []
        try:
            if self.username and self.password:
                # Use credentials with net use first, then net view
                subprocess.run(["net", "use", f"\\\\{self.target}\\IPC$", self.password, f"/user:{self.username}"], 
                             capture_output=True, text=True, timeout=10)
            
            result = subprocess.run(["net", "view", f"\\\\{self.target}"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('The command') and not line.startswith('Shared'):
                        if 'Disk' in line or 'Print' in line or '$' in line:
                            services.append(line.strip())
        except Exception:
            pass
        return services
    
    def get_system_info(self):
        """Get basic system information"""
        info = {}
        try:
            if self.username and self.password:
                result = subprocess.run(["systeminfo", "/s", self.target, "/u", self.username, "/p", self.password], 
                                      capture_output=True, text=True, timeout=15)
            else:
                result = subprocess.run(["systeminfo", "/s", self.target], 
                                      capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')[:10]
                info['system_info'] = '\n'.join([line.strip() for line in lines if line.strip()])
        except Exception:
            info['system_info'] = "System information not accessible"
        return info
    
    def run(self):
        try:
            self.signals.status.emit(f"Starting RPC enumeration on {self.target}...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Connecting to RPC service on {self.target}...</p><br>")
            
            # Test RPC port accessibility
            if not self.test_rpc_port():
                self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] RPC port 135 is not accessible on {self.target}</p>")
                self.signals.status.emit("RPC port not accessible")
                return
            
            self.signals.output.emit("<p style='color: #00FF41;'>[+] RPC port 135 is accessible</p><br>")
            
            # Enumerate RPC services
            if self.is_running:
                self.signals.output.emit("<p style='color: #00BFFF;'>Enumerating network shares...</p><br>")
                services = self.enumerate_rpc_services()
                
                if services:
                    self.results['services'] = services
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(services)} network shares:</p><br>")
                    for service in services[:10]:
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {service}</p><br>")
                    if len(services) > 10:
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;... and {len(services) - 10} more</p>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No network shares found or access denied</p>")
            
            # Get system information
            if self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Getting system information...</p><br>")
                info = self.get_system_info()
                
                if info.get('system_info'):
                    self.results.update(info)
                    self.signals.output.emit("<p style='color: #00FF41;'>[+] System information retrieved:</p><br>")
                    lines = info['system_info'].split('\n')[:5]
                    for line in lines:
                        if line.strip():
                            self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {line.strip()}</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] System information not accessible</p>")
            
            # Test additional RPC ports
            if self.is_running:
                rpc_ports = [135, 445, 139, 1024, 1025, 1026]
                open_ports = []
                
                for port in rpc_ports:
                    if self.test_rpc_port(port):
                        open_ports.append(port)
                
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Testing additional RPC ports...</p><br>")
                
                if open_ports:
                    self.results['open_rpc_ports'] = open_ports
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Open RPC-related ports: {', '.join(map(str, open_ports))}</p>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No additional RPC ports found</p>")
            
            # Store results
            if self.results:
                final_results = {self.target: self.results}
                self.signals.results_ready.emit(final_results)
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>RPC enumeration completed</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No RPC information could be retrieved</p>")
            
            self.signals.status.emit("RPC enumeration completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] RPC enumeration failed: {str(e)}</p>")
            self.signals.status.emit("RPC enumeration error")
        finally:
            self.signals.finished.emit()