# app/tools/rpc_scanner.py
import subprocess
import re
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

class RPCSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)

class RPCEnumWorker(QRunnable):
    """RPC enumeration worker using rpcclient"""
    
    def __init__(self, target, username="", password=""):
        super().__init__()
        self.signals = RPCSignals()
        self.target = target
        self.username = username
        self.password = password
        self.is_running = True
        self.results = {}
        
    def run_rpcclient_command(self, command):
        """Execute rpcclient command and return output"""
        try:
            if self.username:
                cmd = ["rpcclient", "-U", f"{self.username}%{self.password}", self.target, "-c", command]
            else:
                cmd = ["rpcclient", "-N", "-U", "", self.target, "-c", command]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
        except FileNotFoundError:
            return "", "rpcclient not found - install samba-common-bin", 1
        except Exception as e:
            return "", str(e), 1
    
    def parse_users(self, output):
        """Parse enumdomusers output"""
        users = []
        for line in output.split('\n'):
            if 'user:' in line:
                match = re.search(r'user:\[([^\]]+)\].*rid:\[([^\]]+)\]', line)
                if match:
                    users.append({'name': match.group(1), 'rid': match.group(2)})
        return users
    
    def parse_groups(self, output):
        """Parse enumdomgroups output"""
        groups = []
        for line in output.split('\n'):
            if 'group:' in line:
                match = re.search(r'group:\[([^\]]+)\].*rid:\[([^\]]+)\]', line)
                if match:
                    groups.append({'name': match.group(1), 'rid': match.group(2)})
        return groups
    
    def run(self):
        try:
            self.signals.status.emit(f"Starting RPC enumeration on {self.target}...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Connecting to RPC service on {self.target}...</p><br>")
            
            # Test connection first
            stdout, stderr, returncode = self.run_rpcclient_command("getusername")
            if returncode != 0:
                self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Failed to connect: {stderr}</p>")
                self.signals.status.emit("RPC connection failed")
                return
            
            self.signals.output.emit("<p style='color: #00FF41;'>[+] RPC connection successful</p><br>")
            
            # Enumerate domain users
            if self.is_running:
                self.signals.output.emit("<p style='color: #00BFFF;'>Enumerating domain users...</p>")
                stdout, stderr, returncode = self.run_rpcclient_command("enumdomusers")
                
                if returncode == 0 and stdout.strip():
                    users = self.parse_users(stdout)
                    if users:
                        self.results['users'] = users
                        self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(users)} users:</p>")
                        for user in users[:10]:  # Show first 10
                            self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {user['name']} (RID: {user['rid']})</p>")
                        if len(users) > 10:
                            self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;... and {len(users) - 10} more</p>")
                    else:
                        self.signals.output.emit("<p style='color: #FFAA00;'>[!] No users found or access denied</p>")
                else:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>[!] User enumeration failed: {stderr}</p>")
            
            # Enumerate domain groups
            if self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Enumerating domain groups...</p>")
                stdout, stderr, returncode = self.run_rpcclient_command("enumdomgroups")
                
                if returncode == 0 and stdout.strip():
                    groups = self.parse_groups(stdout)
                    if groups:
                        self.results['groups'] = groups
                        self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(groups)} groups:</p>")
                        for group in groups[:10]:  # Show first 10
                            self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {group['name']} (RID: {group['rid']})</p>")
                        if len(groups) > 10:
                            self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;... and {len(groups) - 10} more</p>")
                    else:
                        self.signals.output.emit("<p style='color: #FFAA00;'>[!] No groups found or access denied</p>")
                else:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>[!] Group enumeration failed: {stderr}</p>")
            
            # Get server info
            if self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Getting server information...</p>")
                stdout, stderr, returncode = self.run_rpcclient_command("srvinfo")
                
                if returncode == 0 and stdout.strip():
                    self.results['server_info'] = stdout.strip()
                    self.signals.output.emit("<p style='color: #00FF41;'>[+] Server information:</p>")
                    for line in stdout.strip().split('\n')[:5]:  # Show first 5 lines
                        if line.strip():
                            self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {line.strip()}</p>")
            
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