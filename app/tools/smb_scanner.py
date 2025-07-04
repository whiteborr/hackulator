# app/tools/smb_scanner.py
import subprocess
import re
import socket
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

class SMBSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)

class SMBEnumWorker(QRunnable):
    """SMB enumeration worker using multiple tools"""
    
    def __init__(self, target, username="", password="", scan_type="basic"):
        super().__init__()
        self.signals = SMBSignals()
        self.target = target
        self.username = username
        self.password = password
        self.scan_type = scan_type
        self.is_running = True
        self.results = {}
        
    def run_command(self, cmd, timeout=30):
        """Execute command and return output"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=True)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
        except Exception as e:
            return "", str(e), 1
    
    def check_smb_ports(self):
        """Check if SMB ports are open"""
        ports = [139, 445]
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.target, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            except Exception:
                pass
        
        return open_ports
    
    def enum_shares_smbclient(self):
        """Enumerate shares using smbclient"""
        if self.username:
            cmd = f"smbclient -L \\\\\\\\{self.target} -U {self.username}%{self.password}"
        else:
            cmd = f"smbclient -L \\\\\\\\{self.target} -N"
        
        stdout, stderr, returncode = self.run_command(cmd)
        
        shares = []
        if returncode == 0:
            in_shares_section = False
            for line in stdout.split('\n'):
                line = line.strip()
                if 'Sharename' in line and 'Type' in line:
                    in_shares_section = True
                    continue
                elif in_shares_section and line.startswith('\\\\'):
                    break
                elif in_shares_section and line and not line.startswith('-'):
                    parts = line.split()
                    if len(parts) >= 2:
                        share_name = parts[0]
                        share_type = parts[1]
                        comment = ' '.join(parts[2:]) if len(parts) > 2 else ""
                        shares.append({
                            'name': share_name,
                            'type': share_type,
                            'comment': comment
                        })
        
        return shares, stdout, stderr
    
    def enum_with_nmap(self):
        """Enumerate using nmap SMB scripts"""
        scripts = []
        
        if self.scan_type == "basic":
            scripts = ["smb-os-discovery", "smb2-security-mode"]
        elif self.scan_type == "shares":
            scripts = ["smb-enum-shares", "smb-enum-users"]
        elif self.scan_type == "vulns":
            scripts = ["smb-vuln-ms17-010", "smb-vuln-ms08-067"]
        
        results = {}
        for script in scripts:
            if not self.is_running:
                break
                
            cmd = f"nmap -p139,445 --script {script} {self.target}"
            stdout, stderr, returncode = self.run_command(cmd)
            
            if returncode == 0:
                results[script] = stdout
        
        return results
    
    def enum_with_nbtscan(self):
        """Enumerate using nbtscan"""
        cmd = f"nbtscan {self.target}"
        stdout, stderr, returncode = self.run_command(cmd)
        
        if returncode == 0:
            return stdout
        return None
    
    def run(self):
        try:
            self.signals.status.emit(f"Starting SMB enumeration on {self.target}...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Scanning SMB services on {self.target}...</p><br>")
            
            # Check SMB ports
            open_ports = self.check_smb_ports()
            if not open_ports:
                self.signals.output.emit("<p style='color: #FF4500;'>[!] No SMB ports (139, 445) are open</p>")
                self.signals.status.emit("No SMB ports open")
                return
            
            self.signals.output.emit(f"<p style='color: #00FF41;'>[+] SMB ports open: {', '.join(map(str, open_ports))}</p><br>")
            self.results['open_ports'] = open_ports
            
            # NetBIOS scan
            if self.is_running:
                self.signals.output.emit("<p style='color: #00BFFF;'>Running NetBIOS scan...</p>")
                nbt_result = self.enum_with_nbtscan()
                if nbt_result:
                    self.results['netbios'] = nbt_result
                    self.signals.output.emit("<p style='color: #00FF41;'>[+] NetBIOS information:</p>")
                    for line in nbt_result.split('\n')[:5]:
                        if line.strip():
                            self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {line.strip()}</p>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] NetBIOS scan failed or nbtscan not available</p>")
            
            # Share enumeration
            if self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Enumerating SMB shares...</p>")
                shares, stdout, stderr = self.enum_shares_smbclient()
                
                if shares:
                    self.results['shares'] = shares
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(shares)} shares:</p>")
                    for share in shares:
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {share['name']} ({share['type']}) - {share['comment']}</p>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No shares found or access denied</p>")
                    if stderr:
                        self.signals.output.emit(f"<p style='color: #FFAA00;'>&nbsp;&nbsp;&nbsp;Error: {stderr[:100]}...</p>")
            
            # Nmap enumeration
            if self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Running nmap SMB scripts...</p>")
                nmap_results = self.enum_with_nmap()
                
                if nmap_results:
                    self.results['nmap_scripts'] = nmap_results
                    for script, output in nmap_results.items():
                        if "Host script results:" in output:
                            self.signals.output.emit(f"<p style='color: #00FF41;'>[+] {script} results:</p>")
                            # Extract relevant lines
                            lines = output.split('\n')
                            for line in lines:
                                if '|' in line and ('SMB' in line or 'NetBIOS' in line or 'OS' in line):
                                    clean_line = line.strip().replace('|', '').strip()
                                    if clean_line:
                                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {clean_line}</p>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] Nmap SMB scripts failed or nmap not available</p>")
            
            # Store results
            if self.results:
                final_results = {self.target: self.results}
                self.signals.results_ready.emit(final_results)
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>SMB enumeration completed</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No SMB information could be retrieved</p>")
            
            self.signals.status.emit("SMB enumeration completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] SMB enumeration failed: {str(e)}</p>")
            self.signals.status.emit("SMB enumeration error")
        finally:
            self.signals.finished.emit()