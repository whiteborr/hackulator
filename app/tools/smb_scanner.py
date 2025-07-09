# app/tools/smb_scanner.py
import subprocess
import re
import socket
import sys
import os
import time
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

# SMB protocol imports
try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect
    from smbprotocol.open import Open
    from smbprotocol.exceptions import SMBResponseException
    import smbprotocol.file_info as file_info
    SMBPROTOCOL_AVAILABLE = True
except ImportError:
    SMBPROTOCOL_AVAILABLE = False

# SMB enumeration using Windows native tools
NATIVE_SMB_AVAILABLE = True  # Always available on Windows

# Common shares to test for native enumeration
COMMON_SHARES = ["C$", "ADMIN$", "IPC$", "Users", "Shared", "Public", "Docs", "SYSVOL", "NETLOGON"]

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
    
    def enum_shares_native(self):
        """Enumerate shares using Windows PowerShell and net commands"""
        shares_found = []
        error_msg = None
        
        try:
            # Use PowerShell Get-SmbShare if available, fallback to net view
            if self.username and self.password:
                # Try PowerShell first for better credential handling
                ps_cmd = f'powershell -Command "$cred = New-Object System.Management.Automation.PSCredential(\"{self.username}\", (ConvertTo-SecureString \"{self.password}\" -AsPlainText -Force)); Get-SmbShare -CimSession (New-CimSession -ComputerName {self.target} -Credential $cred) | Select-Object Name,ShareType,Description | Format-Table -AutoSize"'
                stdout, stderr, returncode = self.run_command(ps_cmd, timeout=15)
                
                if returncode == 0 and 'Name' in stdout:
                    # Parse PowerShell output
                    lines = stdout.split('\n')
                    header_found = False
                    for line in lines:
                        line = line.strip()
                        if 'Name' in line and 'ShareType' in line:
                            header_found = True
                            continue
                        elif header_found and line and not line.startswith('-'):
                            parts = line.split()
                            if len(parts) >= 2:
                                share_name = parts[0]
                                share_type = parts[1] if len(parts) > 1 else 'Unknown'
                                comment = ' '.join(parts[2:]) if len(parts) > 2 else ''
                                shares_found.append({
                                    'name': share_name,
                                    'type': share_type,
                                    'comment': comment
                                })
                elif returncode != 0:
                    error_msg = f"PowerShell failed (code {returncode}): {stderr}"
                
                # If PowerShell failed, try net use + net view
                if not shares_found:
                    # Try multiple username formats
                    username_formats = []
                    if '\\' in self.username or '@' in self.username:
                        username_formats.append(self.username)
                    else:
                        username_formats.extend([
                            self.username,
                            f".\\{self.username}",
                            f"{self.target}\\{self.username}"
                        ])
                    
                    # Try each format until one works
                    auth_success = False
                    for username_formatted in username_formats:
                        net_use_cmd = f'net use \\\\{self.target}\\IPC$ /user:"{username_formatted}" "{self.password}"'
                        stdout, stderr, returncode = self.run_command(net_use_cmd)
                        
                        if returncode == 0:
                            auth_success = True
                            break
                        else:
                            cleanup_cmd = f'net use \\\\{self.target}\\IPC$ /delete /yes 2>nul'
                            self.run_command(cleanup_cmd)
                    
                    if auth_success:
                        # Enumerate shares
                        net_view_cmd = f'net view \\\\{self.target}'
                        stdout, stderr, returncode = self.run_command(net_view_cmd)
                        
                        if returncode == 0:
                            shares_found = self._parse_net_view_output(stdout)
                            if not shares_found:
                                error_msg = f"net view succeeded but no shares parsed from output: {stdout[:200]}"
                        else:
                            error_msg = f"net view failed (code {returncode}): {stderr}"
                    else:
                        error_msg = f"Authentication failed (code {returncode}): {stderr}"
                    
                    # Clean up
                    cleanup_cmd = f'net use \\\\{self.target}\\IPC$ /delete /yes'
                    self.run_command(cleanup_cmd)
            else:
                # Anonymous enumeration
                net_view_cmd = f'net view \\\\{self.target}'
                stdout, stderr, returncode = self.run_command(net_view_cmd)
                
                if returncode == 0:
                    shares_found = self._parse_net_view_output(stdout)
                    if not shares_found:
                        error_msg = f"Anonymous net view succeeded but no shares parsed from output: {stdout[:200]}"
                else:
                    # Try null session enumeration
                    self.signals.output.emit("<p style='color: #87CEEB;'>[*] Trying null session enumeration...</p><br>")
                    null_shares = self._try_null_session_enum()
                    if null_shares:
                        shares_found.extend(null_shares)
                        self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(null_shares)} shares via null session</p>")
                    else:
                        # Try nmap SMB scripts for anonymous enumeration
                        self.signals.output.emit("<p style='color: #87CEEB;'>[*] Trying nmap anonymous enumeration...</p><br>")
                        nmap_shares = self._try_nmap_anonymous_enum()
                        if nmap_shares:
                            shares_found.extend(nmap_shares)
                            self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(nmap_shares)} shares via nmap</p>")
                        else:
                            error_msg = f"All anonymous methods failed. Last error: {stderr}"
                
        except Exception as e:
            error_msg = str(e)
        
        return shares_found, f"Found {len(shares_found)} shares", error_msg
    
    def _try_null_session_enum(self):
        """Try null session enumeration"""
        shares = []
        try:
            # Establish null session
            null_cmd = f'net use \\\\{self.target}\\IPC$ "" /user:""'
            stdout, stderr, returncode = self.run_command(null_cmd)
            
            if returncode == 0:
                # Try to enumerate shares with null session
                view_cmd = f'net view \\\\{self.target}'
                stdout, stderr, returncode = self.run_command(view_cmd)
                
                if returncode == 0:
                    shares = self._parse_net_view_output(stdout)
                
                # Clean up
                cleanup_cmd = f'net use \\\\{self.target}\\IPC$ /delete /yes'
                self.run_command(cleanup_cmd)
        except Exception:
            pass
        
        return shares
    
    def _parse_net_view_output(self, output):
        """Parse net view command output"""
        shares = []
        lines = output.split('\n')
        in_shares_section = False
        
        for i, line in enumerate(lines):
            original_line = line
            line = line.strip()
            
            if 'Share name' in line and 'Type' in line:
                in_shares_section = True
                continue
            elif in_shares_section and line.startswith('-'):
                continue
            elif in_shares_section and line:
                # Check if this is a share line (not empty, not command completion)
                if (not line.startswith('The command') and 
                    not line.startswith('\\\\') and 
                    line.strip() and
                    not 'completed successfully' in line.lower()):
                    
                    # Split the line and check if it looks like a share entry
                    parts = line.split()
                    if len(parts) >= 2 and not parts[0].startswith('-'):
                        share_name = parts[0]
                        share_type = parts[1]
                        
                        # Get comment - everything after the second column
                        if len(parts) > 2:
                            # Skip the "Used as" column if present, get the actual comment
                            comment_parts = parts[2:]
                            # If first comment part looks like a placeholder, skip it
                            if comment_parts and (comment_parts[0] == '' or len(comment_parts[0]) < 2):
                                comment = ' '.join(comment_parts[1:]) if len(comment_parts) > 1 else ''
                            else:
                                comment = ' '.join(comment_parts)
                        else:
                            comment = ''
                        
                        shares.append({
                            'name': share_name,
                            'type': share_type,
                            'comment': comment
                        })
                elif not line or 'The command completed' in line:
                    break
        
        return shares
    
    def _try_nmap_anonymous_enum(self):
        """Try nmap SMB enumeration scripts for anonymous access"""
        shares = []
        try:
            nmap_path = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'nmap', 'nmap.exe')
            nmap_path = os.path.abspath(nmap_path)
            
            if os.path.exists(nmap_path):
                # Use nmap SMB enumeration scripts
                nmap_cmd = f'"{nmap_path}" -Pn -p139,445 --script smb-enum-shares.nse --script-args smbuser=guest,smbpass= {self.target}'
                stdout, stderr, returncode = self.run_command(nmap_cmd, timeout=30)
                
                if returncode == 0 and 'shares:' in stdout.lower():
                    # Parse nmap output for shares
                    lines = stdout.split('\n')
                    for line in lines:
                        if '|' in line and ('$' in line or 'SYSVOL' in line or 'NETLOGON' in line):
                            # Extract share name from nmap output
                            share_line = line.strip().replace('|', '').strip()
                            if share_line:
                                parts = share_line.split()
                                if len(parts) >= 1:
                                    share_name = parts[0]
                                    shares.append({
                                        'name': share_name,
                                        'type': 'Disk',
                                        'comment': 'Found via nmap'
                                    })
        except Exception:
            pass
        
        return shares
    
    def detect_smb_version(self):
        """Detect SMB version using nmap"""
        nmap_path = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'nmap', 'nmap.exe')
        nmap_path = os.path.abspath(nmap_path)
        
        if not os.path.exists(nmap_path):
            return "Unknown"
        
        cmd = f'"{nmap_path}" -Pn -p445 --script smb-protocols {self.target}'
        stdout, stderr, returncode = self.run_command(cmd, timeout=30)
        
        if returncode == 0 and stdout:
            if 'SMB 3.1.1' in stdout:
                return "SMB 3.1.1"
            elif 'SMB 3.0' in stdout:
                return "SMB 3.0"
            elif 'SMB 2.1' in stdout:
                return "SMB 2.1"
            elif 'SMB 2.0' in stdout:
                return "SMB 2.0"
            elif 'SMB 1.0' in stdout:
                return "SMB 1.0"
        
        return "Unknown"
    
    def enum_shares_smbclient(self):
        """Enumerate shares using smbclient"""
        self.signals.output.emit("<p style='color: #87CEEB;'>[*] Trying smbclient -L enumeration...</p><br>")
        
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
    
    def enum_shares_wordlist(self):
        """Enumerate shares using wordlist"""
        shares = []
        wordlist_path = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'wordlists', 'shares-top100.txt')
        
        if not os.path.exists(wordlist_path):
            return shares
        
        try:
            with open(wordlist_path, 'r') as f:
                share_names = [line.strip() for line in f if line.strip()]
            
            self.signals.output.emit(f"<p style='color: #87CEEB;'>[*] Testing {len(share_names)} share names from wordlist...</p><br>")
            
            for share_name in share_names:
                if not self.is_running:
                    break
                
                if self.username and self.password:
                    test_cmd = f'net use \\\\{self.target}\\{share_name} /user:"{self.username}" "{self.password}"'
                else:
                    test_cmd = f'net use \\\\{self.target}\\{share_name} "" /user:""'
                
                stdout, stderr, returncode = self.run_command(test_cmd, timeout=3)
                
                if returncode == 0:
                    shares.append({
                        'name': share_name,
                        'type': 'Disk',
                        'comment': 'Found via wordlist'
                    })
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Share {share_name} is accessible</p>")
                    
                    # Clean up connection
                    cleanup_cmd = f'net use \\\\{self.target}\\{share_name} /delete /yes'
                    self.run_command(cleanup_cmd)
        
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>[*] Wordlist enumeration failed: {str(e)}</p>")
        
        return shares
    
    def enum_shares_smbprotocol(self):
        """Enumerate SMB shares using smbprotocol (SMB2/3)"""
        if not SMBPROTOCOL_AVAILABLE:
            return [], "", "smbprotocol not available"
        
        shares = []
        try:
            conn = Connection(uuid="c1", server=self.target, port=445)
            conn.connect()

            # Parse domain from username if possible
            if '\\' in self.username:
                domain, user = self.username.split('\\', 1)
            else:
                domain = "WORKGROUP"
                user = self.username

            session = Session(connection=conn, username=user, password=self.password, domain=domain)
            session.connect()

            # Connect to IPC$ share to enumerate shares
            tree = TreeConnect(session, r"\\\\" + self.target + r"\\IPC$")
            tree.connect()
            
            # Use NetShareEnum equivalent through SMB2
            # This is a simplified approach - in practice you'd need to implement
            # the full NetShareEnum RPC call through the IPC$ share
            
            # For now, just return that the connection was successful
            # A full implementation would require additional RPC handling
            shares.append({
                'name': 'IPC$',
                'type': 'IPC',
                'comment': 'SMB2/3 connection successful'
            })
            
            tree.disconnect()
            session.disconnect()
            conn.disconnect()

            return shares, "smbprotocol connection successful", None

        except SMBResponseException as e:
            return [], "", f"smbprotocol failed: {str(e)}"
        except Exception as e:
            return [], "", f"smbprotocol error: {str(e)}"
    
    def enum_with_nmap(self):
        """Enumerate using nmap SMB scripts"""
        # Get nmap path from resources directory
        nmap_path = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'nmap', 'nmap.exe')
        nmap_path = os.path.abspath(nmap_path)
    
        if not os.path.exists(nmap_path):
            return {}

        # Detect SMB version first
        smb_version = self.detect_smb_version()
        if smb_version != "Unknown":
            self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Detected {smb_version}</p><br>")
        
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

            if self.username and self.password:
                # Split domain if present in username
                if '\\' in self.username:
                    smbdomain, smbuser = self.username.split('\\', 1)
                elif '@' in self.username:
                    smbuser, smbdomain = self.username.split('@', 1)
                else:
                    smbuser = self.username
                    smbdomain = 'WORKGROUP'  # Default fallback domain

                # Construct the command with domain
                cmd = (
                    f'"{nmap_path}" -Pn -n --disable-arp-ping -p139,445 --open '
                    f'--script {script} '
                    f'--script-trace '
                    f'--script-args unsafe=1, smbuser="{smbuser}",smbpass="{self.password}",smbdomain="{smbdomain}" '
                    f'{self.target}'
                )
            else:
                # Anonymous
                cmd = f'"{nmap_path}" -Pn -n --disable-arp-ping -p139,445 --open --script-trace --script {script} {self.target}'

            # Debug output removed

            stdout, stderr, returncode = self.run_command(cmd, timeout=60)

            if returncode == 0:
                results[script] = stdout if stdout.strip() else f"Script completed but returned no output"
            else:
                results[script] = f"Script failed (code {returncode}): {stderr}"

        return results
    
    def enum_netbios_native(self):
        """Enumerate NetBIOS using Windows nbtstat command"""
        try:
            # Use nbtstat for NetBIOS enumeration
            nbtstat_cmd = f'nbtstat -A {self.target}'
            stdout, stderr, returncode = self.run_command(nbtstat_cmd, timeout=10)
            
            if returncode == 0 and 'NetBIOS Remote Machine Name Table' in stdout:
                return stdout
            else:
                # Fallback to simple port check
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.target, 139))
                sock.close()
                
                if result == 0:
                    return f"NetBIOS Port 139: Open\nTarget: {self.target}\nBasic connectivity confirmed"
                else:
                    return f"NetBIOS Port 139: Closed or filtered"
                
        except Exception as e:
            return f"NetBIOS Error: {str(e)}"
    
    def enum_with_nbtscan(self):
        """Enumerate using nbtscan (fallback method)"""
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
            
            # NetBIOS scan (only for Basic Info and Vulnerability Scan)
            if self.is_running and self.scan_type in ["basic", "vulns"]:
                self.signals.output.emit("<p style='color: #00BFFF;'>Running NetBIOS scan...</p><br>")
                if NATIVE_SMB_AVAILABLE:

                    nbt_result = self.enum_netbios_native()
                    if not nbt_result or "Error:" in nbt_result:
                        self.signals.output.emit("<p style='color: #FFAA00;'>[*] Native failed, trying nbtscan</p>")
                        nbt_result = self.enum_with_nbtscan()
                else:
                    nbt_result = self.enum_with_nbtscan()
                if nbt_result:
                    self.results['netbios'] = nbt_result
                    self.signals.output.emit("<p style='color: #00FF41;'>[+] NetBIOS information:</p><br>")
                    # Parse and display NetBIOS names if available
                    if 'NetBIOS Remote Machine Name Table' in nbt_result:
                        lines = nbt_result.split('\n')
                        for line in lines:
                            if '<' in line and '>' in line and 'UNIQUE' in line:
                                # Extract NetBIOS name entries
                                parts = line.strip().split()
                                if len(parts) >= 2:
                                    name = parts[0]
                                    name_type = parts[1] if len(parts) > 1 else ''
                                    self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {name} {name_type}</p><br>")
                    else:
                        # Display first few lines for other output
                        for line in nbt_result.split('\n')[:5]:
                            if line.strip():
                                self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {line.strip()}</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] NetBIOS scan failed</p><br>")
            
            # Share enumeration (all scan types)
            if self.is_running:
                if self.scan_type == "basic":
                    self.signals.output.emit("<br><p style='color: #00BFFF;'>Basic SMB information...</p><br>")
                elif self.scan_type == "shares":
                    self.signals.output.emit("<br><p style='color: #00BFFF;'>Enumerating SMB shares...</p><br>")
                elif self.scan_type == "vulns":
                    self.signals.output.emit("<br><p style='color: #00BFFF;'>SMB vulnerability assessment...</p><br>")
                start_time = time.time()
                
                # Try Windows net view first

                shares, stdout, stderr = self.enum_shares_native()
                
                # If Windows method fails, show detailed error and try smbclient as fallback
                if not shares:
                    if stderr:
                        self.signals.output.emit(f"<p style='color: #FFAA00;'>[*] Windows method failed: {stderr}</p>")
                    else:
                        self.signals.output.emit("<p style='color: #FFAA00;'>[*] Windows method failed with no error message</p>")
                    
                    self.signals.output.emit("<p style='color: #FFAA00;'>[*] Trying smbclient fallback</p>")
                    try:
                        fallback_shares, fallback_stdout, fallback_stderr = self.enum_shares_smbclient()
                        if fallback_shares:
                            shares = fallback_shares
                            stdout = fallback_stdout
                            stderr = fallback_stderr
                        else:
                            if fallback_stderr:
                                self.signals.output.emit(f"<p style='color: #FFAA00;'>[*] smbclient failed: {fallback_stderr}</p>")
                            else:
                                self.signals.output.emit("<p style='color: #FFAA00;'>[*] smbclient also failed or not available</p>")
                    except Exception as e:
                        self.signals.output.emit(f"<p style='color: #FFAA00;'>[*] Fallback failed: {str(e)}</p>")
                
                # Try smbprotocol fallback if still no shares
                if not shares and self.username and self.password:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[*] Trying smbprotocol fallback</p><br>")
                    try:
                        smbprotocol_shares, _, smbproto_err = self.enum_shares_smbprotocol()
                        if smbprotocol_shares:
                            shares = smbprotocol_shares
                        else:
                            self.signals.output.emit(f"<p style='color: #FFAA00;'>[*] smbprotocol failed: {smbproto_err}</p>")
                    except Exception as e:
                        self.signals.output.emit(f"<p style='color: #FFAA00;'>[*] smbprotocol fallback failed: {str(e)}</p>")
                
                # Try wordlist enumeration if still no shares
                if not shares:
                    wordlist_shares = self.enum_shares_wordlist()
                    if wordlist_shares:
                        shares.extend(wordlist_shares)
                
                elapsed = time.time() - start_time

                
                if shares:
                    self.results['shares'] = shares
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(shares)} shares:</p><br>")
                    for share in shares:
                        share_name = share.get('name', 'Unknown')
                        share_type = share.get('type', 'Unknown')
                        share_comment = share.get('comment', '')
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {share_name} ({share_type}) - {share_comment}</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No shares found or access denied</p>")
                    if stderr:
                        self.signals.output.emit(f"<p style='color: #FFAA00;'>&nbsp;&nbsp;&nbsp;Error: {stderr}</p>")
                    
                    # Try manual share testing for common shares
                    self.signals.output.emit("<p style='color: #87CEEB;'>[*] Testing common shares...</p><br>")
                    common_shares = ['C$', 'ADMIN$', 'IPC$', 'SYSVOL', 'NETLOGON']
                    for share in common_shares:
                        test_cmd = f'net use \\\\{self.target}\\{share} /user:"{self.username}" "{self.password}"' if self.username else f'dir \\\\{self.target}\\{share}'
                        test_stdout, test_stderr, test_returncode = self.run_command(test_cmd, timeout=5)
                        if test_returncode == 0:
                            self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Share {share} is accessible</p>")
                            shares.append({'name': share, 'type': 'Disk', 'comment': 'Manually verified'})
                            if self.username:
                                cleanup_cmd = f'net use \\\\{self.target}\\{share} /delete /yes'
                                self.run_command(cleanup_cmd)
                        else:
                            self.signals.output.emit(f"<p style='color: #FFAA00;'>[-] Share {share}: {test_stderr.strip() if test_stderr else 'Access denied'}</p>")
            
            # Nmap enumeration (based on scan type)
            if self.is_running:
                if self.scan_type == "basic":
                    self.signals.output.emit("<br><p style='color: #00BFFF;'>Running basic SMB detection...</p><br>")
                elif self.scan_type == "vulns":
                    self.signals.output.emit("<br><p style='color: #00BFFF;'>Running SMB vulnerability scans...</p><br>")
                else:
                    self.signals.output.emit("<br><p style='color: #00BFFF;'>Running SMB enumeration scripts...</p><br>")
                
                nmap_results = self.enum_with_nmap()
                
                if nmap_results:
                    self.results['nmap_scripts'] = nmap_results
                    for script, output in nmap_results.items():
                        self.signals.output.emit(f"<p style='color: #00FF41;'>[+] {script} results:</p><br>")
                        # Show all nmap output
                        lines = output.split('\n')
                        meaningful_lines = 0
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('Starting Nmap') and not line.startswith('Nmap done'):
                                meaningful_lines += 1
                                # Highlight vulnerabilities
                                if 'VULNERABLE' in line or 'CVE' in line or 'LIKELY VULNERABLE' in line:
                                    self.signals.output.emit(f"<p style='color: #FF4500;'>&nbsp;&nbsp;&nbsp;{line}</p><br>")
                                elif '|' in line:
                                    clean_line = line.replace('|', '').strip()
                                    if clean_line:
                                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;{clean_line}</p><br>")
                                elif 'PORT' in line or 'Host script results' in line or line.startswith('445/'):
                                    self.signals.output.emit(f"<p style='color: #87CEEB;'>&nbsp;&nbsp;&nbsp;{line}</p><br>")
                                elif line and len(line) > 5:  # Show other meaningful lines
                                    self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;{line}</p><br>")
                        
                        # If no meaningful output, show a message
                        if meaningful_lines == 0:
                            self.signals.output.emit(f"<p style='color: #FFAA00;'>&nbsp;&nbsp;&nbsp;No results returned by {script}</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] Nmap SMB scripts failed or nmap not available</p>")
                    # Try basic SMB port connectivity as fallback for basic scan
                    if self.scan_type == "basic":
                        try:
                            import socket
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(5)
                            result445 = sock.connect_ex((self.target, 445))
                            sock.close()
                            
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(5)
                            result139 = sock.connect_ex((self.target, 139))
                            sock.close()
                            
                            if result445 == 0:
                                self.signals.output.emit("<p style='color: #00FF41;'>[+] SMB port 445/tcp is open</p>")
                            if result139 == 0:
                                self.signals.output.emit("<p style='color: #00FF41;'>[+] NetBIOS port 139/tcp is open</p>")
                                
                        except Exception:
                            pass
            
            # Store results
            if self.results:
                final_results = {self.target: self.results}
                self.signals.results_ready.emit(final_results)
                if self.scan_type == "basic":
                    self.signals.output.emit(f"<br><p style='color: #00FF41;'>Basic SMB scan completed</p>")
                elif self.scan_type == "shares":
                    self.signals.output.emit(f"<br><p style='color: #00FF41;'>SMB share enumeration completed</p>")
                elif self.scan_type == "vulns":
                    self.signals.output.emit(f"<br><p style='color: #00FF41;'>SMB vulnerability scan completed</p>")
                else:
                    self.signals.output.emit(f"<br><p style='color: #00FF41;'>SMB enumeration completed</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No SMB information could be retrieved</p>")
            
            self.signals.status.emit("SMB enumeration completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] SMB enumeration failed: {str(e)}</p>")
            self.signals.status.emit("SMB enumeration error")
        finally:
            self.signals.finished.emit()