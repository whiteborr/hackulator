# app/tools/rpc_scanner.py
import os
import socket
import subprocess
import re
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

class RPCSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)

class RPCEnumWorker(QRunnable):
    """RPC enumeration worker using native socket connections"""
    
    def __init__(self, target, username="", password="", ntlm_hash=""):
        super().__init__()
        self.signals = RPCSignals()
        self.target = target
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
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
            if self.username and (self.password or self.ntlm_hash):
                # Use credentials with net use first, then net view
                if self.ntlm_hash:
                    # For NTLM hash, try using runas /netonly or alternative method
                    # Note: Windows net commands don't directly support hash auth
                    # This would typically require tools like pth-winexe or similar
                    pass
                else:
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
            if self.username and (self.password or self.ntlm_hash):
                if self.ntlm_hash:
                    # NTLM hash auth not directly supported by systeminfo
                    # Would require tools like pth-winexe or wmiexec
                    info['system_info'] = "NTLM hash auth - use specialized tools"
                else:
                    result = subprocess.run(["systeminfo", "/s", self.target, "/u", self.username, "/p", self.password], 
                                          capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')[:10]
                        info['system_info'] = '\n'.join([line.strip() for line in lines if line.strip()])
            else:
                result = subprocess.run(["systeminfo", "/s", self.target], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')[:10]
                    info['system_info'] = '\n'.join([line.strip() for line in lines if line.strip()])
        except Exception:
            info['system_info'] = "System information not accessible"
        return info
    
    def enumerate_rpc_interfaces(self):
        """Enumerate RPC interfaces using rpcdump if available"""
        interfaces = []
        try:
            # Try internal rpcdump.py first
            rpcdump_path = os.path.join(os.path.dirname(__file__), "rpcdump.py")
            if os.path.exists(rpcdump_path):
                cmd = ["python", rpcdump_path, self.target]
                if self.username and self.password:
                    cmd.extend(["-username", self.username, "-password", self.password])
                elif self.username and self.ntlm_hash:
                    cmd.extend(["-username", self.username, "-hashes", f":{self.ntlm_hash}"])
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                if result.returncode == 0:
                    # Parse rpcdump output for interface UUIDs
                    for line in result.stdout.split('\n'):
                        if 'uuid' in line.lower() and '-' in line:
                            parts = line.strip().split()
                            if len(parts) >= 2:
                                interfaces.append(line.strip())
                            if len(interfaces) >= 10:
                                break
            
            # Fallback: Use rpcinfo or basic RPC detection
            if not interfaces:
                interfaces = self._fallback_rpc_detection()
                
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Try fallback method
            interfaces = self._fallback_rpc_detection()
        except Exception:
            interfaces = self._fallback_rpc_detection()
        return interfaces
    
    def _fallback_rpc_detection(self):
        """Fallback RPC interface detection using basic methods"""
        interfaces = []
        try:
            # Common RPC interfaces based on open ports
            if self.test_rpc_port(135):
                interfaces.append("RPC Endpoint Mapper (port 135) - Active")
            if self.test_rpc_port(445):
                interfaces.append("SMB/CIFS (port 445) - spoolss, samr, lsarpc interfaces likely")
            if self.test_rpc_port(139):
                interfaces.append("NetBIOS Session (port 139) - Legacy RPC interfaces")
            
            # Try basic RPC service detection via net commands
            try:
                result = subprocess.run(["sc", "query", "type=", "service", "state=", "all"], 
                                      capture_output=True, text=True, timeout=10)
                if "Spooler" in result.stdout:
                    interfaces.append("Print Spooler Service - spoolss interface available")
                if "RemoteRegistry" in result.stdout:
                    interfaces.append("Remote Registry Service - winreg interface available")
            except:
                pass
                
        except Exception:
            pass
        return interfaces[:5]  # Limit to 5 fallback interfaces
    
    def enumerate_samr_users(self):
        """Enumerate users via SAMR interface"""
        users = []
        try:
            # Try smbclient or rpcclient for SAMR enumeration
            if self.username and (self.password or self.ntlm_hash):
                if self.ntlm_hash:
                    cmd = ["rpcclient", "-U", f"{self.username}%{self.ntlm_hash}", "--pw-nt-hash", self.target]
                else:
                    cmd = ["rpcclient", "-U", f"{self.username}%{self.password}", self.target]
                
                # Execute enumdomusers command
                process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate(input="enumdomusers\nquit\n", timeout=15)
                
                if process.returncode == 0:
                    for line in stdout.split('\n'):
                        if 'user:' in line and 'rid:' in line:
                            # Parse user entries like: user:[Administrator] rid:[0x1f4]
                            user_match = re.search(r'user:\[([^\]]+)\]', line)
                            if user_match:
                                users.append(user_match.group(1))
                            if len(users) >= 20:  # Limit results
                                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception:
            pass
        return users
    
    def enumerate_samr_groups(self):
        """Enumerate groups via SAMR interface"""
        groups = []
        try:
            if self.username and (self.password or self.ntlm_hash):
                if self.ntlm_hash:
                    cmd = ["rpcclient", "-U", f"{self.username}%{self.ntlm_hash}", "--pw-nt-hash", self.target]
                else:
                    cmd = ["rpcclient", "-U", f"{self.username}%{self.password}", self.target]
                
                process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate(input="enumdomgroups\nquit\n", timeout=15)
                
                if process.returncode == 0:
                    for line in stdout.split('\n'):
                        if 'group:' in line and 'rid:' in line:
                            group_match = re.search(r'group:\[([^\]]+)\]', line)
                            if group_match:
                                groups.append(group_match.group(1))
                            if len(groups) >= 15:  # Limit results
                                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception:
            pass
        return groups
    
    def enumerate_lsarpc_info(self):
        """Enumerate LSA information via LSARPC interface"""
        lsa_info = {}
        try:
            if self.username and (self.password or self.ntlm_hash):
                if self.ntlm_hash:
                    cmd = ["rpcclient", "-U", f"{self.username}%{self.ntlm_hash}", "--pw-nt-hash", self.target]
                else:
                    cmd = ["rpcclient", "-U", f"{self.username}%{self.password}", self.target]
                
                # Get domain SID and policy info
                process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                commands = "lsaquery\nlsaenumsid\nquit\n"
                stdout, stderr = process.communicate(input=commands, timeout=15)
                
                if process.returncode == 0:
                    lines = stdout.split('\n')
                    domain_sid = None
                    trust_domains = []
                    
                    for line in lines:
                        # Extract domain SID
                        if 'Domain Sid:' in line:
                            domain_sid = line.split('Domain Sid:')[1].strip()
                        # Extract trust relationships
                        elif 'Domain Name:' in line and 'SID:' in line:
                            trust_match = re.search(r'Domain Name: ([^\s]+).*SID: (S-[0-9-]+)', line)
                            if trust_match:
                                trust_domains.append({
                                    'name': trust_match.group(1),
                                    'sid': trust_match.group(2)
                                })
                    
                    if domain_sid:
                        lsa_info['domain_sid'] = domain_sid
                    if trust_domains:
                        lsa_info['trust_domains'] = trust_domains[:5]  # Limit to 5
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception:
            pass
        return lsa_info
    
    def probe_rpc_vulnerabilities(self):
        """Probe for known RPC-based vulnerabilities"""
        vulnerabilities = []
        try:
            # Check for PrintNightmare (spoolss)
            if self.test_rpc_port(445):  # SMB required for spoolss
                try:
                    # Test if spoolss is accessible
                    result = subprocess.run(["rpcclient", "-U", "%", "-c", "enumprinters", self.target], 
                                          capture_output=True, text=True, timeout=10)
                    if "NT_STATUS_OK" in result.stdout or "result was" in result.stdout:
                        vulnerabilities.append({
                            'name': 'PrintNightmare (CVE-2021-1675)',
                            'interface': 'spoolss',
                            'severity': 'High',
                            'description': 'Print Spooler service may be vulnerable to privilege escalation'
                        })
                except:
                    pass
            
            # Check for PetitPotam (efsr/lsarpc)
            if self.test_rpc_port(445):
                try:
                    result = subprocess.run(["rpcclient", "-U", "%", "-c", "lsaquery", self.target], 
                                          capture_output=True, text=True, timeout=10)
                    if "NT_STATUS_OK" in result.stdout:
                        vulnerabilities.append({
                            'name': 'PetitPotam (CVE-2021-36942)',
                            'interface': 'efsr/lsarpc',
                            'severity': 'Medium',
                            'description': 'LSA service may be vulnerable to NTLM relay attacks'
                        })
                except:
                    pass
            
            # Check for service control vulnerabilities
            if self.username and (self.password or self.ntlm_hash):
                try:
                    if self.ntlm_hash:
                        cmd = ["rpcclient", "-U", f"{self.username}%{self.ntlm_hash}", "--pw-nt-hash", self.target]
                    else:
                        cmd = ["rpcclient", "-U", f"{self.username}%{self.password}", self.target]
                    
                    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
                                             stderr=subprocess.PIPE, text=True)
                    stdout, stderr = process.communicate(input="svcctl\nquit\n", timeout=10)
                    
                    if "NT_STATUS_OK" in stdout or "opened" in stdout.lower():
                        vulnerabilities.append({
                            'name': 'Service Control Abuse',
                            'interface': 'svcctl',
                            'severity': 'Medium',
                            'description': 'Service control interface accessible - potential for service manipulation'
                        })
                except:
                    pass
        except Exception:
            pass
        return vulnerabilities
    
    def enumerate_rid_cycling(self):
        """Enumerate users via RID cycling"""
        rid_users = []
        try:
            if self.username and (self.password or self.ntlm_hash):
                if self.ntlm_hash:
                    cmd = ["rpcclient", "-U", f"{self.username}%{self.ntlm_hash}", "--pw-nt-hash", self.target]
                else:
                    cmd = ["rpcclient", "-U", f"{self.username}%{self.password}", self.target]
                
                # Common RIDs to check
                common_rids = [500, 501, 502, 512, 513, 514, 515, 516, 517, 518, 519, 520, 
                              1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009]
                
                for rid in common_rids:
                    try:
                        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
                                                 stderr=subprocess.PIPE, text=True)
                        command = f"lookupsids S-1-5-21-*-{rid}\nquit\n"
                        stdout, stderr = process.communicate(input=command, timeout=5)
                        
                        if process.returncode == 0 and "S-1-5-21" in stdout:
                            # Parse the output for username
                            for line in stdout.split('\n'):
                                if f"-{rid}" in line and "(" in line:
                                    user_match = re.search(r'\\([^\\\(]+)\s*\(', line)
                                    if user_match:
                                        username = user_match.group(1)
                                        privilege_level = "High" if rid in [500, 512, 516, 518, 519] else "Standard"
                                        rid_users.append({
                                            'username': username,
                                            'rid': rid,
                                            'privilege': privilege_level
                                        })
                                        break
                    except subprocess.TimeoutExpired:
                        continue
                    except Exception:
                        continue
                    
                    if len(rid_users) >= 15:  # Limit results
                        break
        except Exception:
            pass
        return rid_users
    
    def enumerate_wkssvc_info(self):
        """Enumerate workstation information via WKSSVC interface"""
        wks_info = {}
        try:
            if self.username and (self.password or self.ntlm_hash):
                if self.ntlm_hash:
                    cmd = ["rpcclient", "-U", f"{self.username}%{self.ntlm_hash}", "--pw-nt-hash", self.target]
                else:
                    cmd = ["rpcclient", "-U", f"{self.username}%{self.password}", self.target]
                
                # Get workstation info
                process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
                                         stderr=subprocess.PIPE, text=True)
                commands = "wkssvc_info\nquit\n"
                stdout, stderr = process.communicate(input=commands, timeout=10)
                
                if process.returncode == 0:
                    # Parse workstation information
                    for line in stdout.split('\n'):
                        if 'Computer Name:' in line:
                            wks_info['computer_name'] = line.split('Computer Name:')[1].strip()
                        elif 'Domain Name:' in line:
                            wks_info['domain_name'] = line.split('Domain Name:')[1].strip()
                        elif 'OS Version:' in line:
                            wks_info['os_version'] = line.split('OS Version:')[1].strip()
                        elif 'Logged Users:' in line:
                            wks_info['logged_users'] = line.split('Logged Users:')[1].strip()
                
                # Alternative: Try net session enumeration
                if not wks_info:
                    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
                                             stderr=subprocess.PIPE, text=True)
                    commands = "netshareenum\nquit\n"
                    stdout, stderr = process.communicate(input=commands, timeout=10)
                    
                    if "NT_STATUS_OK" in stdout:
                        wks_info['workstation_accessible'] = True
                        # Extract basic info from share enumeration
                        share_count = stdout.count('netname:')
                        if share_count > 0:
                            wks_info['share_count'] = share_count
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception:
            pass
        return wks_info
    
    def extract_secrets(self, confirm_privileged=False):
        """Extract secrets and hashes (privileged operation)"""
        secrets = {}
        if not confirm_privileged:
            return secrets
            
        try:
            if self.username and (self.password or self.ntlm_hash):
                # Try secretsdump.py (Impacket)
                if self.ntlm_hash:
                    cmd = ["secretsdump.py", "-hashes", f":{self.ntlm_hash}", f"{self.username}@{self.target}"]
                else:
                    cmd = ["secretsdump.py", f"{self.username}:{self.password}@{self.target}"]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    # Parse secretsdump output
                    lines = result.stdout.split('\n')
                    sam_hashes = []
                    lsa_secrets = []
                    
                    for line in lines:
                        if ':::' in line and len(line.split(':')) >= 4:
                            # SAM hash format: username:rid:lm:nt:::
                            sam_hashes.append(line.strip())
                        elif 'dpapi_machinekey' in line.lower() or 'dpapi_userkey' in line.lower():
                            lsa_secrets.append(line.strip())
                        
                        if len(sam_hashes) >= 10:  # Limit results
                            break
                    
                    if sam_hashes:
                        secrets['sam_hashes'] = sam_hashes
                    if lsa_secrets:
                        secrets['lsa_secrets'] = lsa_secrets[:5]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception:
            pass
        return secrets
    
    def detect_rpc_relay_potential(self):
        """Detect RPC interfaces susceptible to NTLM relay attacks"""
        relay_info = {}
        try:
            # Check for NTLM-authenticating RPC interfaces
            relay_vulnerable = []
            
            # Test common relay-vulnerable interfaces
            if self.test_rpc_port(445):  # SMB required
                try:
                    # Test anonymous access to various RPC interfaces
                    result = subprocess.run(["rpcclient", "-U", "%", "-c", "enumprinters", self.target], 
                                          capture_output=True, text=True, timeout=8)
                    if "NT_STATUS_ACCESS_DENIED" in result.stderr:
                        relay_vulnerable.append({
                            'interface': 'spoolss',
                            'description': 'Print Spooler - potential for PrinterBug/SpoolSample relay',
                            'risk': 'High'
                        })
                except:
                    pass
                
                try:
                    result = subprocess.run(["rpcclient", "-U", "%", "-c", "lsaquery", self.target], 
                                          capture_output=True, text=True, timeout=8)
                    if "NT_STATUS_ACCESS_DENIED" in result.stderr:
                        relay_vulnerable.append({
                            'interface': 'lsarpc',
                            'description': 'LSA RPC - potential for PetitPotam relay',
                            'risk': 'Medium'
                        })
                except:
                    pass
            
            # Check for SMB signing status
            try:
                result = subprocess.run(["smbclient", "-L", self.target, "-U", "%"], 
                                      capture_output=True, text=True, timeout=10)
                if "NT_STATUS_OK" in result.stdout or "Sharename" in result.stdout:
                    # SMB accessible - check if signing is enforced
                    if "signing required" not in result.stderr.lower():
                        relay_info['smb_signing'] = 'Not enforced - relay possible'
                    else:
                        relay_info['smb_signing'] = 'Enforced - relay blocked'
            except:
                pass
            
            if relay_vulnerable:
                relay_info['vulnerable_interfaces'] = relay_vulnerable
                relay_info['relay_potential'] = 'High' if any(r['risk'] == 'High' for r in relay_vulnerable) else 'Medium'
        except Exception:
            pass
        return relay_info
    
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
            
            # Enumerate RPC interfaces
            if self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Enumerating RPC interfaces...</p><br>")
                interfaces = self.enumerate_rpc_interfaces()
                
                if interfaces:
                    self.results['rpc_interfaces'] = interfaces
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(interfaces)} RPC interfaces:</p><br>")
                    for interface in interfaces[:5]:  # Show top 5
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {interface}</p><br>")
                    if len(interfaces) > 5:
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;... and {len(interfaces) - 5} more</p>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No RPC interfaces enumerated (rpcdump not available)</p>")
            
            # Enumerate SAMR users and groups (if authenticated)
            if self.is_running and self.username and (self.password or self.ntlm_hash):
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Enumerating domain users...</p><br>")
                users = self.enumerate_samr_users()
                
                if users:
                    self.results['domain_users'] = users
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(users)} domain users:</p><br>")
                    for user in users[:10]:  # Show top 10
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {user}</p><br>")
                    if len(users) > 10:
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;... and {len(users) - 10} more</p>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No domain users enumerated</p>")
                
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Enumerating domain groups...</p><br>")
                groups = self.enumerate_samr_groups()
                
                if groups:
                    self.results['domain_groups'] = groups
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(groups)} domain groups:</p><br>")
                    for group in groups[:8]:  # Show top 8
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {group}</p><br>")
                    if len(groups) > 8:
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;... and {len(groups) - 8} more</p>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No domain groups enumerated</p>")
                
                # Enumerate LSA information
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Enumerating LSA policy information...</p><br>")
                lsa_info = self.enumerate_lsarpc_info()
                
                if lsa_info:
                    self.results['lsa_info'] = lsa_info
                    if 'domain_sid' in lsa_info:
                        self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Domain SID: {lsa_info['domain_sid']}</p><br>")
                    if 'trust_domains' in lsa_info:
                        self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(lsa_info['trust_domains'])} trust relationships:</p><br>")
                        for trust in lsa_info['trust_domains']:
                            self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {trust['name']} ({trust['sid']})</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No LSA information enumerated</p>")
            
            # Probe for RPC vulnerabilities
            if self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Probing for RPC vulnerabilities...</p><br>")
                vulnerabilities = self.probe_rpc_vulnerabilities()
                
                if vulnerabilities:
                    self.results['vulnerabilities'] = vulnerabilities
                    self.signals.output.emit(f"<p style='color: #FF4500;'>[!] Found {len(vulnerabilities)} potential vulnerabilities:</p><br>")
                    for vuln in vulnerabilities:
                        severity_color = '#FF4500' if vuln['severity'] == 'High' else '#FFAA00'
                        self.signals.output.emit(f"<p style='color: {severity_color};'>&nbsp;&nbsp;&nbsp;⚠ {vuln['name']} ({vuln['severity']})</p><br>")
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{vuln['description']}</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #00FF41;'>[+] No obvious RPC vulnerabilities detected</p>")
            
            # RID cycling enumeration
            if self.is_running and self.username and (self.password or self.ntlm_hash):
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Performing RID cycling enumeration...</p><br>")
                rid_users = self.enumerate_rid_cycling()
                
                if rid_users:
                    self.results['rid_users'] = rid_users
                    high_priv = [u for u in rid_users if u['privilege'] == 'High']
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(rid_users)} users via RID cycling:</p><br>")
                    
                    # Show high privilege users first
                    if high_priv:
                        self.signals.output.emit("<p style='color: #FF4500;'>&nbsp;&nbsp;&nbsp;High Privilege Users:</p><br>")
                        for user in high_priv[:5]:
                            self.signals.output.emit(f"<p style='color: #FF4500;'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ {user['username']} (RID: {user['rid']})</p><br>")
                    
                    # Show standard users
                    standard_users = [u for u in rid_users if u['privilege'] == 'Standard']
                    if standard_users:
                        self.signals.output.emit("<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;Standard Users:</p><br>")
                        for user in standard_users[:5]:
                            self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ {user['username']} (RID: {user['rid']})</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No users found via RID cycling</p>")
            
            # WKSSVC workstation information
            if self.is_running and self.username and (self.password or self.ntlm_hash):
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Enumerating workstation information...</p><br>")
                wks_info = self.enumerate_wkssvc_info()
                
                if wks_info:
                    self.results['workstation_info'] = wks_info
                    self.signals.output.emit("<p style='color: #00FF41;'>[+] Workstation information retrieved:</p><br>")
                    
                    if 'computer_name' in wks_info:
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ Computer: {wks_info['computer_name']}</p><br>")
                    if 'domain_name' in wks_info:
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ Domain: {wks_info['domain_name']}</p><br>")
                    if 'os_version' in wks_info:
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ OS: {wks_info['os_version']}</p><br>")
                    if 'logged_users' in wks_info:
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ Logged Users: {wks_info['logged_users']}</p><br>")
                    if 'share_count' in wks_info:
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ Shares: {wks_info['share_count']}</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No workstation information available</p>")
            
            # Privileged secrets extraction (if enabled)
            # Note: This would require user confirmation in a real implementation
            privileged_mode = False  # Set to True only with explicit user consent
            if self.is_running and privileged_mode and self.username and (self.password or self.ntlm_hash):
                self.signals.output.emit("<br><p style='color: #FF4500;'>Attempting privileged secrets extraction...</p><br>")
                secrets = self.extract_secrets(confirm_privileged=True)
                
                if secrets:
                    self.results['secrets'] = secrets
                    if 'sam_hashes' in secrets:
                        self.signals.output.emit(f"<p style='color: #FF4500;'>[!] Extracted {len(secrets['sam_hashes'])} SAM hashes</p><br>")
                        # Don't display actual hashes in UI for security
                        self.signals.output.emit("<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ Hashes stored in results (not displayed)</p><br>")
                    if 'lsa_secrets' in secrets:
                        self.signals.output.emit(f"<p style='color: #FF4500;'>[!] Extracted {len(secrets['lsa_secrets'])} LSA secrets</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No secrets extracted or insufficient privileges</p>")
            
            # RPC Relay & MITM detection
            if self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Detecting RPC relay potential...</p><br>")
                relay_info = self.detect_rpc_relay_potential()
                
                if relay_info:
                    self.results['relay_info'] = relay_info
                    
                    if 'smb_signing' in relay_info:
                        color = '#FF4500' if 'not enforced' in relay_info['smb_signing'].lower() else '#00FF41'
                        self.signals.output.emit(f"<p style='color: {color};'>[+] SMB Signing: {relay_info['smb_signing']}</p><br>")
                    
                    if 'vulnerable_interfaces' in relay_info:
                        self.signals.output.emit(f"<p style='color: #FF4500;'>[!] Found {len(relay_info['vulnerable_interfaces'])} relay-vulnerable interfaces:</p><br>")
                        for vuln in relay_info['vulnerable_interfaces']:
                            risk_color = '#FF4500' if vuln['risk'] == 'High' else '#FFAA00'
                            self.signals.output.emit(f"<p style='color: {risk_color};'>&nbsp;&nbsp;&nbsp;⚠ {vuln['interface']} ({vuln['risk']} Risk)</p><br>")
                            self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{vuln['description']}</p><br>")
                    
                    if 'relay_potential' in relay_info:
                        potential_color = '#FF4500' if relay_info['relay_potential'] == 'High' else '#FFAA00'
                        self.signals.output.emit(f"<p style='color: {potential_color};'>[!] Overall Relay Potential: {relay_info['relay_potential']}</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #00FF41;'>[+] No obvious relay vulnerabilities detected</p>")
            
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
            
            # Normalize and emit final structured result
            if self.results:
                structured = {
                    "host": self.target,
                    "os": self.results.get("system_info", "Not Available"),
                    "shares": self.results.get("services", []),
                    "ports": self.results.get("open_rpc_ports", []),
                    "rpc_interfaces": self.results.get("rpc_interfaces", []),
                    "domain_users": self.results.get("domain_users", []),
                    "domain_groups": self.results.get("domain_groups", []),
                    "lsa_info": self.results.get("lsa_info", {}),
                    "vulnerabilities": self.results.get("vulnerabilities", []),
                    "rid_users": self.results.get("rid_users", []),
                    "workstation_info": self.results.get("workstation_info", {}),
                    "secrets": self.results.get("secrets", {}),
                    "relay_info": self.results.get("relay_info", {})
                }
                self.signals.results_ready.emit(structured)
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>RPC enumeration completed</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No RPC information could be retrieved</p>")
            
            self.signals.status.emit("RPC enumeration completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] RPC enumeration failed: {str(e)}</p>")
            self.signals.status.emit("RPC enumeration error")
        finally:
            self.signals.finished.emit()