# app/tools/snmp_scanner.py
import subprocess
import socket
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

class SNMPSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)
    progress_start = pyqtSignal(int)

class SNMPEnumWorker(QRunnable):
    """SNMP enumeration worker using multiple tools"""
    
    def __init__(self, target, communities=None, scan_type="basic", version="2c"):
        super().__init__()
        self.signals = SNMPSignals()
        self.target = target
        self.communities = communities or ["public", "private", "community"]
        self.scan_type = scan_type
        self.version = version
        self.is_running = True
        self.results = {}
        
        # Common SNMP OIDs
        self.oids = {
            'system_info': '1.3.6.1.2.1.1',
            'users': '1.3.6.1.4.1.77.1.2.25',
            'processes': '1.3.6.1.2.1.25.4.2.1.2',
            'software': '1.3.6.1.2.1.25.6.3.1.2',
            'tcp_ports': '1.3.6.1.2.1.6.13.1.3',
            'interfaces': '1.3.6.1.2.1.2.2.1.2',
            'routing_table': '1.3.6.1.2.1.4.21.1.1'
        }
    
    def run_command(self, cmd, timeout=30):
        """Execute command and return output"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=True)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
        except Exception as e:
            return "", str(e), 1
    
    def check_snmp_port(self):
        """Check if SNMP port 161 is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            # Send a simple SNMP request
            sock.sendto(b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00', (self.target, 161))
            data, addr = sock.recvfrom(1024)
            sock.close()
            return True
        except Exception:
            return False
    
    def test_community_strings(self):
        """Test community strings using onesixtyone or snmpwalk"""
        valid_communities = []
        
        for community in self.communities:
            if not self.is_running:
                break
                
            # Try with snmpwalk first
            cmd = f"snmpwalk -v{self.version} -c {community} -t 3 {self.target} 1.3.6.1.2.1.1.1.0"
            stdout, stderr, returncode = self.run_command(cmd)
            
            if returncode == 0 and stdout.strip():
                valid_communities.append(community)
                self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Valid community string: {community}</p>")
            else:
                # Try with onesixtyone as fallback
                cmd = f"onesixtyone {self.target} {community}"
                stdout, stderr, returncode = self.run_command(cmd)
                
                if returncode == 0 and self.target in stdout:
                    valid_communities.append(community)
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Valid community string: {community}</p>")
        
        return valid_communities
    
    def snmp_walk(self, community, oid="", description=""):
        """Perform SNMP walk on specific OID"""
        if not oid:
            cmd = f"snmpwalk -v{self.version} -c {community} -t 5 {self.target}"
        else:
            cmd = f"snmpwalk -v{self.version} -c {community} -t 5 {self.target} {oid}"
        
        stdout, stderr, returncode = self.run_command(cmd)
        
        if returncode == 0 and stdout.strip():
            return stdout.strip()
        return None
    
    def enumerate_system_info(self, community):
        """Get basic system information"""
        info = {}
        
        # System description
        result = self.snmp_walk(community, "1.3.6.1.2.1.1.1.0")
        if result:
            info['description'] = result
        
        # System uptime
        result = self.snmp_walk(community, "1.3.6.1.2.1.1.3.0")
        if result:
            info['uptime'] = result
        
        # System contact
        result = self.snmp_walk(community, "1.3.6.1.2.1.1.4.0")
        if result:
            info['contact'] = result
        
        # System name
        result = self.snmp_walk(community, "1.3.6.1.2.1.1.5.0")
        if result:
            info['name'] = result
        
        return info
    
    def enumerate_detailed_info(self, community):
        """Get detailed SNMP information"""
        detailed_info = {}
        
        if self.scan_type == "users":
            result = self.snmp_walk(community, self.oids['users'])
            if result:
                detailed_info['users'] = result
        
        elif self.scan_type == "processes":
            result = self.snmp_walk(community, self.oids['processes'])
            if result:
                detailed_info['processes'] = result
        
        elif self.scan_type == "software":
            result = self.snmp_walk(community, self.oids['software'])
            if result:
                detailed_info['software'] = result
        
        elif self.scan_type == "network":
            # TCP ports
            result = self.snmp_walk(community, self.oids['tcp_ports'])
            if result:
                detailed_info['tcp_ports'] = result
            
            # Interfaces
            result = self.snmp_walk(community, self.oids['interfaces'])
            if result:
                detailed_info['interfaces'] = result
        
        elif self.scan_type == "full":
            # Get everything
            for key, oid in self.oids.items():
                if not self.is_running:
                    break
                result = self.snmp_walk(community, oid)
                if result:
                    detailed_info[key] = result
        
        return detailed_info
    
    def run(self):
        try:
            self.signals.status.emit(f"Starting SNMP enumeration on {self.target}...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Testing SNMP service on {self.target}:161...</p><br>")
            
            # Check SNMP port
            if not self.check_snmp_port():
                self.signals.output.emit("<p style='color: #FF4500;'>[!] SNMP port 161 appears to be closed or filtered</p>")
                # Continue anyway as UDP scanning can be unreliable
            else:
                self.signals.output.emit("<p style='color: #00FF41;'>[+] SNMP port 161 is accessible</p><br>")
            
            # Test community strings
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Testing {len(self.communities)} community strings...</p>")
            self.signals.progress_start.emit(len(self.communities))
            
            valid_communities = self.test_community_strings()
            
            if not valid_communities:
                self.signals.output.emit("<p style='color: #FFAA00;'>[!] No valid community strings found</p>")
                self.signals.status.emit("No valid SNMP communities")
                return
            
            self.signals.output.emit(f"<br><p style='color: #00FF41;'>Found {len(valid_communities)} valid community strings</p><br>")
            self.results['valid_communities'] = valid_communities
            
            # Enumerate with first valid community
            community = valid_communities[0]
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Enumerating with community '{community}'...</p>")
            
            # Get system information
            system_info = self.enumerate_system_info(community)
            if system_info:
                self.results['system_info'] = system_info
                self.signals.output.emit("<p style='color: #00FF41;'>[+] System Information:</p>")
                for key, value in system_info.items():
                    clean_value = value.split('=')[-1].strip() if '=' in value else value
                    self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {key.title()}: {clean_value[:100]}...</p>")
            
            # Get detailed information based on scan type
            if self.scan_type != "basic":
                detailed_info = self.enumerate_detailed_info(community)
                if detailed_info:
                    self.results['detailed_info'] = detailed_info
                    self.signals.output.emit(f"<br><p style='color: #00FF41;'>[+] {self.scan_type.title()} Information:</p>")
                    
                    for key, value in detailed_info.items():
                        lines = value.split('\n')[:5]  # Show first 5 lines
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {key.title()} ({len(value.split())} entries):</p>")
                        for line in lines:
                            if line.strip():
                                clean_line = line.split('=')[-1].strip() if '=' in line else line
                                self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;• {clean_line[:80]}...</p>")
            
            # Store results
            if self.results:
                final_results = {self.target: self.results}
                self.signals.results_ready.emit(final_results)
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>SNMP enumeration completed</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No SNMP information could be retrieved</p>")
            
            self.signals.status.emit("SNMP enumeration completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] SNMP enumeration failed: {str(e)}</p>")
            self.signals.status.emit("SNMP enumeration error")
        finally:
            self.signals.finished.emit()