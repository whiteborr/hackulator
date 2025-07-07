# app/tools/port_scanner.py
import socket
import threading
import concurrent.futures
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from app.core.logger import logger

class PortScannerSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)
    progress_start = pyqtSignal(int)

class PortScanWorker(QRunnable):
    """Port scanning worker for TCP connect scans"""
    
    def __init__(self, target, ports, scan_type="tcp", timeout=3):
        super().__init__()
        self.signals = PortScannerSignals()
        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self.timeout = timeout
        self.is_running = True
        self.results = {}
        
    def scan_port(self, port):
        """Scan a single port"""
        if not self.is_running:
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                # Try to get service name
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return port, service
        except Exception:
            pass
        return None
    
    def run(self):
        try:
            self.signals.status.emit(f"Starting port scan on {self.target}...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Scanning {len(self.ports)} ports on {self.target}...</p><br>")
            self.signals.progress_start.emit(len(self.ports))
            
            open_ports = []
            completed = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_port = {executor.submit(self.scan_port, port): port for port in self.ports}
                
                for future in concurrent.futures.as_completed(future_to_port):
                    if not self.is_running:
                        break
                        
                    result = future.result()
                    completed += 1
                    
                    if result:
                        port, service = result
                        open_ports.append((port, service))
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>[+] Port {port}/tcp open - {service}</p><br>"
                        )
                    
                    if completed % 10 == 0:
                        self.signals.progress_update.emit(completed, len(open_ports))
            
            # Store results
            if open_ports:
                self.results[self.target] = {
                    'open_ports': [{'port': port, 'service': service, 'banner': ''} for port, service in open_ports]
                }
                self.signals.results_ready.emit(self.results)
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>Found {len(open_ports)} open ports</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No open ports found</p>")
            
            self.signals.status.emit("Port scan completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Port scan failed: {str(e)}</p>")
            self.signals.status.emit("Port scan error")
        finally:
            self.signals.finished.emit()

class NetworkSweepWorker(QRunnable):
    """Network sweep worker for host discovery"""
    
    def __init__(self, network_range, timeout=1):
        super().__init__()
        self.signals = PortScannerSignals()
        self.network_range = network_range
        self.timeout = timeout
        self.is_running = True
        
    def ping_host(self, ip):
        """Check if host is alive using TCP connect to port 80"""
        if not self.is_running:
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, 80))
            sock.close()
            
            if result == 0:
                return ip
        except Exception:
            pass
        return None
    
    def run(self):
        try:
            import ipaddress
            
            # Parse network range
            if '/' in self.network_range:
                network = ipaddress.ip_network(self.network_range, strict=False)
                ips = [str(ip) for ip in network.hosts()]
            elif '-' in self.network_range:
                # Handle range like 192.168.1.1-254
                parts = self.network_range.split('-')
                base_ip = parts[0].strip()
                end_octet = int(parts[1].strip())
                base_parts = base_ip.split('.')
                start_octet = int(base_parts[3])
                base_network = '.'.join(base_parts[:3])
                ips = [f"{base_network}.{i}" for i in range(start_octet, end_octet + 1)]
            else:
                ips = [self.network_range]
            
            self.signals.status.emit(f"Starting network sweep on {len(ips)} hosts...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Sweeping {len(ips)} hosts...</p><br>")
            self.signals.progress_start.emit(len(ips))
            
            alive_hosts = []
            completed = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                future_to_ip = {executor.submit(self.ping_host, ip): ip for ip in ips}
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    if not self.is_running:
                        break
                        
                    result = future.result()
                    completed += 1
                    
                    if result:
                        alive_hosts.append(result)
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>[+] Host {result} is alive</p>"
                        )
                    
                    if completed % 20 == 0:
                        self.signals.progress_update.emit(completed, len(alive_hosts))
            
            # Store results
            if alive_hosts:
                results = {}
                for host in alive_hosts:
                    results[host] = {'status': 'alive'}
                self.signals.results_ready.emit(results)
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>Found {len(alive_hosts)} alive hosts</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No alive hosts found</p>")
            
            self.signals.status.emit("Network sweep completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Network sweep failed: {str(e)}</p>")
            self.signals.status.emit("Network sweep error")
        finally:
            self.signals.finished.emit()

class IPRangePortScanWorker(QRunnable):
    """Port scanning worker for IP ranges"""
    
    def __init__(self, ips, ports, timeout=3):
        super().__init__()
        self.signals = PortScannerSignals()
        self.ips = ips
        self.ports = ports
        self.timeout = timeout
        self.is_running = True
        self.results = {}
        
    def scan_port(self, ip, port):
        """Scan a single port on a single IP"""
        if not self.is_running:
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return ip, port, service
        except Exception:
            pass
        return None
    
    def run(self):
        try:
            total_scans = len(self.ips) * len(self.ports)
            self.signals.status.emit(f"Starting port scan on {len(self.ips)} IPs, {len(self.ports)} ports each...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Scanning {len(self.ports)} ports on {len(self.ips)} IPs...</p><br>")
            self.signals.progress_start.emit(total_scans)
            
            completed = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                # Create all scan tasks
                futures = []
                for ip in self.ips:
                    for port in self.ports:
                        future = executor.submit(self.scan_port, ip, port)
                        futures.append(future)
                
                # Process results
                for future in concurrent.futures.as_completed(futures):
                    if not self.is_running:
                        break
                        
                    result = future.result()
                    completed += 1
                    
                    if result:
                        ip, port, service = result
                        if ip not in self.results:
                            self.results[ip] = {'open_ports': []}
                        self.results[ip]['open_ports'].append({'port': port, 'service': service, 'banner': ''})
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>[+] {ip}:{port}/tcp open - {service}</p><br>"
                        )
                    
                    if completed % 20 == 0:
                        open_count = sum(len(data['open_ports']) for data in self.results.values())
                        self.signals.progress_update.emit(completed, open_count)
            
            # Emit final results
            if self.results:
                self.signals.results_ready.emit(self.results)
                total_open = sum(len(data['open_ports']) for data in self.results.values())
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>Found {total_open} open ports across {len(self.results)} hosts</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No open ports found</p>")
            
            self.signals.status.emit("IP range port scan completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] IP range port scan failed: {str(e)}</p>")
            self.signals.status.emit("IP range port scan error")
        finally:
            self.signals.finished.emit()

class NmapScanWorker(QRunnable):
    """Nmap-based scanning worker"""
    
    def __init__(self, target, ports, scan_type, os_detection=False, service_detection=False):
        super().__init__()
        self.signals = PortScannerSignals()
        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self.os_detection = os_detection
        self.service_detection = service_detection
        self.is_running = True
        
    def build_nmap_command(self):
        """Build nmap command based on scan type"""
        port_range = ','.join(map(str, self.ports))
        
        if "🟩 1. Network Sweep" in self.scan_type:
            return f"nmap -sn -PE -PA80,443 -PS22,80,443,3389 {self.target}"
        elif "🟨 2. SYN Stealth" in self.scan_type:
            command = f"nmap -sS -T4 -p {port_range} -v {self.target}"
        elif "🟦 3. Service Detection" in self.scan_type:
            command = f"nmap -sS -sV -p {port_range} {self.target}"
        elif "🟥 4. OS Detection" in self.scan_type:
            command = f"nmap -O --osscan-guess --traceroute -p {port_range} {self.target}"
        elif "🟪 5. TCP Connect" in self.scan_type:
            command = f"nmap -sT -p {port_range} {self.target}"
        elif "🟫 6. UDP Scan" in self.scan_type:
            command = f"nmap -sU --top-ports 100 {self.target}"
        elif "🟨 7. Aggressive" in self.scan_type:
            command = f"nmap -A -T4 -p {port_range} {self.target}"
        elif "🔥 8. Full Scan" in self.scan_type:
            # Full scan workflow handled separately
            command = f"nmap -sT -p {port_range} {self.target}"
        else:
            command = f"nmap -sT -p {port_range} {self.target}"
        
        # Add detection flags based on checkboxes
        if self.os_detection and "OS Detection" not in self.scan_type:
            command += " -O --osscan-guess"
        if self.service_detection and "Service Detection" not in self.scan_type:
            command += " -sV"
        
        return command
    
    def run(self):
        try:
            import subprocess
            
            command = self.build_nmap_command()
            self.signals.status.emit(f"Running {self.scan_type} scan...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Executing: {command}</p><br>")
            self.signals.progress_start.emit(1)
            
            # Run nmap command
            process = subprocess.Popen(
                command.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                universal_newlines=True
            )
            
            # Read output line by line
            while True:
                if not self.is_running:
                    process.terminate()
                    break
                    
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self.signals.output.emit(f"<p style='color: #DCDCDC;'>{output.strip()}</p>")
            
            # Get final output
            stdout, stderr = process.communicate()
            
            if stderr:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>Warnings: {stderr}</p>")
            
            # Parse results (basic parsing)
            results = self.parse_nmap_output(stdout)
            if results:
                self.signals.results_ready.emit(results)
            
            self.signals.progress_update.emit(1, len(results) if results else 0)
            self.signals.status.emit(f"{self.scan_type} scan completed")
            
        except FileNotFoundError:
            self.signals.output.emit("<p style='color: #FF4500;'>[ERROR] nmap not found. Please install nmap.</p>")
            self.signals.status.emit("nmap not available")
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Nmap scan failed: {str(e)}</p>")
            self.signals.status.emit("Nmap scan error")
        finally:
            self.signals.finished.emit()
    
    def parse_nmap_output(self, output):
        """Basic nmap output parsing"""
        results = {}
        current_host = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Extract host
            if 'Nmap scan report for' in line:
                current_host = line.split('for ')[-1].split(' ')[0]
                results[current_host] = {'open_ports': []}
            
            # Extract open ports
            elif '/tcp' in line or '/udp' in line:
                if 'open' in line and current_host:
                    parts = line.split()
                    if len(parts) >= 2:
                        port_proto = parts[0]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        port = port_proto.split('/')[0]
                        results[current_host]['open_ports'].append({
                            'port': int(port),
                            'service': service,
                            'banner': ''
                        })
        
        return results if any(data['open_ports'] for data in results.values()) else None

def get_common_ports():
    """Get list of common ports to scan"""
    return [20, 21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 111, 135, 137, 138, 139, 143, 161, 443, 445, 993, 995, 1433, 1521, 1723, 1900, 3306, 3389, 3544, 5355, 5432, 5900, 5984, 6379, 7474, 8000, 8080, 8086, 8888, 9042, 9200, 11211, 27017]

def get_top_ports(count=100):
    """Get top N ports"""
    top_1000 = [1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100]
    return top_1000[:count]