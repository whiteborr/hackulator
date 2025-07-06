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
                            f"<p style='color: #00FF41;'>[+] Port {port}/tcp open - {service}</p>"
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

def get_common_ports():
    """Get list of common ports to scan"""
    return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]

def get_top_ports(count=100):
    """Get top N ports"""
    top_1000 = [1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100]
    return top_1000[:count]