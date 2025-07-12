# app/tools/http_scanner.py
import requests
import subprocess
import socket
import ssl
from urllib.parse import urljoin, urlparse
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

class HTTPSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)
    progress_start = pyqtSignal(int)

class HTTPEnumWorker(QRunnable):
    """HTTP/S enumeration and fingerprinting worker"""
    
    def __init__(self, target, scan_type="basic", wordlist_path=None, extensions=None, dns_server=None):
        super().__init__()
        self.signals = HTTPSignals()
        self.target = target
        self.scan_type = scan_type
        self.wordlist_path = wordlist_path
        self.extensions = extensions or ['.php', '.html', '.asp', '.aspx', '.jsp']
        self.dns_server = dns_server
        self.is_running = True
        self.results = {}
        self.session = requests.Session()
        self.session.timeout = 10
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        
        # Setup custom DNS resolution using global settings
        from app.core.dns_settings import dns_settings
        self.dns_server = dns_settings.get_current_dns()
        if self.dns_server and self.dns_server != "Default DNS":
            self.setup_custom_dns()
    
    def setup_custom_dns(self):
        """Setup custom DNS resolution"""
        import socket
        
        # Store original getaddrinfo
        self.original_getaddrinfo = socket.getaddrinfo
        
        def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            """Custom DNS resolution using specified DNS server"""
            try:
                if self.dns_server == "LocalDNS":
                    # Query LocalDNS server directly
                    ip = self.query_local_dns(host)
                    if ip:
                        return [(family, type, proto, '', (ip, port))]
                    return self.original_getaddrinfo(host, port, family, type, proto, flags)
                else:
                    return self.original_getaddrinfo(host, port, family, type, proto, flags)
            except:
                return self.original_getaddrinfo(host, port, family, type, proto, flags)
        
        # Monkey patch socket.getaddrinfo
        socket.getaddrinfo = custom_getaddrinfo
    
    def query_local_dns(self, hostname):
        """Query LocalDNS server for hostname resolution"""
        try:
            from app.core.local_dns_server import local_dns_server
            
            # Check if LocalDNS server is running and has the record
            if local_dns_server.running:
                records = local_dns_server.get_records()
                domain_records = records.get(hostname.lower(), {})
                if 'A' in domain_records and domain_records['A']:
                    return domain_records['A'][0]
            
            return None
            
        except Exception:
            return None
        
    def restore_dns(self):
        """Restore original DNS resolution"""
        if hasattr(self, 'original_getaddrinfo'):
            import socket
            socket.getaddrinfo = self.original_getaddrinfo
        
    def normalize_url(self, url):
        """Ensure URL has proper scheme and resolve hostname"""
        if not url.startswith(('http://', 'https://')):
            # Resolve hostname first if using LocalDNS
            resolved_target = self.resolve_hostname(url)
            
            # Try HTTPS first, fallback to HTTP
            try:
                test_url = f"https://{resolved_target}"
                response = self.session.head(test_url, timeout=5, verify=False)
                return test_url
            except:
                return f"http://{resolved_target}"
        else:
            # Extract hostname from URL and resolve if needed
            from urllib.parse import urlparse
            parsed = urlparse(url)
            resolved_hostname = self.resolve_hostname(parsed.hostname)
            if resolved_hostname != parsed.hostname:
                return url.replace(parsed.hostname, resolved_hostname)
        return url
    
    def resolve_hostname(self, hostname):
        """Resolve hostname using global DNS settings"""
        import re
        
        # If already an IP address, return as-is
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, hostname):
            return hostname
        
        # Try LocalDNS resolution
        if self.dns_server == "LocalDNS":
            resolved_ip = self.query_local_dns(hostname)
            if resolved_ip:
                return resolved_ip
        
        # Return original hostname if no resolution
        return hostname
    
    def run_command(self, cmd, timeout=60):
        """Execute command and return output"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=True)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
        except Exception as e:
            return "", str(e), 1
    
    def fingerprint_server(self, url):
        """Fingerprint web server and gather basic information"""
        info = {}
        
        try:
            response = self.session.get(url, verify=False)
            info['status_code'] = response.status_code
            info['headers'] = dict(response.headers)
            info['content_length'] = len(response.content)
            
            # Server identification
            server = response.headers.get('Server', 'Unknown')
            info['server'] = server
            
            # Technology detection
            tech_indicators = {
                'PHP': ['X-Powered-By: PHP', 'Set-Cookie: PHPSESSID'],
                'ASP.NET': ['X-AspNet-Version', 'X-Powered-By: ASP.NET'],
                'Apache': ['Server: Apache'],
                'Nginx': ['Server: nginx'],
                'IIS': ['Server: Microsoft-IIS'],
                'WordPress': ['X-Pingback', '/wp-content/', '/wp-includes/'],
                'Drupal': ['/sites/default/', 'X-Drupal-Cache'],
                'Joomla': ['/components/', '/modules/']
            }
            
            detected_tech = []
            response_text = response.text.lower()
            headers_text = str(response.headers).lower()
            
            for tech, indicators in tech_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in headers_text or indicator.lower() in response_text:
                        detected_tech.append(tech)
                        break
            
            info['technologies'] = detected_tech
            
            # Security headers
            security_headers = {
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy')
            }
            info['security_headers'] = {k: v for k, v in security_headers.items() if v}
            
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def check_ssl_info(self, hostname, port=443):
        """Get SSL/TLS certificate information"""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info['subject'] = dict(x[0] for x in cert['subject'])
                    ssl_info['issuer'] = dict(x[0] for x in cert['issuer'])
                    ssl_info['version'] = cert['version']
                    ssl_info['serial_number'] = cert['serialNumber']
                    ssl_info['not_before'] = cert['notBefore']
                    ssl_info['not_after'] = cert['notAfter']
                    ssl_info['cipher'] = ssock.cipher()
                    
        except Exception as e:
            ssl_info['error'] = str(e)
        
        return ssl_info
    
    def directory_enumeration(self, base_url):
        """Enumerate directories using wordlist"""
        found_dirs = []
        
        # Default directories if no wordlist
        default_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
            'backup', 'backups', 'config', 'includes', 'uploads', 'images',
            'css', 'js', 'api', 'test', 'dev', 'staging', 'beta'
        ]
        
        wordlist = default_dirs
        if self.wordlist_path:
            try:
                with open(self.wordlist_path, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except:
                pass
        
        self.signals.progress_start.emit(len(wordlist))
        
        for i, directory in enumerate(wordlist):
            if not self.is_running:
                break
                
            for ext in [''] + self.extensions:
                if not self.is_running:
                    break
                    
                test_path = directory + ext
                test_url = urljoin(base_url, test_path)
                
                try:
                    response = self.session.head(test_url, verify=False)
                    if response.status_code in [200, 301, 302, 403]:
                        found_dirs.append({
                            'path': test_path,
                            'status': response.status_code,
                            'size': response.headers.get('Content-Length', 'Unknown')
                        })
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>[{response.status_code}] {test_path}</p>"
                        )
                except:
                    pass
            
            if i % 10 == 0:
                self.signals.progress_update.emit(i, len(found_dirs))
        
        return found_dirs
    
    def run_nikto_scan(self, url):
        """Run nikto vulnerability scanner"""
        cmd = f"nikto -h {url} -Format txt"
        stdout, stderr, returncode = self.run_command(cmd)
        
        if returncode == 0:
            return stdout
        return None
    
    def run_nmap_http_scripts(self, target):
        """Run nmap HTTP enumeration scripts"""
        scripts = ['http-enum', 'http-headers', 'http-methods', 'http-title']
        results = {}
        
        for script in scripts:
            if not self.is_running:
                break
                
            cmd = f"nmap -p80,443 --script {script} {target}"
            stdout, stderr, returncode = self.run_command(cmd)
            
            if returncode == 0:
                results[script] = stdout
        
        return results
    
    def run(self):
        try:
            self.signals.status.emit(f"Starting HTTP enumeration on {self.target}...")
            
            # Normalize URL
            url = self.normalize_url(self.target)
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Analyzing {url}...</p><br>")
            
            # Basic fingerprinting
            self.signals.output.emit("<p style='color: #00BFFF;'>Fingerprinting web server...</p>")
            server_info = self.fingerprint_server(url)
            
            if 'error' not in server_info:
                self.results['server_info'] = server_info
                self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Server: {server_info.get('server', 'Unknown')}</p>")
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ Status: {server_info.get('status_code')}</p>")
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ Content Length: {server_info.get('content_length')} bytes</p>")
                
                if server_info.get('technologies'):
                    tech_list = ', '.join(server_info['technologies'])
                    self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ Technologies: {tech_list}</p>")
                
                if server_info.get('security_headers'):
                    self.signals.output.emit("<p style='color: #00FF41;'>[+] Security Headers:</p>")
                    for header, value in server_info['security_headers'].items():
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {header}: {value[:50]}...</p>")
            else:
                self.signals.output.emit(f"<p style='color: #FF4500;'>[!] Connection failed: {server_info['error']}</p>")
            
            # SSL/TLS analysis for HTTPS
            if url.startswith('https://') and self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Analyzing SSL/TLS certificate...</p>")
                ssl_info = self.check_ssl_info(hostname)
                
                if 'error' not in ssl_info:
                    self.results['ssl_info'] = ssl_info
                    self.signals.output.emit("<p style='color: #00FF41;'>[+] SSL Certificate Info:</p>")
                    if 'subject' in ssl_info:
                        cn = ssl_info['subject'].get('commonName', 'Unknown')
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ Common Name: {cn}</p>")
                    if 'issuer' in ssl_info:
                        issuer = ssl_info['issuer'].get('organizationName', 'Unknown')
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ Issuer: {issuer}</p>")
                    if 'cipher' in ssl_info:
                        cipher = ssl_info['cipher'][0] if ssl_info['cipher'] else 'Unknown'
                        self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ Cipher: {cipher}</p>")
            
            # Directory enumeration
            if self.scan_type in ["directories", "full"] and self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Enumerating directories...</p>")
                found_dirs = self.directory_enumeration(url)
                
                if found_dirs:
                    self.results['directories'] = found_dirs
                    self.signals.output.emit(f"<br><p style='color: #00FF41;'>Found {len(found_dirs)} directories/files</p>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No directories found</p>")
            
            # Nmap HTTP scripts
            if self.scan_type in ["nmap", "full"] and self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Running nmap HTTP scripts...</p>")
                nmap_results = self.run_nmap_http_scripts(hostname)
                
                if nmap_results:
                    self.results['nmap_scripts'] = nmap_results
                    for script, output in nmap_results.items():
                        if "Host script results:" in output or "PORT" in output:
                            self.signals.output.emit(f"<p style='color: #00FF41;'>[+] {script} results found</p>")
            
            # Nikto scan
            if self.scan_type in ["nikto", "full"] and self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Running Nikto scan...</p>")
                nikto_output = self.run_nikto_scan(url)
                
                if nikto_output:
                    self.results['nikto'] = nikto_output
                    self.signals.output.emit("<p style='color: #00FF41;'>[+] Nikto scan completed</p>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] Nikto scan failed or not available</p>")
            
            # Store results
            if self.results:
                final_results = {self.target: self.results}
                self.signals.results_ready.emit(final_results)
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>HTTP enumeration completed</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No HTTP information could be retrieved</p>")
            
            self.signals.status.emit("HTTP enumeration completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] HTTP enumeration failed: {str(e)}</p>")
            self.signals.status.emit("HTTP enumeration error")
        finally:
            # Restore original DNS resolution
            self.restore_dns()
            self.signals.finished.emit()