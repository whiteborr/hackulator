# app/tools/api_scanner.py
import requests
import json
import subprocess
from urllib.parse import urljoin
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

class APISignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)
    progress_start = pyqtSignal(int)

class APIEnumWorker(QRunnable):
    """API enumeration and testing worker"""
    import base64
    import codecs

    def __init__(self, target, scan_type="basic", wordlist_path=None, dns_server=None):
        super().__init__()
        self.signals = APISignals()
        self.target = target
        self.scan_type = scan_type
        self.wordlist_path = wordlist_path
        self.dns_server = dns_server
        self.is_running = True
        self.results = {}
        self.session = requests.Session()
        self.session.timeout = 10
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 API Scanner'})
        
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
            import socket as sock
            import struct
            
            # Create DNS query packet
            query_id = 0x1234
            flags = 0x0100  # Standard query
            questions = 1
            
            # Build DNS header
            header = struct.pack('!HHHHHH', query_id, flags, questions, 0, 0, 0)
            
            # Build question section
            question = b''
            for part in hostname.split('.'):
                question += bytes([len(part)]) + part.encode()
            question += b'\x00'  # End of domain
            question += struct.pack('!HH', 1, 1)  # Type A, Class IN
            
            query = header + question
            
            # Send query to LocalDNS server
            dns_socket = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
            dns_socket.settimeout(5)
            dns_socket.sendto(query, ('127.0.0.1', 53530))
            
            # Receive response
            response, _ = dns_socket.recvfrom(512)
            dns_socket.close()
            
            # Parse response to extract IP
            if len(response) > 12:
                # Skip header and question, find answer
                offset = 12
                # Skip question section
                while offset < len(response) and response[offset] != 0:
                    length = response[offset]
                    offset += 1 + length
                offset += 5  # Skip null terminator and question type/class
                
                # Parse answer section
                if offset + 12 <= len(response):
                    # Skip name pointer, type, class, TTL
                    offset += 10
                    data_len = struct.unpack('!H', response[offset:offset+2])[0]
                    offset += 2
                    
                    if data_len == 4 and offset + 4 <= len(response):
                        # Extract IP address
                        ip_bytes = response[offset:offset+4]
                        ip = '.'.join(str(b) for b in ip_bytes)
                        return ip
            
            return None
            
        except Exception:
            return None
        
    def restore_dns(self):
        """Restore original DNS resolution"""
        if hasattr(self, 'original_getaddrinfo'):
            import socket
            socket.getaddrinfo = self.original_getaddrinfo
        
        # Common API patterns
        self.api_patterns = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/v2',
            '/graphql', '/swagger', '/openapi',
            '/users', '/admin', '/auth', '/login'
        ]
        
        # Common API endpoints
        self.common_endpoints = [
            'users', 'admin', 'auth', 'login', 'register', 'profile',
            'config', 'settings', 'status', 'health', 'version',
            'docs', 'swagger', 'openapi', 'graphql'
        ]
    
    def normalize_url(self, url):
        """Ensure URL has proper scheme"""
        if not url.startswith(('http://', 'https://')):
            return f"http://{url}"
        return url
    
    def run_command(self, cmd, timeout=60):
        """Execute command and return output"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=True)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
        except Exception as e:
            return "", str(e), 1
    
    def test_api_endpoint(self, url, method='GET', data=None, headers=None):
        """Test a single API endpoint"""
        try:
            req_headers = self.session.headers.copy()
            if headers:
                req_headers.update(headers)
            
            if method.upper() == 'GET':
                response = self.session.get(url, headers=req_headers)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, headers=req_headers)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data, headers=req_headers)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=req_headers)
            else:
                response = self.session.request(method, url, json=data, headers=req_headers)
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_type': response.headers.get('Content-Type', ''),
                'content_length': len(response.content),
                'response_text': response.text[:500] if response.text else ''
            }
        except Exception as e:
            return {'error': str(e)}
    
    def discover_api_endpoints(self, base_url):
        """Discover API endpoints using common patterns"""
        found_endpoints = []
        
        # Test common API patterns
        for pattern in self.api_patterns:
            if not self.is_running:
                break
                
            test_url = urljoin(base_url, pattern)
            result = self.test_api_endpoint(test_url)
            
            if 'error' not in result and result['status_code'] in [200, 201, 301, 302, 401, 403]:
                found_endpoints.append({
                    'url': test_url,
                    'method': 'GET',
                    'status': result['status_code'],
                    'content_type': result['content_type']
                })
                self.signals.output.emit(
                    f"<p style='color: #00FF41;'>[{result['status_code']}] {pattern}</p>"
                )
        
        return found_endpoints
    
    def recursive_api_discovery(self, base_url, starting_path="/api/"):
        """Recursively discover API endpoints by parsing JSON responses."""
        self.signals.output.emit("<br><p style='color: #00BFFF;'>Starting recursive API discovery...</p>")
    
        endpoints_found = []
        scan_queue = [starting_path]
        scanned_paths = set()

        while scan_queue:
            path = scan_queue.pop(0)
            if path in scanned_paths:
                continue
        
            scanned_paths.add(path)
            full_url = urljoin(base_url, path)

            try:
                # Use the existing session to maintain state (like cookies)
                response = self.session.get(full_url, verify=False, timeout=10)

                if response.status_code == 200 and 'application/json' in response.headers.get('Content-Type', ''):
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Discovered Endpoint: {path}</p>")
                    endpoints_found.append(path)
                
                    # Try to find new paths in the JSON response
                    data = response.json()
                    for key, value in data.items():
                        if isinstance(value, str) and value.startswith('/') and value not in scanned_paths:
                            scan_queue.append(value)
                        elif isinstance(value, dict): # Handle nested objects
                            for sub_key, sub_value in value.items():
                                if isinstance(sub_value, str) and sub_value.startswith('/') and sub_value not in scanned_paths:
                                    scan_queue.append(sub_value)
            except Exception as e:
                self.signals.output.emit(f"<p style='color: #FF4500;'>[!] Error scanning {path}: {e}</p>")
            
        self.results['recursive_endpoints'] = endpoints_found

    def enumerate_with_gobuster(self, base_url):
        """Use gobuster for API endpoint enumeration"""
        found_endpoints = []
        
        # Create pattern file for gobuster
        patterns = ['{GOBUSTER}/v1', '{GOBUSTER}/v2', '{GOBUSTER}/api', '{GOBUSTER}']
        
        # Use default wordlist or provided one
        wordlist = self.wordlist_path or "/usr/share/wordlists/dirb/common.txt"
        
        # Run gobuster with API patterns
        cmd = f"gobuster dir -u {base_url} -w {wordlist} -q --no-error"
        stdout, stderr, returncode = self.run_command(cmd)
        
        if returncode == 0:
            for line in stdout.split('\n'):
                if line.strip() and '(Status:' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        path = parts[0]
                        status = parts[1].replace('(Status:', '').replace(')', '')
                        found_endpoints.append({
                            'url': urljoin(base_url, path),
                            'method': 'GET',
                            'status': status,
                            'source': 'gobuster'
                        })
        
        return found_endpoints
    
    def test_api_methods(self, endpoint_url):
        """Test different HTTP methods on an endpoint"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        method_results = {}
        
        for method in methods:
            if not self.is_running:
                break
                
            result = self.test_api_endpoint(endpoint_url, method)
            if 'error' not in result:
                method_results[method] = result['status_code']
        
        return method_results
    
    def test_authentication_bypass(self, base_url):
        """Test for authentication bypass vulnerabilities"""
        auth_tests = []
        
        # Test registration with admin privileges
        register_endpoints = ['/register', '/api/register', '/users/register', '/api/v1/register']
        
        for endpoint in register_endpoints:
            if not self.is_running:
                break
                
            test_url = urljoin(base_url, endpoint)
            
            # Test normal registration
            normal_data = {
                "username": "testuser",
                "password": "testpass",
                "email": "test@test.com"
            }
            
            result = self.test_api_endpoint(test_url, 'POST', normal_data, {'Content-Type': 'application/json'})
            if 'error' not in result and result['status_code'] in [200, 201]:
                auth_tests.append({
                    'endpoint': endpoint,
                    'test': 'normal_registration',
                    'status': result['status_code'],
                    'response': result['response_text'][:200]
                })
            
            # Test registration with admin flag
            admin_data = {
                "username": "adminuser",
                "password": "adminpass",
                "email": "admin@test.com",
                "admin": True,
                "role": "admin",
                "is_admin": True
            }
            
            result = self.test_api_endpoint(test_url, 'POST', admin_data, {'Content-Type': 'application/json'})
            if 'error' not in result and result['status_code'] in [200, 201]:
                auth_tests.append({
                    'endpoint': endpoint,
                    'test': 'admin_privilege_escalation',
                    'status': result['status_code'],
                    'response': result['response_text'][:200]
                })
        
        return auth_tests
    
    def test_common_vulnerabilities(self, endpoints):
        """Test for common API vulnerabilities"""
        vuln_tests = []
        
        for endpoint_info in endpoints[:5]:  # Test first 5 endpoints
            if not self.is_running:
                break
                
            endpoint_url = endpoint_info['url']
            
            # Test for SQL injection
            sqli_payloads = ["'", "1' OR '1'='1", "'; DROP TABLE users; --"]
            for payload in sqli_payloads:
                test_url = f"{endpoint_url}?id={payload}"
                result = self.test_api_endpoint(test_url)
                
                if 'error' not in result and ('error' in result['response_text'].lower() or 'sql' in result['response_text'].lower()):
                    vuln_tests.append({
                        'endpoint': endpoint_url,
                        'vulnerability': 'SQL Injection',
                        'payload': payload,
                        'status': result['status_code']
                    })
            
            # Test for NoSQL injection
            nosql_payloads = ['{"$ne": null}', '{"$gt": ""}']
            for payload in nosql_payloads:
                result = self.test_api_endpoint(endpoint_url, 'POST', payload, {'Content-Type': 'application/json'})
                
                if 'error' not in result and result['status_code'] != 400:
                    vuln_tests.append({
                        'endpoint': endpoint_url,
                        'vulnerability': 'NoSQL Injection',
                        'payload': payload,
                        'status': result['status_code']
                    })
        
        return vuln_tests
    
    def intelligent_decode(self, response_json):
        """Attempts to decode data based on hints in the JSON response."""
        try:
            # Check for ROT13 format from the guide [cite: 157]
            if 'enctype' in response_json and response_json['enctype'] == 'ROT13' and 'data' in response_json:
                decoded = codecs.decode(response_json['data'], 'rot_13')
                self.signals.output.emit(f"<p style='color: #90EE90;'>&nbsp;&nbsp;&nbsp;→ Decoded ROT13: {decoded}</p>")
                return decoded

            # Check for Base64 format from the guide [cite: 173, 177]
            if 'format' in response_json and response_json['format'] == 'encoded' and 'data' in response_json:
                decoded = base64.b64decode(response_json['data']).decode('utf-8')
                self.signals.output.emit(f"<p style='color: #90EE90;'>&nbsp;&nbsp;&nbsp;→ Decoded Base64: {decoded}</p>")
                return decoded
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[!] Decoding failed: {e}</p>")
        
        return None

    def run(self):
        try:
            self.signals.status.emit(f"Starting API enumeration on {self.target}...")
            
            base_url = self.normalize_url(self.target)
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Enumerating API endpoints on {base_url}...</p><br>")
            
            # Discover API endpoints
            self.signals.output.emit("<p style='color: #00BFFF;'>Discovering API endpoints...</p>")
            endpoints = self.discover_api_endpoints(base_url)
            
            if endpoints:
                self.results['endpoints'] = endpoints
                self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(endpoints)} API endpoints</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>[!] No API endpoints discovered</p><br>")
            
            # Use gobuster for additional enumeration
            if self.scan_type in ["gobuster", "full"] and self.is_running:
                self.signals.output.emit("<p style='color: #00BFFF;'>Running gobuster enumeration...</p>")
                gobuster_endpoints = self.enumerate_with_gobuster(base_url)
                
                if gobuster_endpoints:
                    self.results['gobuster_endpoints'] = gobuster_endpoints
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Gobuster found {len(gobuster_endpoints)} additional endpoints</p><br>")
                    endpoints.extend(gobuster_endpoints)
            
            # Test HTTP methods
            if self.scan_type in ["methods", "full"] and endpoints and self.is_running:
                self.signals.output.emit("<p style='color: #00BFFF;'>Testing HTTP methods...</p>")
                method_results = {}
                
                for endpoint_info in endpoints[:3]:  # Test first 3 endpoints
                    if not self.is_running:
                        break
                    methods = self.test_api_methods(endpoint_info['url'])
                    if methods:
                        method_results[endpoint_info['url']] = methods
                        allowed_methods = [m for m, s in methods.items() if s not in [404, 405]]
                        if allowed_methods:
                            self.signals.output.emit(f"<p style='color: #00FF41;'>[+] {endpoint_info['url']}: {', '.join(allowed_methods)}</p>")
                
                if method_results:
                    self.results['http_methods'] = method_results
            
            # Test authentication bypass
            if self.scan_type in ["auth", "full"] and self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Testing authentication bypass...</p>")
                auth_tests = self.test_authentication_bypass(base_url)
                
                if auth_tests:
                    self.results['auth_tests'] = auth_tests
                    for test in auth_tests:
                        self.signals.output.emit(f"<p style='color: #FFAA00;'>[!] {test['test']} on {test['endpoint']}: {test['status']}</p>")
            
            # Test common vulnerabilities
            if self.scan_type in ["vulns", "full"] and endpoints and self.is_running:
                self.signals.output.emit("<br><p style='color: #00BFFF;'>Testing for vulnerabilities...</p>")
                vuln_tests = self.test_common_vulnerabilities(endpoints)
                
                if vuln_tests:
                    self.results['vulnerabilities'] = vuln_tests
                    for vuln in vuln_tests:
                        self.signals.output.emit(f"<p style='color: #FF4500;'>[VULN] {vuln['vulnerability']} on {vuln['endpoint']}</p>")
            
            # Store results
            if self.results:
                final_results = {self.target: self.results}
                self.signals.results_ready.emit(final_results)
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>API enumeration completed</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No API information could be retrieved</p>")
            
            self.signals.status.emit("API enumeration completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] API enumeration failed: {str(e)}</p>")
            self.signals.status.emit("API enumeration error")
        finally:
            # Restore original DNS resolution
            self.restore_dns()
            self.signals.finished.emit()