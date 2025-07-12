# app/tools/http_fingerprint.py
import requests
import re
from urllib.parse import urljoin, urlparse
from .encoders import decode_javascript_obfuscation, detect_and_decode

class HTTPFingerprinter:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def analyze_headers(self, response):
        """Enhanced header analysis for technology detection"""
        tech_info = {}
        headers = response.headers
        
        # Server identification
        server = headers.get('Server', '')
        tech_info['server'] = server
        
        # Framework detection
        frameworks = {
            'Laravel': ['laravel_session', 'X-RateLimit-Limit'],
            'Express': ['X-Powered-By: Express'],
            'Django': ['X-Frame-Options: DENY', 'csrftoken'],
            'Flask': ['Werkzeug'],
            'ASP.NET': ['X-AspNet-Version', 'X-Powered-By: ASP.NET'],
            'PHP': ['X-Powered-By: PHP', 'PHPSESSID'],
            'WordPress': ['X-Pingback', 'wp-'],
            'Drupal': ['X-Drupal-Cache', 'X-Generator: Drupal']
        }
        
        detected_frameworks = []
        headers_str = str(headers).lower()
        
        for framework, indicators in frameworks.items():
            for indicator in indicators:
                if indicator.lower() in headers_str:
                    detected_frameworks.append(framework)
                    break
        
        tech_info['frameworks'] = detected_frameworks
        
        # Security headers analysis
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-Powered-By': headers.get('X-Powered-By')
        }
        
        tech_info['security_headers'] = {k: v for k, v in security_headers.items() if v}
        
        return tech_info
    
    def extract_javascript_files(self, html_content, base_url):
        """Extract and analyze JavaScript files"""
        js_files = []
        
        # Find script tags with src
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(script_pattern, html_content, re.IGNORECASE)
        
        for src in matches:
            if not src.startswith('http'):
                src = urljoin(base_url, src)
            js_files.append(src)
        
        # Download and analyze JS files
        analyzed_js = []
        for js_url in js_files[:5]:  # Limit to first 5 files
            try:
                response = self.session.get(js_url, timeout=10, verify=False)
                if response.status_code == 200:
                    js_content = response.text
                    
                    # Look for API endpoints in JS
                    api_endpoints = self.extract_api_endpoints_from_js(js_content)
                    
                    # Decode obfuscated content
                    decoded_content = decode_javascript_obfuscation(js_content)
                    
                    # Look for encoded data
                    encoded_data = []
                    for line in js_content.split('\n'):
                        if any(pattern in line for pattern in ['"', "'"]):
                            strings = re.findall(r'["\']([^"\']{20,})["\']', line)
                            for string in strings:
                                decoded = detect_and_decode(string)
                                if decoded:
                                    encoded_data.extend(decoded)
                    
                    analyzed_js.append({
                        'url': js_url,
                        'size': len(js_content),
                        'api_endpoints': api_endpoints,
                        'decoded_content': decoded_content,
                        'encoded_data': encoded_data
                    })
                    
            except Exception:
                pass
        
        return analyzed_js
    
    def extract_api_endpoints_from_js(self, js_content):
        """Extract API endpoints from JavaScript code"""
        endpoints = []
        
        # Common API endpoint patterns
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\']([^"\']*\.php[^"\']*)["\']',
            r'["\']([^"\']*\.asp[x]?[^"\']*)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'endpoint\s*:\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            endpoints.extend(matches)
        
        # Remove duplicates and filter
        unique_endpoints = list(set(endpoints))
        filtered_endpoints = [ep for ep in unique_endpoints if len(ep) > 3 and not ep.startswith('http')]
        
        return filtered_endpoints
    
    def parse_web_content(self, html_content, base_url):
        """Parse HTML content for forms, links, and other elements"""
        content_info = {}
        
        # Extract forms
        forms = []
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
        
        for action, form_content in form_matches:
            # Extract input fields
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            forms.append({
                'action': action if action.startswith('http') else urljoin(base_url, action),
                'inputs': inputs
            })
        
        content_info['forms'] = forms
        
        # Extract links
        links = []
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>'
        link_matches = re.findall(link_pattern, html_content, re.IGNORECASE)
        
        for link in link_matches:
            if not link.startswith('http') and not link.startswith('#'):
                full_link = urljoin(base_url, link)
                links.append(full_link)
        
        content_info['links'] = list(set(links))[:20]  # Limit to 20 unique links
        
        # Extract meta information
        meta_info = {}
        meta_patterns = {
            'generator': r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            'description': r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
            'keywords': r'<meta[^>]+name=["\']keywords["\'][^>]+content=["\']([^"\']+)["\']'
        }
        
        for key, pattern in meta_patterns.items():
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                meta_info[key] = match.group(1)
        
        content_info['meta'] = meta_info
        
        return content_info
    
    def check_known_files(self, base_url):
        """Check for known files and directories"""
        known_files = [
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/.htaccess',
            '/web.config',
            '/config.php',
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/admin.php',
            '/login.php',
            '/js/inviteapi.min.js',
            '/js/app.js',
            '/js/main.js',
            '/api/swagger.json',
            '/api/openapi.json'
        ]
        
        found_files = []
        
        for file_path in known_files:
            try:
                url = urljoin(base_url, file_path)
                response = self.session.head(url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    found_files.append({
                        'path': file_path,
                        'url': url,
                        'size': response.headers.get('Content-Length', 'Unknown'),
                        'content_type': response.headers.get('Content-Type', 'Unknown')
                    })
                    
            except Exception:
                pass
        
        return found_files
    
    def comprehensive_fingerprint(self, url):
        """Perform comprehensive HTTP fingerprinting"""
        results = {}
        
        try:
            # Initial request
            response = self.session.get(url, timeout=10, verify=False)
            results['status_code'] = response.status_code
            results['content_length'] = len(response.content)
            
            # Header analysis
            results['technology'] = self.analyze_headers(response)
            
            # Content parsing
            if 'text/html' in response.headers.get('Content-Type', ''):
                results['content_analysis'] = self.parse_web_content(response.text, url)
                
                # JavaScript analysis
                results['javascript_analysis'] = self.extract_javascript_files(response.text, url)
            
            # Known files check
            results['known_files'] = self.check_known_files(url)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results