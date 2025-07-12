#!/usr/bin/env python3
"""
Enhanced HTTP/S Fingerprinting Tool
Features:
- Framework detection (Laravel, Express, WordPress, etc.)
- JavaScript file analysis and deobfuscation
- Encoded data detection (Base64, ROT13)
- API endpoint extraction from JS
- Security header analysis
"""

import requests
import re
import base64
import argparse
from urllib.parse import urljoin, urlparse

def analyze_headers(response):
    """Enhanced header analysis for technology detection"""
    headers = response.headers
    tech_info = {'server': headers.get('Server', 'Unknown')}
    
    # Framework detection
    frameworks = {
        'Laravel': ['laravel_session', 'X-RateLimit-Limit', 'laravel_token'],
        'Express': ['X-Powered-By: Express'],
        'Django': ['X-Frame-Options: DENY', 'csrftoken', 'django'],
        'Flask': ['Werkzeug', 'flask'],
        'ASP.NET': ['X-AspNet-Version', 'X-Powered-By: ASP.NET'],
        'PHP': ['X-Powered-By: PHP', 'PHPSESSID'],
        'WordPress': ['X-Pingback', 'wp-', '/wp-content/'],
        'Drupal': ['X-Drupal-Cache', 'X-Generator: Drupal'],
        'Joomla': ['/components/', '/modules/']
    }
    
    detected = []
    headers_str = str(headers).lower()
    
    for framework, indicators in frameworks.items():
        for indicator in indicators:
            if indicator.lower() in headers_str:
                detected.append(framework)
                break
    
    tech_info['frameworks'] = detected
    
    # Security headers
    security = {
        'X-Frame-Options': headers.get('X-Frame-Options'),
        'X-XSS-Protection': headers.get('X-XSS-Protection'),
        'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
        'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
        'Content-Security-Policy': headers.get('Content-Security-Policy')
    }
    tech_info['security_headers'] = {k: v for k, v in security.items() if v}
    
    return tech_info

def extract_javascript_files(html_content, base_url, session):
    """Extract and analyze JavaScript files"""
    js_files = []
    
    # Find script tags
    script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
    matches = re.findall(script_pattern, html_content, re.IGNORECASE)
    
    print(f"[*] Found {len(matches)} JavaScript files")
    
    for src in matches[:5]:  # Limit to first 5
        if not src.startswith('http'):
            src = urljoin(base_url, src)
        
        try:
            print(f"[*] Analyzing {src}")
            response = session.get(src, timeout=10, verify=False)
            
            if response.status_code == 200:
                js_content = response.text
                
                # Extract API endpoints
                api_endpoints = extract_api_endpoints_from_js(js_content)
                
                # Look for obfuscated code
                obfuscated = detect_js_obfuscation(js_content)
                
                # Look for encoded strings
                encoded_data = find_encoded_strings(js_content)
                
                js_info = {
                    'url': src,
                    'size': len(js_content),
                    'api_endpoints': api_endpoints,
                    'obfuscated': obfuscated,
                    'encoded_data': encoded_data
                }
                
                js_files.append(js_info)
                
                # Display findings
                if api_endpoints:
                    print(f"    [+] Found {len(api_endpoints)} API endpoints:")
                    for endpoint in api_endpoints[:5]:
                        print(f"        → {endpoint}")
                
                if encoded_data:
                    print(f"    [+] Found encoded data:")
                    for encoding, decoded in encoded_data:
                        print(f"        → {encoding}: {decoded[:50]}...")
                
                if obfuscated:
                    print(f"    [!] Obfuscated code detected")
                    
        except Exception as e:
            print(f"    [-] Error analyzing {src}: {e}")
    
    return js_files

def extract_api_endpoints_from_js(js_content):
    """Extract API endpoints from JavaScript"""
    endpoints = []
    
    patterns = [
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/rest/[^"\']+)["\']',
        r'["\']([^"\']*\.php[^"\']*)["\']',
        r'["\']([^"\']*\.asp[x]?[^"\']*)["\']',
        r'url\s*:\s*["\']([^"\']+)["\']',
        r'endpoint\s*:\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        endpoints.extend(matches)
    
    # Filter and deduplicate
    unique_endpoints = list(set(endpoints))
    filtered = [ep for ep in unique_endpoints if len(ep) > 3 and not ep.startswith('http')]
    
    return filtered

def detect_js_obfuscation(js_content):
    """Detect JavaScript obfuscation patterns"""
    obfuscation_patterns = [
        r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)',
        r'_0x[a-f0-9]+',
        r'\\x[0-9a-f]{2}',
        r'String\.fromCharCode',
        r'unescape\s*\(',
        r'atob\s*\('
    ]
    
    for pattern in obfuscation_patterns:
        if re.search(pattern, js_content, re.IGNORECASE):
            return True
    
    return False

def find_encoded_strings(js_content):
    """Find and decode encoded strings in JavaScript"""
    encoded_data = []
    
    # Find quoted strings longer than 20 chars
    string_pattern = r'["\']([A-Za-z0-9+/=]{20,})["\']'
    matches = re.findall(string_pattern, js_content)
    
    for match in matches:
        # Try Base64 decoding
        try:
            if len(match) % 4 == 0:
                decoded = base64.b64decode(match).decode('utf-8')
                if all(ord(c) < 128 for c in decoded):  # ASCII check
                    encoded_data.append(('Base64', decoded))
        except:
            pass
    
    return encoded_data

def check_known_files(base_url, session):
    """Check for known interesting files"""
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
        '/js/config.js',
        '/api/swagger.json',
        '/api/openapi.json',
        '/.env',
        '/backup.sql',
        '/database.sql'
    ]
    
    print(f"[*] Checking for known files")
    found_files = []
    
    for file_path in known_files:
        try:
            url = urljoin(base_url, file_path)
            response = session.head(url, timeout=5, verify=False)
            
            if response.status_code == 200:
                size = response.headers.get('Content-Length', 'Unknown')
                content_type = response.headers.get('Content-Type', 'Unknown')
                
                found_files.append({
                    'path': file_path,
                    'size': size,
                    'content_type': content_type
                })
                
                print(f"    [+] {file_path} ({content_type}, {size} bytes)")
                
        except:
            pass
    
    return found_files

def parse_html_content(html_content, base_url):
    """Parse HTML for forms, links, and meta info"""
    content_info = {}
    
    # Extract forms
    forms = []
    form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
    form_matches = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
    
    for action, form_content in form_matches:
        input_pattern = r'<input[^>]*name=["\']([^"\']*)["\']'
        inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
        
        forms.append({
            'action': action if action.startswith('http') else urljoin(base_url, action),
            'inputs': inputs
        })
    
    content_info['forms'] = forms
    
    # Extract meta information
    meta_patterns = {
        'generator': r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        'description': r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']'
    }
    
    meta_info = {}
    for key, pattern in meta_patterns.items():
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            meta_info[key] = match.group(1)
    
    content_info['meta'] = meta_info
    
    return content_info

def comprehensive_fingerprint(url):
    """Perform comprehensive HTTP fingerprinting"""
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 HTTP Fingerprinter'})
    session.verify = False
    
    print(f"[*] Comprehensive fingerprinting of {url}")
    
    try:
        # Initial request
        response = session.get(url, timeout=10)
        print(f"[+] Status: {response.status_code}")
        print(f"[+] Content Length: {len(response.content)} bytes")
        
        # Header analysis
        tech_info = analyze_headers(response)
        print(f"[+] Server: {tech_info['server']}")
        
        if tech_info['frameworks']:
            print(f"[+] Frameworks: {', '.join(tech_info['frameworks'])}")
        
        if tech_info['security_headers']:
            print(f"[+] Security Headers: {len(tech_info['security_headers'])} found")
        
        # Content analysis
        if 'text/html' in response.headers.get('Content-Type', ''):
            # JavaScript analysis
            js_files = extract_javascript_files(response.text, url, session)
            
            # HTML content parsing
            content_info = parse_html_content(response.text, url)
            
            if content_info['forms']:
                print(f"[+] Forms: {len(content_info['forms'])} found")
                for form in content_info['forms']:
                    print(f"    → {form['action']} ({len(form['inputs'])} inputs)")
        
        # Known files check
        known_files = check_known_files(url, session)
        
        return {
            'status_code': response.status_code,
            'technology': tech_info,
            'javascript_files': js_files if 'js_files' in locals() else [],
            'known_files': known_files,
            'content_info': content_info if 'content_info' in locals() else {}
        }
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return {'error': str(e)}

def main():
    parser = argparse.ArgumentParser(description="Enhanced HTTP/S Fingerprinting Tool")
    parser.add_argument("target", help="Target URL (e.g., http://example.com)")
    parser.add_argument("--js-analysis", action="store_true", help="Deep JavaScript analysis")
    parser.add_argument("--known-files", action="store_true", help="Check for known files")
    parser.add_argument("--all", action="store_true", help="Run all checks")
    
    args = parser.parse_args()
    
    url = args.target
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    # Run comprehensive fingerprinting
    results = comprehensive_fingerprint(url)
    
    if 'error' not in results:
        print(f"\n[*] Fingerprinting completed successfully")
    else:
        print(f"\n[-] Fingerprinting failed: {results['error']}")

if __name__ == "__main__":
    main()