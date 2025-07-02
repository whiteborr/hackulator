# app/core/advanced_dir_enum.py
import requests
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
import time
from typing import Set, Dict, List, Callable

class AdvancedDirectoryEnumerator:
    """Advanced directory enumeration with recursive scanning"""
    
    def __init__(self):
        self.found_directories = set()
        self.found_files = set()
        self.scanned_paths = set()
        self.max_depth = 3
        self.max_threads = 20
        self.timeout = 5
        self.interesting_extensions = ['.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl']
        self.interesting_files = ['admin', 'login', 'config', 'backup', 'test']
        
    def enumerate_directories(self, target_url: str, wordlist_path: str, 
                            progress_callback: Callable = None,
                            result_callback: Callable = None) -> Dict:
        """Enhanced directory enumeration with recursive scanning"""
        
        results = {
            'directories': [],
            'files': [],
            'interesting_findings': [],
            'status_codes': {},
            'scan_stats': {}
        }
        
        try:
            # Load wordlist
            with open(wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            
            # Initial scan
            self._scan_level(target_url, wordlist, 0, results, progress_callback, result_callback)
            
            # Recursive scanning of found directories
            for depth in range(1, self.max_depth):
                new_dirs = [d for d in self.found_directories if d not in self.scanned_paths]
                if not new_dirs:
                    break
                    
                for directory in new_dirs:
                    self._scan_level(directory, wordlist, depth, results, progress_callback, result_callback)
            
            # Compile final results
            results['directories'] = list(self.found_directories)
            results['files'] = list(self.found_files)
            results['scan_stats'] = {
                'total_requests': len(self.scanned_paths),
                'directories_found': len(self.found_directories),
                'files_found': len(self.found_files),
                'max_depth_reached': min(depth + 1, self.max_depth)
            }
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _scan_level(self, base_url: str, wordlist: List[str], depth: int, 
                   results: Dict, progress_callback: Callable, result_callback: Callable):
        """Scan a single directory level"""
        
        if progress_callback:
            progress_callback(f"Scanning depth {depth}: {base_url}")
        
        def check_path(word):
            url = urljoin(base_url, word)
            return self._check_url(url, results, result_callback)
        
        # Use thread pool for concurrent requests
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(check_path, word) for word in wordlist[:200]]  # Limit for performance
            
            for future in futures:
                try:
                    future.result(timeout=self.timeout)
                except:
                    continue
        
        self.scanned_paths.add(base_url)
    
    def _check_url(self, url: str, results: Dict, result_callback: Callable):
        """Check individual URL and categorize findings"""
        
        try:
            # Apply rate limiting
            try:
                from app.core.rate_limiter import rate_limiter
                rate_limiter.wait_if_needed('advanced_dir_enum')
            except ImportError:
                time.sleep(0.1)  # Basic rate limiting
            
            # Get proxy settings
            proxies = {}
            try:
                from app.core.proxy_manager import proxy_manager
                proxies = proxy_manager.get_proxy_dict()
            except ImportError:
                pass
            
            response = requests.get(url, timeout=self.timeout, allow_redirects=False, 
                                  verify=False, proxies=proxies)
            
            status_code = response.status_code
            content_length = len(response.content)
            
            # Track status codes
            if status_code not in results['status_codes']:
                results['status_codes'][status_code] = 0
            results['status_codes'][status_code] += 1
            
            # Categorize findings
            if status_code in [200, 301, 302, 403]:
                finding = {
                    'url': url,
                    'status_code': status_code,
                    'content_length': content_length,
                    'type': self._categorize_finding(url, status_code, response)
                }
                
                if finding['type'] == 'directory':
                    self.found_directories.add(url)
                    results['directories'].append(finding)
                elif finding['type'] == 'file':
                    self.found_files.add(url)
                    results['files'].append(finding)
                
                # Check for interesting findings
                if self._is_interesting_finding(url, status_code, response):
                    finding['interesting'] = True
                    results['interesting_findings'].append(finding)
                
                if result_callback:
                    result_callback(finding)
        
        except Exception:
            pass  # Ignore individual request failures
    
    def _categorize_finding(self, url: str, status_code: int, response) -> str:
        """Categorize finding as directory or file"""
        
        # Check URL structure
        if url.endswith('/'):
            return 'directory'
        
        # Check for file extensions
        parsed = urlparse(url)
        path = parsed.path
        if '.' in path.split('/')[-1]:
            return 'file'
        
        # Check response headers
        content_type = response.headers.get('content-type', '').lower()
        if 'text/html' in content_type and status_code == 200:
            # Check if it's a directory listing
            if 'index of' in response.text.lower() or 'directory listing' in response.text.lower():
                return 'directory'
        
        # Default to file for specific status codes
        if status_code == 200:
            return 'file'
        elif status_code in [301, 302] and response.headers.get('location', '').endswith('/'):
            return 'directory'
        
        return 'unknown'
    
    def _is_interesting_finding(self, url: str, status_code: int, response) -> bool:
        """Determine if finding is particularly interesting"""
        
        url_lower = url.lower()
        
        # Check for interesting file names
        for interesting_file in self.interesting_files:
            if interesting_file in url_lower:
                return True
        
        # Check for interesting extensions
        for ext in self.interesting_extensions:
            if url_lower.endswith(ext):
                return True
        
        # Check for admin/sensitive paths
        sensitive_paths = ['admin', 'login', 'config', 'backup', 'test', 'dev', 'staging']
        for path in sensitive_paths:
            if path in url_lower:
                return True
        
        # Check response content for interesting indicators
        if status_code == 200 and hasattr(response, 'text'):
            content_lower = response.text.lower()
            interesting_content = ['password', 'admin', 'login', 'config', 'database', 'api']
            for indicator in interesting_content:
                if indicator in content_lower:
                    return True
        
        return False

# Global instance
advanced_dir_enum = AdvancedDirectoryEnumerator()