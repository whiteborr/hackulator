#!/usr/bin/env python3
import requests
import socket
import ssl
import argparse
import sys
from urllib.parse import urljoin
import threading
from concurrent.futures import ThreadPoolExecutor

# Import connection pool
try:
    from app.core.connection_pool import connection_pool
    from app.core.proxy_manager import proxy_manager
except ImportError:
    connection_pool = None
    proxy_manager = None

def http_fingerprint(target, port=80, https=False):
    protocol = "https" if https else "http"
    url = f"{protocol}://{target}:{port}"
    
    try:
        # Use connection pool if available
        if connection_pool:
            session = connection_pool.get_session(f"http_{target}")
            proxies = proxy_manager.get_proxy_dict() if proxy_manager else {}
            response = session.get(url, timeout=5, verify=False, proxies=proxies)
        else:
            proxies = proxy_manager.get_proxy_dict() if proxy_manager else {}
            response = requests.get(url, timeout=5, verify=False, proxies=proxies)
        print(f"[+] {url} - Status: {response.status_code}")
        
        # Server header
        server = response.headers.get('Server', 'Unknown')
        print(f"[+] Server: {server}")
        
        # Other headers
        headers = ['X-Powered-By', 'X-AspNet-Version', 'X-Generator']
        for header in headers:
            if header in response.headers:
                print(f"[+] {header}: {response.headers[header]}")
        
        return True
    except Exception as e:
        print(f"[-] {url} - Error: {e}")
        return False

def ssl_scan(target, port=443):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                print(f"[+] SSL Certificate Subject: {cert.get('subject', 'Unknown')}")
                print(f"[+] SSL Certificate Issuer: {cert.get('issuer', 'Unknown')}")
                
                # Get cipher info
                cipher = ssock.cipher()
                if cipher:
                    print(f"[+] SSL Cipher: {cipher[0]} {cipher[1]} {cipher[2]}")
        return True
    except Exception as e:
        print(f"[-] SSL scan failed: {e}")
        return False

def directory_scan(target, port=80, https=False, wordlist=None):
    protocol = "https" if https else "http"
    base_url = f"{protocol}://{target}:{port}"
    
    if not wordlist:
        dirs = ["admin", "login", "test", "backup", "config", "api", "uploads", "images", "js", "css"]
    else:
        with open(wordlist, 'r') as f:
            dirs = [line.strip() for line in f if line.strip()]
    
    print(f"[*] Directory scanning {base_url}")
    found_dirs = []
    
    def check_dir(directory):
        url = urljoin(base_url + "/", directory)
        try:
            # Apply rate limiting
            try:
                from app.core.rate_limiter import rate_limiter
                rate_limiter.wait_if_needed('http_dir_scan')
            except ImportError:
                pass
            
            # Use connection pool if available
            if connection_pool:
                session = connection_pool.get_session(f"dir_{target}")
                proxies = proxy_manager.get_proxy_dict() if proxy_manager else {}
                response = session.get(url, timeout=3, verify=False, allow_redirects=False, proxies=proxies)
            else:
                proxies = proxy_manager.get_proxy_dict() if proxy_manager else {}
                response = requests.get(url, timeout=3, verify=False, allow_redirects=False, proxies=proxies)
            if response.status_code in [200, 301, 302, 403]:
                print(f"[+] {url} - Status: {response.status_code}")
                found_dirs.append(url)
        except:
            pass
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_dir, dirs)
    
    return found_dirs

def main():
    parser = argparse.ArgumentParser(description="HTTP/S Enumeration Tool")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=80, help="Port number")
    parser.add_argument("--https", action="store_true", help="Use HTTPS")
    parser.add_argument("--ssl-scan", action="store_true", help="SSL/TLS scan")
    parser.add_argument("--dir-scan", action="store_true", help="Directory scan")
    parser.add_argument("--wordlist", help="Directory wordlist")
    
    args = parser.parse_args()
    
    print(f"[*] HTTP enumeration on {args.target}:{args.port}")
    
    # Basic HTTP fingerprinting
    if http_fingerprint(args.target, args.port, args.https):
        print("[+] HTTP service detected")
    
    # SSL scan
    if args.ssl_scan or (args.https and args.port == 443):
        ssl_scan(args.target, args.port)
    
    # Directory scan
    if args.dir_scan:
        found = directory_scan(args.target, args.port, args.https, args.wordlist)
        print(f"[*] Found {len(found)} directories/files")

if __name__ == "__main__":
    main()