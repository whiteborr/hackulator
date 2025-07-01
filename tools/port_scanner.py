#!/usr/bin/env python3
import socket
import subprocess
import threading
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
import time

class PortScanner:
    def __init__(self, target, ports=None, threads=50, timeout=3):
        self.target = target
        self.ports = ports or range(1, 1025)
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.lock = threading.Lock()

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                    print(f"[+] Port {port}/tcp open")
        except:
            pass

    def tcp_connect_scan(self):
        print(f"[*] Starting TCP connect scan on {self.target}")
        print(f"[*] Scanning ports: {min(self.ports)}-{max(self.ports)}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_port, self.ports)
        
        return sorted(self.open_ports)

    def ping_sweep(self, network):
        """Network sweep scan (equivalent to nmap -sn)"""
        print(f"[*] Performing ping sweep on {network}")
        alive_hosts = []
        
        base_ip = '.'.join(network.split('.')[:-1])
        
        def ping_host(host_num):
            target_ip = f"{base_ip}.{host_num}"
            try:
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', target_ip], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    alive_hosts.append(target_ip)
                    print(f"[+] {target_ip} is alive")
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(ping_host, range(1, 255))
        
        return sorted(alive_hosts)

    def service_detection(self, port):
        """Basic service detection on open ports"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                return banner.split('\n')[0] if banner else "HTTP Service"
            
            sock.send(b"\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else "Unknown Service"
            
        except:
            return "Unknown Service"

def main():
    parser = argparse.ArgumentParser(description="Port Scanner Tool")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 1-1000 or 80,443,22)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=3, help="Connection timeout")
    parser.add_argument("--sweep", action="store_true", help="Perform network ping sweep")
    parser.add_argument("--top-ports", type=int, help="Scan top N ports")
    parser.add_argument("--service-detect", action="store_true", help="Service detection")
    
    args = parser.parse_args()
    
    if args.sweep:
        scanner = PortScanner(args.target)
        alive_hosts = scanner.ping_sweep(args.target)
        print(f"\n[*] Found {len(alive_hosts)} alive hosts")
        return
    
    ports = range(1, 1025)
    
    if args.top_ports:
        top_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
        ports = top_ports[:args.top_ports]
    elif args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = range(start, end + 1)
        elif ',' in args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        else:
            ports = [int(args.ports)]
    
    scanner = PortScanner(args.target, ports, args.threads, args.timeout)
    
    start_time = time.time()
    open_ports = scanner.tcp_connect_scan()
    scan_time = time.time() - start_time
    
    print(f"\n[*] Scan completed in {scan_time:.2f} seconds")
    print(f"[*] Found {len(open_ports)} open ports")
    
    if open_ports and args.service_detect:
        print("\n[*] Performing service detection...")
        for port in open_ports:
            service = scanner.service_detection(port)
            print(f"[+] {port}/tcp - {service}")
    
    if open_ports:
        print(f"\n[*] Open ports: {', '.join(map(str, open_ports))}")
    else:
        print("\n[-] No open ports found")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)