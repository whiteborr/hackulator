# app/tools/port_utils.py
from PyQt6.QtCore import QThreadPool
from .port_scanner import PortScanWorker, NetworkSweepWorker, get_common_ports, get_top_ports

def run_port_scan(target, ports, output_callback, status_callback, finished_callback, results_callback, progress_callback=None, progress_start_callback=None):
    """Run TCP port scan on target"""
    worker = PortScanWorker(target, ports)
    
    # Connect signals
    worker.signals.output.connect(output_callback)
    worker.signals.status.connect(status_callback)
    worker.signals.finished.connect(finished_callback)
    worker.signals.results_ready.connect(results_callback)
    
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    
    QThreadPool.globalInstance().start(worker)
    return worker

def run_network_sweep(network_range, output_callback, status_callback, finished_callback, results_callback, progress_callback=None, progress_start_callback=None):
    """Run network sweep to discover alive hosts"""
    worker = NetworkSweepWorker(network_range)
    
    # Connect signals
    worker.signals.output.connect(output_callback)
    worker.signals.status.connect(status_callback)
    worker.signals.finished.connect(finished_callback)
    worker.signals.results_ready.connect(results_callback)
    
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    
    QThreadPool.globalInstance().start(worker)
    return worker

def run_nmap_scan(target, ports, scan_type, os_detection=False, service_detection=False, output_callback=None, status_callback=None, finished_callback=None, results_callback=None, progress_callback=None, progress_start_callback=None):
    """Run nmap-based port scan"""
    from .port_scanner import NmapScanWorker
    worker = NmapScanWorker(target, ports, scan_type, os_detection, service_detection)
    
    # Connect signals
    worker.signals.output.connect(output_callback)
    worker.signals.status.connect(status_callback)
    worker.signals.finished.connect(finished_callback)
    worker.signals.results_ready.connect(results_callback)
    
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    
    QThreadPool.globalInstance().start(worker)
    return worker

def parse_port_range(port_string):
    """Parse port range string into list of ports"""
    ports = []
    
    if not port_string.strip():
        raise ValueError("Port range cannot be empty")
    
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            # Range like 80-90
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            # Single port
            ports.append(int(part))
    
    return sorted(list(set(ports)))  # Remove duplicates and sort

def run_ip_range_port_scan(ip_range, ports, output_callback, status_callback, finished_callback, results_callback, progress_callback=None, progress_start_callback=None):
    """Run port scan on IP range"""
    import ipaddress
    import re
    
    # Parse IP range
    ips = []
    if '/' in ip_range:
        # CIDR notation
        network = ipaddress.ip_network(ip_range, strict=False)
        ips = [str(ip) for ip in network.hosts()]
    elif '-' in ip_range:
        # Range notation like 192.168.1.1-254
        parts = ip_range.split('-')
        base_ip = parts[0].strip()
        end_octet = int(parts[1].strip())
        base_parts = base_ip.split('.')
        start_octet = int(base_parts[3])
        base_network = '.'.join(base_parts[:3])
        ips = [f"{base_network}.{i}" for i in range(start_octet, end_octet + 1)]
    else:
        # Single IP
        ips = [ip_range]
    
    # Create worker for IP range scanning
    from .port_scanner import IPRangePortScanWorker
    worker = IPRangePortScanWorker(ips, ports)
    
    # Connect signals
    worker.signals.output.connect(output_callback)
    worker.signals.status.connect(status_callback)
    worker.signals.finished.connect(finished_callback)
    worker.signals.results_ready.connect(results_callback)
    
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    
    QThreadPool.globalInstance().start(worker)
    return worker