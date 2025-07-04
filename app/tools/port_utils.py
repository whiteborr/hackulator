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

def parse_port_range(port_string):
    """Parse port range string into list of ports"""
    ports = []
    
    if not port_string.strip():
        return get_common_ports()
    
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