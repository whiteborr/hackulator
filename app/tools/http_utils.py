# app/tools/http_utils.py
from PyQt6.QtCore import QThreadPool
from .http_scanner import HTTPEnumWorker

def run_http_enumeration(target, scan_type="basic", wordlist_path=None, extensions=None, output_callback=None, status_callback=None, finished_callback=None, results_callback=None, progress_callback=None, progress_start_callback=None):
    """Run HTTP enumeration on target"""
    worker = HTTPEnumWorker(target, scan_type, wordlist_path, extensions)
    
    # Connect signals
    if output_callback:
        worker.signals.output.connect(output_callback)
    if status_callback:
        worker.signals.status.connect(status_callback)
    if finished_callback:
        worker.signals.finished.connect(finished_callback)
    if results_callback:
        worker.signals.results_ready.connect(results_callback)
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    
    QThreadPool.globalInstance().start(worker)
    return worker