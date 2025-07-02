# app/core/memory_manager.py
import psutil
import gc
import threading
import time
from typing import Callable, Optional

class MemoryManager:
    """Monitor and optimize memory usage"""
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.memory_threshold = 80  # Percentage
            self.monitoring = False
            self.callback: Optional[Callable] = None
            self.initialized = True
    
    def get_memory_usage(self) -> float:
        """Get current memory usage percentage"""
        return psutil.virtual_memory().percent
    
    def get_memory_info(self) -> dict:
        """Get detailed memory information"""
        mem = psutil.virtual_memory()
        return {
            'total': mem.total // (1024**2),  # MB
            'used': mem.used // (1024**2),    # MB
            'available': mem.available // (1024**2),  # MB
            'percent': mem.percent
        }
    
    def optimize_memory(self):
        """Force garbage collection and memory cleanup"""
        gc.collect()
        
    def start_monitoring(self, callback: Callable = None):
        """Start memory monitoring in background"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.callback = callback
        
        def monitor():
            while self.monitoring:
                usage = self.get_memory_usage()
                if usage > self.memory_threshold:
                    self.optimize_memory()
                    if self.callback:
                        self.callback(f"Memory optimized: {usage:.1f}%")
                time.sleep(5)  # Check every 5 seconds
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def stop_monitoring(self):
        """Stop memory monitoring"""
        self.monitoring = False

# Global instance
memory_manager = MemoryManager()