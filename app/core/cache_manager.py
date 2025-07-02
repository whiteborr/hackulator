# app/core/cache_manager.py
import json
import hashlib
import time
from pathlib import Path
from typing import Any, Optional, Dict
import threading

class CacheManager:
    """Simple file-based cache for scan results"""
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
            self.cache_dir = Path("cache")
            self.cache_dir.mkdir(exist_ok=True)
            self.ttl = 3600  # 1 hour default TTL
            self.initialized = True
    
    def _get_cache_key(self, tool: str, target: str, params: Dict = None) -> str:
        """Generate cache key from tool, target, and parameters"""
        data = f"{tool}:{target}:{json.dumps(params or {}, sort_keys=True)}"
        return hashlib.md5(data.encode()).hexdigest()
    
    def get(self, tool: str, target: str, params: Dict = None) -> Optional[Any]:
        """Get cached result if valid"""
        cache_key = self._get_cache_key(tool, target, params)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            
            # Check TTL
            if time.time() - cache_data['timestamp'] > self.ttl:
                cache_file.unlink()  # Remove expired cache
                return None
            
            return cache_data['results']
        except:
            return None
    
    def set(self, tool: str, target: str, results: Any, params: Dict = None):
        """Cache scan results"""
        cache_key = self._get_cache_key(tool, target, params)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        cache_data = {
            'timestamp': time.time(),
            'tool': tool,
            'target': target,
            'params': params or {},
            'results': results
        }
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
        except:
            pass  # Fail silently
    
    def clear_expired(self):
        """Remove expired cache entries"""
        current_time = time.time()
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)
                if current_time - cache_data['timestamp'] > self.ttl:
                    cache_file.unlink()
            except:
                pass

# Global instance
cache_manager = CacheManager()