# app/core/stealth_engine.py
import random
import time
import threading
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal

class StealthEngine(QObject):
    """Advanced stealth and evasion engine for professional pentesting"""
    
    stealth_event = pyqtSignal(str, str)  # event_type, message
    
    def __init__(self):
        super().__init__()
        self.stealth_enabled = False
        self.evasion_level = "medium"  # low, medium, high, extreme
        self.decoy_ips = []
        self.timing_profiles = {
            "paranoid": {"delay": (5, 15), "jitter": 0.8, "rate": 1},
            "sneaky": {"delay": (2, 8), "jitter": 0.6, "rate": 5},
            "polite": {"delay": (1, 3), "jitter": 0.4, "rate": 10},
            "normal": {"delay": (0.1, 1), "jitter": 0.2, "rate": 50}
        }
        
    def enable_stealth_mode(self, level: str = "medium"):
        """Enable stealth mode with specified evasion level"""
        self.stealth_enabled = True
        self.evasion_level = level
        self.stealth_event.emit('stealth_enabled', f'Stealth mode activated: {level}')
        
    def get_nmap_stealth_flags(self) -> List[str]:
        """Generate nmap stealth flags based on evasion level"""
        flags = []
        
        if self.evasion_level == "extreme":
            flags.extend(["-f", "-f", "--mtu", "8", "-T0", "--scan-delay", "10s"])
            flags.extend(["--max-retries", "1", "--host-timeout", "300s"])
        elif self.evasion_level == "high":
            flags.extend(["-f", "-T1", "--scan-delay", "5s"])
            flags.extend(["--max-retries", "2", "--randomize-hosts"])
        elif self.evasion_level == "medium":
            flags.extend(["-T2", "--randomize-hosts"])
            
        if self.decoy_ips:
            flags.extend(["-D", ",".join(self.decoy_ips)])
            
        return flags
        
    def get_timing_delay(self, profile: str = "polite") -> float:
        """Get randomized timing delay for requests"""
        if not self.stealth_enabled:
            return 0.1
            
        timing = self.timing_profiles.get(profile, self.timing_profiles["polite"])
        base_delay = random.uniform(*timing["delay"])
        jitter = random.uniform(-timing["jitter"], timing["jitter"])
        return max(0.1, base_delay + jitter)
        
    def generate_decoy_ips(self, target_ip: str, count: int = 5) -> List[str]:
        """Generate decoy IPs for scan obfuscation"""
        import ipaddress
        
        try:
            target = ipaddress.ip_address(target_ip)
            network = ipaddress.ip_network(f"{target}/24", strict=False)
            
            decoys = []
            for _ in range(count):
                decoy = random.choice(list(network.hosts()))
                if str(decoy) != target_ip:
                    decoys.append(str(decoy))
                    
            self.decoy_ips = decoys[:count]
            return self.decoy_ips
            
        except Exception:
            # Fallback to random private IPs
            self.decoy_ips = [f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" 
                             for _ in range(count)]
            return self.decoy_ips

# Global stealth engine instance
stealth_engine = StealthEngine()