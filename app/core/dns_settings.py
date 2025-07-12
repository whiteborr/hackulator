# app/core/dns_settings.py
import json
import os
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger

class DNSSettingsManager(QObject):
    """Global DNS settings manager"""
    
    dns_changed = pyqtSignal(str)  # dns_server
    
    def __init__(self):
        super().__init__()
        self.settings_file = "dns_settings.json"
        self.current_dns = "Default DNS"  # Default on startup
        self.load_settings()
    
    def get_current_dns(self):
        """Get current DNS server setting"""
        return self.current_dns
    
    def set_dns_server(self, dns_server):
        """Set global DNS server"""
        self.current_dns = dns_server
        self.save_settings()
        self.dns_changed.emit(dns_server)
        logger.info(f"DNS server changed to: {dns_server}")
    
    def get_available_dns_servers(self):
        """Get list of available DNS servers"""
        return [
            "Default DNS",
            "LocalDNS"
        ]
    
    def save_settings(self):
        """Save DNS settings to file"""
        try:
            settings = {
                "current_dns": self.current_dns
            }
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save DNS settings: {e}")
    
    def load_settings(self):
        """Load DNS settings from file"""
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    settings = json.load(f)
                    self.current_dns = settings.get("current_dns", "Default DNS")
        except Exception as e:
            logger.error(f"Failed to load DNS settings: {e}")
            self.current_dns = "Default DNS"

# Global DNS settings instance
dns_settings = DNSSettingsManager()