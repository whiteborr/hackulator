# app/core/logger.py
import logging
import os
from pathlib import Path
from datetime import datetime

class HackulatorLogger:
    """Centralized logging system for Hackulator"""
    
    _instance = None
    _logger = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._logger is None:
            self._setup_logger()
    
    def _setup_logger(self):
        """Initialize the logging system"""
        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Create logger
        self._logger = logging.getLogger("hackulator")
        self._logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        self._logger.handlers.clear()
        
        # File handler for all logs
        log_file = log_dir / f"hackulator_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler for important messages
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self._logger.addHandler(file_handler)
        self._logger.addHandler(console_handler)
    
    def debug(self, message):
        """Log debug message"""
        self._logger.debug(message)
    
    def info(self, message):
        """Log info message"""
        self._logger.info(message)
    
    def warning(self, message):
        """Log warning message"""
        self._logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        self._logger.error(message)
    
    def critical(self, message):
        """Log critical message"""
        self._logger.critical(message)
    
    def log_scan_start(self, target, wordlist, record_types):
        """Log scan initiation"""
        self.info(f"DNS scan started - Target: {target}, Wordlist: {Path(wordlist).name}, Types: {record_types}")
    
    def log_scan_complete(self, target, results_count):
        """Log scan completion"""
        self.info(f"DNS scan completed - Target: {target}, Results: {results_count}")
    
    def log_validation_error(self, field, error):
        """Log validation errors"""
        self.warning(f"Validation failed - {field}: {error}")
    
    def log_dns_error(self, domain, error):
        """Log DNS resolution errors"""
        self.debug(f"DNS error for {domain}: {error}")

# Global logger instance
logger = HackulatorLogger()