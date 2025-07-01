# app/core/validators.py
import re
import os
from pathlib import Path

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class InputValidator:
    """Handles input validation and sanitization"""
    
    @staticmethod
    def validate_domain(domain):
        """
        Validates domain format and prevents injection attacks
        Returns: (is_valid: bool, error_message: str)
        """
        if not domain or not isinstance(domain, str):
            return False, "Domain cannot be empty"
        
        # Remove whitespace and convert to lowercase
        domain = domain.strip().lower()
        
        # Check length
        if len(domain) > 253:
            return False, "Domain name too long (max 253 characters)"
        
        if len(domain) < 1:
            return False, "Domain name too short"
        
        # Check for valid domain pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(domain_pattern, domain):
            return False, "Invalid domain format"
        
        # Check for suspicious characters that could indicate injection
        suspicious_chars = ['<', '>', '"', "'", '&', ';', '|', '`', '$', '(', ')']
        if any(char in domain for char in suspicious_chars):
            return False, "Domain contains invalid characters"
        
        return True, domain
    
    @staticmethod
    def validate_wordlist_path(path):
        """
        Validates wordlist file path and accessibility
        Returns: (is_valid: bool, error_message: str, absolute_path: str)
        """
        if not path or not isinstance(path, str):
            return False, "Wordlist path cannot be empty", None
        
        try:
            # Convert to Path object for better handling
            wordlist_path = Path(path)
            
            # Check if file exists
            if not wordlist_path.exists():
                return False, f"Wordlist file not found: {path}", None
            
            # Check if it's a file (not directory)
            if not wordlist_path.is_file():
                return False, f"Path is not a file: {path}", None
            
            # Check file extension
            if not wordlist_path.suffix.lower() == '.txt':
                return False, "Wordlist must be a .txt file", None
            
            # Check file size (prevent extremely large files)
            file_size = wordlist_path.stat().st_size
            max_size = 100 * 1024 * 1024  # 100MB limit
            if file_size > max_size:
                return False, f"Wordlist file too large (max 100MB): {file_size/1024/1024:.1f}MB", None
            
            # Check if file is readable
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    # Try to read first line to verify format
                    first_line = f.readline()
                    if not first_line:
                        return False, "Wordlist file is empty", None
            except UnicodeDecodeError:
                return False, "Wordlist file contains invalid characters", None
            except PermissionError:
                return False, "Permission denied reading wordlist file", None
            
            return True, "Valid wordlist file", str(wordlist_path.absolute())
            
        except Exception as e:
            return False, f"Error validating wordlist: {str(e)}", None
    
    @staticmethod
    def validate_record_types(record_types):
        """
        Validates DNS record types selection
        Returns: (is_valid: bool, error_message: str, validated_types: list)
        """
        if not record_types:
            return False, "At least one record type must be selected", None
        
        valid_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR']
        validated_types = []
        
        for record_type in record_types:
            if not isinstance(record_type, str):
                return False, f"Invalid record type format: {record_type}", None
            
            record_type = record_type.upper().strip()
            if record_type not in valid_types:
                return False, f"Unsupported record type: {record_type}", None
            
            if record_type not in validated_types:
                validated_types.append(record_type)
        
        return True, "Valid record types", validated_types
    
    @staticmethod
    def sanitize_filename(filename):
        """
        Sanitizes filename for safe file operations
        Returns: sanitized filename string
        """
        if not filename:
            return "unnamed"
        
        # Remove or replace invalid filename characters
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        # Remove leading/trailing whitespace and dots
        filename = filename.strip(' .')
        
        # Limit length
        if len(filename) > 200:
            filename = filename[:200]
        
        # Ensure it's not empty after sanitization
        if not filename:
            filename = "unnamed"
        
        return filename