# Hackulator API Documentation

## Core Components

### InputValidator
```python
from app.core.validators import InputValidator

validator = InputValidator()
validator.validate_ip("192.168.1.1")      # Returns True
validator.validate_domain("example.com")   # Returns True
```

### CacheManager
```python
from app.core.cache_manager import cache_manager

# Store results
cache_manager.set("dns", "example.com", {"A": ["1.2.3.4"]})

# Retrieve results
results = cache_manager.get("dns", "example.com")

# Clear cache
cache_manager.clear()
```

### AdvancedThemeManager
```python
from app.core.advanced_theme_manager import AdvancedThemeManager

theme_manager = AdvancedThemeManager(project_root)
theme_manager.apply_theme("cyberpunk")
themes = theme_manager.get_available_themes()
```

### ContextMenuManager
```python
from app.core.context_menu_manager import ContextMenuManager

context_manager = ContextMenuManager()
menu = context_manager.create_terminal_menu(widget, selected_text)
```

## Enumeration Tools

### DNS Enumeration
```python
import custom_scripts

custom_scripts.enumerate_hostnames(
    target="example.com",
    wordlist_path="wordlist.txt",
    record_types=["A", "CNAME"],
    output_callback=print_output,
    finished_callback=on_complete
)
```

## Export System

### Basic Export
```python
from app.core.exporter import exporter

success, filepath, message = exporter.export_results(
    results, target, "json"
)
```

## Database Operations

### Scan Database
```python
from app.core.scan_database import scan_db

# Save scan
scan_id = scan_db.save_scan(target, scan_type, results)

# Retrieve scan
scan = scan_db.get_scan(scan_id)
```