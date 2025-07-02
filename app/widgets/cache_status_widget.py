# app/widgets/cache_status_widget.py
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel, QPushButton
from PyQt6.QtCore import Qt
from app.core.cache_manager import cache_manager

class CacheStatusWidget(QWidget):
    """Simple widget to show cache status and clear cache"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Cache status label
        self.status_label = QLabel("Cache: Ready")
        self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt;")
        
        # Clear cache button
        clear_btn = QPushButton("Clear Cache")
        clear_btn.setFixedSize(80, 25)
        clear_btn.clicked.connect(self.clear_cache)
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 100, 100, 150);
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 9pt;
            }
            QPushButton:hover {
                background-color: rgba(255, 100, 100, 200);
            }
        """)
        
        layout.addWidget(self.status_label)
        layout.addStretch()
        layout.addWidget(clear_btn)
        
    def update_status(self, message):
        """Update cache status message"""
        self.status_label.setText(f"Cache: {message}")
        
    def clear_cache(self):
        """Clear all cached results"""
        cache_manager.clear_expired()
        # Clear all cache files
        for cache_file in cache_manager.cache_dir.glob("*.json"):
            cache_file.unlink()
        self.update_status("Cleared")