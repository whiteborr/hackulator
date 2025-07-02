# app/widgets/drag_drop_combo.py
from PyQt6.QtWidgets import QComboBox
from PyQt6.QtCore import pyqtSignal
from app.core.drag_drop_handler import DragDropMixin
import os

class DragDropComboBox(QComboBox, DragDropMixin):
    """ComboBox with drag and drop support for wordlist files"""
    
    file_dropped = pyqtSignal(str)  # Signal when file is dropped
    
    def __init__(self, parent=None):
        QComboBox.__init__(self, parent)
        DragDropMixin.__init__(self)
        self.supported_extensions = ['.txt']  # Only text files for wordlists
        self.set_drop_callback(self.handle_wordlist_drop)
    
    def handle_wordlist_drop(self, file_paths):
        """Handle dropped wordlist files"""
        for file_path in file_paths:
            if self._is_wordlist_file(file_path):
                # Add to combo box if not already present
                file_name = os.path.basename(file_path)
                
                # Check if already in combo
                existing_index = -1
                for i in range(self.count()):
                    if self.itemData(i) == file_path:
                        existing_index = i
                        break
                
                if existing_index == -1:
                    # Add new item
                    self.addItem(f"📁 {file_name}", file_path)
                    self.setCurrentIndex(self.count() - 1)
                else:
                    # Select existing item
                    self.setCurrentIndex(existing_index)
                
                self.file_dropped.emit(file_path)
                break  # Only process first valid file
    
    def _is_wordlist_file(self, file_path):
        """Check if file is a valid wordlist"""
        if not self._is_valid_file(file_path):
            return False
        
        try:
            # Quick validation - check if file has reasonable content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[:10]  # Check first 10 lines
                return len(lines) > 0 and all(len(line.strip()) > 0 for line in lines if line.strip())
        except:
            return False