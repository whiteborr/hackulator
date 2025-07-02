# app/core/shortcut_manager.py
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QShortcut, QKeySequence
from PyQt6.QtCore import QObject, pyqtSignal

class ShortcutManager(QObject):
    """Manage application keyboard shortcuts"""
    
    # Signals for shortcut actions
    new_scan = pyqtSignal()
    export_results = pyqtSignal()
    toggle_theme = pyqtSignal()
    show_help = pyqtSignal()
    quit_app = pyqtSignal()
    pause_scan = pyqtSignal()
    stop_scan = pyqtSignal()
    multi_target = pyqtSignal()
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.shortcuts = {}
        self.setup_shortcuts()
    
    def setup_shortcuts(self):
        """Setup all keyboard shortcuts"""
        shortcuts_config = {
            'Ctrl+N': ('new_scan', 'Start New Scan'),
            'Ctrl+E': ('export_results', 'Export Results'),
            'Ctrl+T': ('toggle_theme', 'Toggle Theme'),
            'F1': ('show_help', 'Show Help'),
            'Ctrl+Q': ('quit_app', 'Quit Application'),
            'Ctrl+P': ('pause_scan', 'Pause/Resume Scan'),
            'Ctrl+S': ('stop_scan', 'Stop Scan'),
            'Ctrl+M': ('multi_target', 'Multi-Target Scan'),
            'Escape': ('stop_scan', 'Stop Current Operation')
        }
        
        for key_combo, (signal_name, description) in shortcuts_config.items():
            shortcut = QShortcut(QKeySequence(key_combo), self.main_window)
            signal = getattr(self, signal_name)
            shortcut.activated.connect(signal.emit)
            
            self.shortcuts[key_combo] = {
                'shortcut': shortcut,
                'signal': signal_name,
                'description': description
            }
    
    def get_shortcuts_list(self) -> list:
        """Get list of all shortcuts for help display"""
        return [
            {'key': key, 'description': info['description']}
            for key, info in self.shortcuts.items()
        ]
    
    def enable_shortcuts(self):
        """Enable all shortcuts"""
        for info in self.shortcuts.values():
            info['shortcut'].setEnabled(True)
    
    def disable_shortcuts(self):
        """Disable all shortcuts"""
        for info in self.shortcuts.values():
            info['shortcut'].setEnabled(False)

# Global instance (will be initialized with main window)
shortcut_manager = None