# app/core/theme_manager.py
import json
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QObject, pyqtSignal

class ThemeManager(QObject):
    """Manage application themes"""
    
    theme_changed = pyqtSignal(str)  # Signal when theme changes
    
    def __init__(self):
        super().__init__()
        self.current_theme = "dark"
        self.themes_file = "theme_settings.json"
        self.load_theme_preference()
        
        self.themes = {
            "dark": {
                "name": "Dark Theme",
                "background": "#1e1e1e",
                "surface": "#2d2d2d",
                "primary": "#64C8FF",
                "secondary": "#00FF41",
                "accent": "#FFAA00",
                "text": "#DCDCDC",
                "text_secondary": "#888888",
                "border": "#555555",
                "success": "#00AA00",
                "warning": "#FF6600",
                "error": "#FF4444"
            },
            "light": {
                "name": "Light Theme",
                "background": "#ffffff",
                "surface": "#f5f5f5",
                "primary": "#2196F3",
                "secondary": "#4CAF50",
                "accent": "#FF9800",
                "text": "#212121",
                "text_secondary": "#757575",
                "border": "#e0e0e0",
                "success": "#4CAF50",
                "warning": "#FF9800",
                "error": "#F44336"
            }
        }
    
    def get_current_theme(self) -> str:
        """Get current theme name"""
        return self.current_theme
    
    def get_theme_colors(self, theme_name: str = None) -> dict:
        """Get theme color palette"""
        theme_name = theme_name or self.current_theme
        return self.themes.get(theme_name, self.themes["dark"])
    
    def set_theme(self, theme_name: str):
        """Set application theme"""
        if theme_name in self.themes:
            self.current_theme = theme_name
            self.save_theme_preference()
            self.apply_theme()
            self.theme_changed.emit(theme_name)
    
    def toggle_theme(self):
        """Toggle between dark and light themes"""
        new_theme = "light" if self.current_theme == "dark" else "dark"
        self.set_theme(new_theme)
    
    def apply_theme(self):
        """Apply current theme to application"""
        colors = self.get_theme_colors()
        
        stylesheet = f"""
        QMainWindow {{
            background-color: {colors['background']};
            color: {colors['text']};
        }}
        
        QWidget {{
            background-color: {colors['background']};
            color: {colors['text']};
        }}
        
        QGroupBox {{
            color: {colors['primary']};
            border: 2px solid {colors['border']};
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
            font-weight: bold;
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }}
        
        QLineEdit {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            padding: 4px 8px;
            font-size: 10pt;
        }}
        
        QLineEdit:focus {{
            border: 2px solid {colors['primary']};
        }}
        
        QTextEdit {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            font-size: 10pt;
            padding: 8px;
        }}
        
        QPushButton {{
            background-color: {colors['primary']};
            color: white;
            border: none;
            border-radius: 4px;
            padding: 6px 12px;
            font-size: 10pt;
        }}
        
        QPushButton:hover {{
            background-color: {colors['accent']};
        }}
        
        QPushButton:disabled {{
            background-color: {colors['text_secondary']};
            color: {colors['border']};
        }}
        
        QComboBox {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            padding: 4px 8px;
        }}
        
        QComboBox::drop-down {{
            border: none;
        }}
        
        QComboBox::down-arrow {{
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid {colors['text']};
        }}
        
        QTableWidget {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            gridline-color: {colors['border']};
        }}
        
        QHeaderView::section {{
            background-color: {colors['primary']};
            color: white;
            padding: 4px;
            border: none;
            font-weight: bold;
        }}
        
        QProgressBar {{
            border: 1px solid {colors['border']};
            border-radius: 4px;
            text-align: center;
            color: {colors['text']};
            font-weight: bold;
        }}
        
        QProgressBar::chunk {{
            background-color: {colors['primary']};
            border-radius: 3px;
        }}
        
        QCheckBox {{
            color: {colors['text']};
        }}
        
        QCheckBox::indicator:checked {{
            background-color: {colors['primary']};
            border: 1px solid {colors['primary']};
        }}
        
        QCheckBox::indicator:unchecked {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
        }}
        
        QLabel {{
            color: {colors['text']};
        }}
        
        QTabWidget::pane {{
            border: 1px solid {colors['border']};
            background-color: {colors['surface']};
        }}
        
        QTabBar::tab {{
            background-color: {colors['surface']};
            color: {colors['text']};
            padding: 8px 12px;
            margin-right: 2px;
            border-radius: 4px 4px 0px 0px;
        }}
        
        QTabBar::tab:selected {{
            background-color: {colors['primary']};
            color: white;
        }}
        """
        
        app = QApplication.instance()
        if app:
            app.setStyleSheet(stylesheet)
    
    def save_theme_preference(self):
        """Save theme preference to file"""
        try:
            with open(self.themes_file, 'w') as f:
                json.dump({"theme": self.current_theme}, f)
        except Exception:
            pass
    
    def load_theme_preference(self):
        """Load theme preference from file"""
        try:
            if os.path.exists(self.themes_file):
                with open(self.themes_file, 'r') as f:
                    data = json.load(f)
                    self.current_theme = data.get("theme", "dark")
        except Exception:
            self.current_theme = "dark"

# Global instance
theme_manager = ThemeManager()