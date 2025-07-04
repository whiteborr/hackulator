# app/core/advanced_theme_manager.py
import json
import os
from PyQt6.QtCore import QObject, pyqtSignal

class AdvancedThemeManager(QObject):
    """Manages advanced UI themes with multiple color schemes and styles.
    
    Provides theme management functionality including theme loading, application,
    and stylesheet generation for multiple color schemes (Dark, Light, Cyberpunk, etc.).
    
    Attributes:
        project_root (str): Root directory path for the project
        themes_dir (str): Directory containing theme resources
        current_theme (str): Currently active theme name
        available_themes (dict): Dictionary of available theme configurations
    
    Signals:
        theme_changed (str): Emitted when theme is successfully changed
    """
    
    theme_changed = pyqtSignal(str)
    
    def __init__(self, project_root):
        super().__init__()
        self.project_root = project_root
        self.themes_dir = os.path.join(project_root, "resources", "themes")
        self.current_theme = "dark"
        self.available_themes = self.load_available_themes()
        
    def load_available_themes(self):
        """Load all available theme configurations"""
        themes = {
            "dark": {
                "name": "Dark Theme",
                "primary": "#64C8FF",
                "background": "#0A0A0A",
                "surface": "rgba(20, 30, 40, 200)",
                "text": "#DCDCDC",
                "accent": "#FFAA00",
                "success": "#00FF41",
                "warning": "#FFAA00",
                "error": "#FF4500"
            },
            "light": {
                "name": "Light Theme", 
                "primary": "#2196F3",
                "background": "#FFFFFF",
                "surface": "rgba(240, 240, 240, 200)",
                "text": "#212121",
                "accent": "#FF9800",
                "success": "#4CAF50",
                "warning": "#FF9800",
                "error": "#F44336"
            },
            "cyberpunk": {
                "name": "Cyberpunk",
                "primary": "#00FFFF",
                "background": "#000000",
                "surface": "rgba(10, 0, 20, 200)",
                "text": "#00FF00",
                "accent": "#FF00FF",
                "success": "#00FF00",
                "warning": "#FFFF00",
                "error": "#FF0040"
            },
            "matrix": {
                "name": "Matrix",
                "primary": "#00FF41",
                "background": "#000000",
                "surface": "rgba(0, 20, 0, 200)",
                "text": "#00FF41",
                "accent": "#00AA00",
                "success": "#00FF41",
                "warning": "#AAFF00",
                "error": "#FF4400"
            },
            "ocean": {
                "name": "Ocean Blue",
                "primary": "#0077BE",
                "background": "#001122",
                "surface": "rgba(0, 30, 60, 200)",
                "text": "#E0F6FF",
                "accent": "#00AAFF",
                "success": "#00DDAA",
                "warning": "#FFAA00",
                "error": "#FF6B6B"
            }
        }
        return themes
        
    def get_available_themes(self):
        """Get list of available theme names"""
        return [(key, theme["name"]) for key, theme in self.available_themes.items()]
        
    def apply_theme(self, theme_name):
        """Apply selected theme to the application.
        
        Args:
            theme_name (str): Name of theme to apply
            
        Returns:
            bool: True if theme was applied successfully, False otherwise
        """
        if theme_name not in self.available_themes:
            return False
            
        self.current_theme = theme_name
        theme = self.available_themes[theme_name]
        
        # Generate stylesheet
        stylesheet = self.generate_stylesheet(theme)
        
        # Apply to application
        from PyQt6.QtWidgets import QApplication
        app = QApplication.instance()
        if app:
            app.setStyleSheet(stylesheet)
            
        self.theme_changed.emit(theme_name)
        return True
        
    def generate_stylesheet(self, theme):
        """Generate QSS stylesheet from theme colors.
        
        Args:
            theme (dict): Theme configuration dictionary containing color values
            
        Returns:
            str: Complete QSS stylesheet string for the theme
        """
        return f"""
        QMainWindow {{
            background-color: {theme['background']};
            color: {theme['text']};
        }}
        
        QFrame {{
            background-color: {theme['surface']};
            border: 1px solid {theme['primary']}40;
            border-radius: 8px;
        }}
        
        QPushButton {{
            background-color: {theme['surface']};
            border: 2px solid {theme['primary']}80;
            border-radius: 6px;
            color: {theme['text']};
            padding: 6px 12px;
            font-weight: bold;
        }}
        
        QPushButton:hover {{
            background-color: {theme['primary']}40;
            border: 2px solid {theme['primary']};
        }}
        
        QPushButton:pressed {{
            background-color: {theme['primary']}60;
        }}
        
        QLineEdit, QTextEdit, QComboBox {{
            background-color: {theme['surface']};
            border: 1px solid {theme['primary']}60;
            border-radius: 4px;
            color: {theme['text']};
            padding: 4px;
        }}
        
        QLineEdit:focus, QTextEdit:focus, QComboBox:focus {{
            border: 2px solid {theme['primary']};
        }}
        
        QLabel {{
            color: {theme['text']};
        }}
        
        QCheckBox {{
            color: {theme['text']};
        }}
        
        QCheckBox::indicator:checked {{
            background-color: {theme['primary']};
            border: 1px solid {theme['primary']};
        }}
        
        QMenuBar {{
            background-color: {theme['surface']};
            color: {theme['text']};
            border-bottom: 1px solid {theme['primary']}60;
        }}
        
        QMenuBar::item:selected {{
            background-color: {theme['primary']}60;
        }}
        
        QMenu {{
            background-color: {theme['surface']};
            color: {theme['text']};
            border: 1px solid {theme['primary']}60;
        }}
        
        QMenu::item:selected {{
            background-color: {theme['primary']}60;
        }}
        
        QStatusBar {{
            background-color: {theme['surface']};
            color: {theme['primary']};
            border-top: 1px solid {theme['primary']}60;
        }}
        """
        
    def get_current_theme(self):
        """Get current theme name"""
        return self.current_theme