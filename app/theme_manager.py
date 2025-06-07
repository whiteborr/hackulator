# app/theme_manager.py
import json
from pathlib import Path

class ThemeManager:
    # Accept the absolute project_root path
    def __init__(self, project_root, theme_folder="resources/themes", default_theme="default"):
        self.project_root = Path(project_root)
        self.themes_path = self.project_root / theme_folder
        self.theme_data = {}
        self.load_theme(default_theme)

    def load_theme(self, theme_name):
        """Loads a theme and converts all resource paths to absolute paths."""
        theme_path = self.themes_path / theme_name / "theme.json"
        try:
            with open(theme_path, 'r') as f:
                self.theme_data = json.load(f)
            print(f"Theme '{theme_name}' loaded successfully.")

            # **FIX**: Convert relative image paths from JSON to absolute paths
            for category in self.theme_data.values():
                if isinstance(category, dict):
                    for key, value in category.items():
                        if isinstance(value, str) and value.endswith('.png'):
                            # Create an absolute path from the project root and the relative path
                            absolute_path = self.project_root / value
                            # Store the path with forward slashes, which is best for Qt stylesheets
                            category[key] = str(absolute_path).replace('\\', '/')
                            
        except FileNotFoundError:
            print(f"ERROR: Theme file not found at {theme_path}")
            self.theme_data = {}

    def get(self, key_path):
        """Gets a value from the theme data using a 'dot.path' key."""
        keys = key_path.split('.')
        value = self.theme_data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value