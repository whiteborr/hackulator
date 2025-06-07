# app/main_window.py
import os
from PyQt6.QtWidgets import QMainWindow
from PyQt6.QtCore import QSize
from PyQt6.QtGui import QFontDatabase

from app.theme_manager import ThemeManager
from app.widgets.animated_stacked_widget import AnimatedStackedWidget
from app.pages.home_page import HomePage
from app.pages.enumeration_page import EnumerationPage

class MainWindow(QMainWindow):
    def __init__(self, project_root):
        super().__init__()
        self.project_root = project_root
        self.setWindowTitle("Hackulator (PyQt6 Edition)")
        self.setFixedSize(QSize(1920, 1080))

        # **FIX**: Define the original design size here
        self.original_size = QSize(1024, 1024)

        self.load_custom_font()
        self.theme_manager = ThemeManager(project_root=self.project_root)

        self.stack = AnimatedStackedWidget(self)
        self.setCentralWidget(self.stack)

        self.home_page = HomePage(self)
        self.enum_page = EnumerationPage(self)

        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.enum_page)

        self.home_page.navigate_signal.connect(self.navigate_to)
        self.enum_page.navigate_signal.connect(self.navigate_to)
        
    def load_custom_font(self):
        """Loads a custom font from a file so it can be used in QSS."""
        font_path = os.path.join(self.project_root, "resources", "fonts", "neuropol.otf")
        font_id = QFontDatabase.addApplicationFont(font_path)
        if font_id == -1:
            print(f"WARNING: Could not load font at {font_path}")
        else:
            font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
            print(f"Custom font '{font_family}' loaded successfully.")

    def navigate_to(self, page_name):
        if page_name == "home":
            self.stack.animate_to_widget(self.home_page)
        elif page_name == "enumeration":
            self.stack.animate_to_widget(self.enum_page)
        else:
            print(f"Navigation request to unknown page: {page_name}")