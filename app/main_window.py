# app/main_window.py
import os
from PyQt6.QtWidgets import QMainWindow
from PyQt6.QtCore import QSize
from PyQt6.QtGui import QFontDatabase

from app.theme_manager import ThemeManager
from app.core.theme_manager import theme_manager as new_theme_manager
from app.core.shortcut_manager import ShortcutManager, shortcut_manager
from app.widgets.animated_stacked_widget import AnimatedStackedWidget
from app.pages.home_page import HomePage
from app.pages.enumeration_page import EnumerationPage
from app.pages.vuln_scanning_page import VulnScanningPage
from app.pages.web_exploits_page import WebExploitsPage
from app.pages.db_attacks_page import DbAttacksPage
from app.pages.os_exploits_page import OSExploitsPage
from app.pages.cracking_page import CrackingPage

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
        self.vuln_page = VulnScanningPage(self)
        self.web_exploits_page = WebExploitsPage(self)
        self.db_attacks_page = DbAttacksPage(self)
        self.os_exploits_page = OSExploitsPage(self)
        self.cracking_page = CrackingPage(self)

        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.enum_page)
        self.stack.addWidget(self.vuln_page)
        self.stack.addWidget(self.web_exploits_page)
        self.stack.addWidget(self.db_attacks_page)
        self.stack.addWidget(self.os_exploits_page)
        self.stack.addWidget(self.cracking_page)

        self.home_page.navigate_signal.connect(self.navigate_to)
        self.enum_page.navigate_signal.connect(self.navigate_to)
        self.vuln_page.navigate_signal.connect(self.navigate_to)
        self.web_exploits_page.navigate_signal.connect(self.navigate_to)
        self.db_attacks_page.navigate_signal.connect(self.navigate_to)
        self.os_exploits_page.navigate_signal.connect(self.navigate_to)
        self.cracking_page.navigate_signal.connect(self.navigate_to)
        
        # Apply initial theme
        new_theme_manager.apply_theme()
        
        # Setup global shortcuts
        global shortcut_manager
        shortcut_manager = ShortcutManager(self)
        shortcut_manager.quit_app.connect(self.close)
        
    def load_custom_font(self):
        """Loads a custom font from a file so it can be used in QSS."""
        font_path = os.path.join(self.project_root, "resources", "fonts", "neuropol.otf")
        font_id = QFontDatabase.addApplicationFont(font_path)
        if font_id == -1:
            print(f"WARNING: Could not load font at {font_path}")
        else:
            font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
            print(f"Custom font '{font_family}' loaded successfully.")
            
            # Set as application default font
            from PyQt6.QtGui import QFont
            from PyQt6.QtWidgets import QApplication
            app_font = QFont(font_family, 12)
            QApplication.instance().setFont(app_font)

    def navigate_to(self, page_name):
        if page_name == "home":
            self.stack.animate_to_widget(self.home_page)
        elif page_name == "enumeration":
            self.stack.animate_to_widget(self.enum_page)
        elif page_name == "vuln_scanning":
            self.stack.animate_to_widget(self.vuln_page)
        elif page_name == "web_exploits":
            self.stack.animate_to_widget(self.web_exploits_page)
        elif page_name == "databases":
            self.stack.animate_to_widget(self.db_attacks_page)
        elif page_name == "os_exploits":
            self.stack.animate_to_widget(self.os_exploits_page)
        elif page_name == "cracking":
            self.stack.animate_to_widget(self.cracking_page)
        else:
            print(f"Navigation request to unknown page: {page_name}")