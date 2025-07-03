# app/main_window_refactored.py
import os
from PyQt6.QtWidgets import QMainWindow, QStatusBar, QMenuBar, QMenu, QSystemTrayIcon
from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QFontDatabase, QAction, QKeySequence
from PyQt6.QtWidgets import QApplication

from app.theme_manager import ThemeManager
from app.core.advanced_theme_manager import AdvancedThemeManager
from app.widgets.animated_stacked_widget import AnimatedStackedWidget
from app.pages.home_page import HomePage
from app.pages.enumeration_page import EnumerationPage
from app.pages.vuln_scanning_page import VulnScanningPage
from app.pages.web_exploits_page import WebExploitsPage
from app.pages.db_attacks_page import DbAttacksPage
from app.pages.os_exploits_page import OSExploitsPage
from app.pages.cracking_page import CrackingPage
from app.pages.osint_page import OSINTPage
from app.pages.findings_page import FindingsPage
from app.pages.owasp_api_page import OWASPAPIPage
from app.pages.scripts_page import ScriptsPage
from app.core.system_tray import SystemTrayManager

class MainWindow(QMainWindow):
    def __init__(self, project_root):
        super().__init__()
        self.project_root = project_root
        self.setWindowTitle("Hackulator (PyQt6 Edition) - Layout Version")
        
        # Set minimum size instead of fixed size for responsiveness
        self.setMinimumSize(QSize(1200, 800))
        self.resize(QSize(1600, 1000))  # Default size
        
        # Enable window resizing
        self.setWindowFlags(Qt.WindowType.Window)
        
        self.load_custom_font()
        self.theme_manager = ThemeManager(project_root=self.project_root)
        self.advanced_theme_manager = AdvancedThemeManager(self.project_root)
        self.advanced_theme_manager.theme_changed.connect(self.on_theme_changed)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar with memory widget
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background-color: rgba(20, 30, 40, 200);
                color: #64C8FF;
                border-top: 1px solid rgba(100, 200, 255, 100);
                font-size: 11pt;
                padding: 2px;
            }
        """)
        
        # Add memory widget to status bar
        from app.widgets.memory_widget import MemoryWidget
        memory_widget = MemoryWidget()
        self.status_bar.addPermanentWidget(memory_widget)
        
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - Hackulator Layout Version")
        
        # Create central widget with stacked layout
        self.stack = AnimatedStackedWidget(self)
        self.setCentralWidget(self.stack)
        
        # Create pages
        self.home_page = HomePage(self)
        self.enum_page = EnumerationPage(self)
        self.vuln_page = VulnScanningPage(self)
        self.web_exploits_page = WebExploitsPage(self)
        self.db_attacks_page = DbAttacksPage(self)
        self.os_exploits_page = OSExploitsPage(self)
        self.cracking_page = CrackingPage(self)
        self.osint_page = OSINTPage(self)
        self.findings_page = FindingsPage(self)
        self.owasp_api_page = OWASPAPIPage(self)
        self.scripts_page = ScriptsPage(self)
        
        # Apply font to all widgets after creation
        if hasattr(self, 'neuropol_family') and self.neuropol_family:
            from PyQt6.QtGui import QFont
            neuropol_font = QFont(self.neuropol_family)
            self.setFont(neuropol_font)
            self.home_page.setFont(neuropol_font)
            self.enum_page.setFont(neuropol_font)
        
        # Add pages to stack
        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.enum_page)
        self.stack.addWidget(self.vuln_page)
        self.stack.addWidget(self.web_exploits_page)
        self.stack.addWidget(self.db_attacks_page)
        self.stack.addWidget(self.os_exploits_page)
        self.stack.addWidget(self.cracking_page)
        self.stack.addWidget(self.osint_page)
        self.stack.addWidget(self.findings_page)
        self.stack.addWidget(self.owasp_api_page)
        self.stack.addWidget(self.scripts_page)
        
        # Connect navigation signals
        self.home_page.navigate_signal.connect(self.navigate_to)
        self.enum_page.navigate_signal.connect(self.navigate_to)
        self.vuln_page.navigate_signal.connect(self.navigate_to)
        self.web_exploits_page.navigate_signal.connect(self.navigate_to)
        self.db_attacks_page.navigate_signal.connect(self.navigate_to)
        self.os_exploits_page.navigate_signal.connect(self.navigate_to)
        self.cracking_page.navigate_signal.connect(self.navigate_to)
        self.osint_page.navigate_signal.connect(self.navigate_to)
        self.findings_page.navigate_signal.connect(self.navigate_to)
        self.owasp_api_page.navigate_signal.connect(self.navigate_to)
        self.scripts_page.navigate_signal.connect(self.navigate_to)
        
        # Connect status signals
        self.home_page.status_updated.connect(self.update_status_bar)
        self.enum_page.status_updated.connect(self.update_status_bar)
        
        # Apply global styling
        self.apply_global_styling()
        
        # Initialize system tray
        self.setup_system_tray()
        
        # Apply initial advanced theme
        self.advanced_theme_manager.apply_theme('dark')
        
    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: rgba(20, 30, 40, 200);
                color: #DCDCDC;
                border-bottom: 1px solid rgba(100, 200, 255, 100);
                font-size: 11pt;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 4px 8px;
            }
            QMenuBar::item:selected {
                background-color: rgba(100, 200, 255, 100);
                border-radius: 4px;
            }
            QMenu {
                background-color: rgba(30, 40, 50, 240);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
            }
            QMenu::item {
                padding: 6px 12px;
            }
            QMenu::item:selected {
                background-color: rgba(100, 200, 255, 150);
            }
        """)
        
        # File menu
        file_menu = menubar.addMenu('&File')
        
        # Export action
        export_action = QAction('&Export Results', self)
        export_action.setShortcut(QKeySequence('Ctrl+E'))
        export_action.setStatusTip('Export scan results')
        export_action.triggered.connect(self.export_current_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        # Exit action
        exit_action = QAction('E&xit', self)
        exit_action.setShortcut(QKeySequence('Ctrl+Q'))
        exit_action.setStatusTip('Exit application')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu('&View')
        
        # Fullscreen action
        fullscreen_action = QAction('&Fullscreen', self)
        fullscreen_action.setShortcut(QKeySequence('F11'))
        fullscreen_action.setStatusTip('Toggle fullscreen mode')
        fullscreen_action.setCheckable(True)
        fullscreen_action.triggered.connect(self.toggle_fullscreen)
        view_menu.addAction(fullscreen_action)
        
        view_menu.addSeparator()
        
        # Theme submenu
        theme_menu = view_menu.addMenu('&Themes')
        
        # Quick theme actions
        dark_action = QAction('&Dark Theme', self)
        dark_action.triggered.connect(lambda: self.advanced_theme_manager.apply_theme('dark'))
        theme_menu.addAction(dark_action)
        
        light_action = QAction('&Light Theme', self)
        light_action.triggered.connect(lambda: self.advanced_theme_manager.apply_theme('light'))
        theme_menu.addAction(light_action)
        
        cyberpunk_action = QAction('&Cyberpunk Theme', self)
        cyberpunk_action.triggered.connect(lambda: self.advanced_theme_manager.apply_theme('cyberpunk'))
        theme_menu.addAction(cyberpunk_action)
        
        view_menu.addSeparator()
        
        # Minimize to tray action
        minimize_tray_action = QAction('&Minimize to Tray', self)
        minimize_tray_action.setShortcut(QKeySequence('Ctrl+M'))
        minimize_tray_action.setStatusTip('Minimize application to system tray')
        minimize_tray_action.triggered.connect(self.minimize_to_tray)
        view_menu.addAction(minimize_tray_action)
        
        # Clear output action
        clear_action = QAction('&Clear Output', self)
        clear_action.setShortcut(QKeySequence('Ctrl+L'))
        clear_action.setStatusTip('Clear terminal output')
        clear_action.triggered.connect(self.clear_current_output)
        view_menu.addAction(clear_action)
        
        # Help menu
        help_menu = menubar.addMenu('&Help')
        
        # About action
        about_action = QAction('&About', self)
        about_action.setStatusTip('About Hackulator')
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def apply_global_styling(self):
        """Apply global application styling"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0A0A0A;
            }
            
            /* Scrollbars */
            QScrollBar:vertical {
                background-color: rgba(50, 50, 50, 100);
                width: 12px;
                border-radius: 6px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: rgba(100, 200, 255, 150);
                border-radius: 6px;
                min-height: 20px;
                margin: 2px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: rgba(100, 200, 255, 200);
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            
            QScrollBar:horizontal {
                background-color: rgba(50, 50, 50, 100);
                height: 12px;
                border-radius: 6px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background-color: rgba(100, 200, 255, 150);
                border-radius: 6px;
                min-width: 20px;
                margin: 2px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: rgba(100, 200, 255, 200);
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
        """)
        
    def load_custom_font(self):
        """Load custom font for the application"""
        font_path = os.path.join(self.project_root, "resources", "fonts", "neuropol.otf")
        font_id = QFontDatabase.addApplicationFont(font_path)
        if font_id == -1:
            print(f"WARNING: Could not load font at {font_path}")
            self.neuropol_family = None
        else:
            self.neuropol_family = QFontDatabase.applicationFontFamilies(font_id)[0]
            print(f"Custom font '{self.neuropol_family}' loaded successfully.")
            
            # Set as application default font
            from PyQt6.QtGui import QFont
            app_font = QFont(self.neuropol_family, 12)
            QApplication.instance().setFont(app_font)
            
            # Force font on all widgets
            self.setStyleSheet(f"""
                QWidget {{
                    font-family: "{self.neuropol_family}";
                }}
                QLabel {{
                    font-family: "{self.neuropol_family}";
                }}
                QPushButton {{
                    font-family: "{self.neuropol_family}";
                }}
            """)
            
    def navigate_to(self, page_name):
        """Navigate to a specific page"""
        self.status_bar.showMessage(f"Navigating to {page_name}...")
        
        if page_name == "home":
            self.stack.animate_to_widget(self.home_page)
            self.status_bar.showMessage("Home - Select a tool to get started")
        elif page_name == "enumeration":
            self.stack.animate_to_widget(self.enum_page)
            self.status_bar.showMessage("Enumeration Tools - Select a tool from the left panel")
        elif page_name == "vuln_scanning":
            self.stack.animate_to_widget(self.vuln_page)
            self.status_bar.showMessage("Vulnerability Scanning Tools")
        elif page_name == "web_exploits":
            self.stack.animate_to_widget(self.web_exploits_page)
            self.status_bar.showMessage("Web Application Exploits")
        elif page_name == "databases":
            self.stack.animate_to_widget(self.db_attacks_page)
            self.status_bar.showMessage("Database Attack Tools")
        elif page_name == "os_exploits":
            self.stack.animate_to_widget(self.os_exploits_page)
            self.status_bar.showMessage("Operating System Exploits")
        elif page_name == "cracking":
            self.stack.animate_to_widget(self.cracking_page)
            self.status_bar.showMessage("Password Cracking Tools")
        elif page_name == "osint":
            self.stack.animate_to_widget(self.osint_page)
            self.status_bar.showMessage("OSINT & Reconnaissance Tools")
        elif page_name == "findings":
            self.stack.animate_to_widget(self.findings_page)
            self.status_bar.showMessage("Common Pentest Findings")
        elif page_name == "owasp_api":
            self.stack.animate_to_widget(self.owasp_api_page)
            self.status_bar.showMessage("OWASP API Security Top 10")
        elif page_name == "scripts":
            self.stack.animate_to_widget(self.scripts_page)
            self.status_bar.showMessage("Scripts & Tools")
        else:
            print(f"Navigation request to unknown page: {page_name}")
            self.status_bar.showMessage(f"Unknown page: {page_name}")
            
    def export_current_results(self):
        """Export results from current page"""
        current_widget = self.stack.currentWidget()
        if hasattr(current_widget, 'export_results'):
            current_widget.export_results()
        else:
            self.status_bar.showMessage("No exportable results on current page")
            
    def clear_current_output(self):
        """Clear output on current page"""
        current_widget = self.stack.currentWidget()
        if hasattr(current_widget, 'clear_terminal'):
            current_widget.clear_terminal()
        elif hasattr(current_widget, 'terminal_output'):
            current_widget.terminal_output.clear()
        else:
            self.status_bar.showMessage("No output to clear on current page")
            
    def toggle_fullscreen(self):
        """Toggle fullscreen mode"""
        if self.isFullScreen():
            self.showNormal()
            self.status_bar.showMessage("Exited fullscreen mode")
        else:
            self.showFullScreen()
            self.status_bar.showMessage("Entered fullscreen mode - Press F11 to exit")
            
    def show_about(self):
        """Show about dialog"""
        from PyQt6.QtWidgets import QMessageBox
        
        about_text = """
        <h2>Hackulator (Layout Version)</h2>
        <p><b>Version:</b> 2.0 (Layout-Based)</p>
        <p><b>Description:</b> A comprehensive cybersecurity toolkit with responsive UI</p>
        <p><b>Features:</b></p>
        <ul>
            <li>Dynamic layout system</li>
            <li>Responsive design</li>
            <li>Comprehensive enumeration tools</li>
            <li>Vulnerability scanning</li>
            <li>Export capabilities</li>
            <li>Keyboard shortcuts</li>
        </ul>
        <p><b>Keyboard Shortcuts:</b></p>
        <ul>
            <li>F5 - Run current tool</li>
            <li>Ctrl+E - Export results</li>
            <li>Ctrl+L - Clear output</li>
            <li>Ctrl+M - Minimize to tray</li>
            <li>F11 - Toggle fullscreen</li>
            <li>View Menu - Quick theme switching</li>
            <li>Escape - Go back</li>
        </ul>
        """
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("About Hackulator")
        msg_box.setText(about_text)
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: rgba(20, 30, 40, 240);
                color: #DCDCDC;
            }
            QMessageBox QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QMessageBox QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """)
        msg_box.exec()
        
    def resizeEvent(self, event):
        """Handle window resize events"""
        super().resizeEvent(event)
        if event:
            # Update status bar with current size
            size = event.size()
            self.status_bar.showMessage(f"Window size: {size.width()}x{size.height()}")
            
    def update_status_bar(self, message):
        """Update status bar with message from child widgets"""
        self.status_bar.showMessage(message)
        
    def setup_system_tray(self):
        """Initialize system tray functionality"""
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_manager = SystemTrayManager(self, self.project_root)
            if self.tray_manager.setup_tray():
                self.tray_manager.show_tray()
                self.status_bar.showMessage("System tray integration enabled")
            else:
                self.tray_manager = None
                self.status_bar.showMessage("System tray not available")
        else:
            self.tray_manager = None
            self.status_bar.showMessage("System tray not supported on this system")
            
    def minimize_to_tray(self):
        """Minimize application to system tray"""
        if self.tray_manager and self.tray_manager.is_available():
            self.hide()
            self.tray_manager.show_message(
                "Hackulator", 
                "Application minimized to tray. Double-click to restore.",
                QSystemTrayIcon.MessageIcon.Information
            )
            self.status_bar.showMessage("Minimized to system tray")
        else:
            self.showMinimized()
            self.status_bar.showMessage("System tray not available - minimized to taskbar")
            
    def changeEvent(self, event):
        """Handle window state changes"""
        if event.type() == event.Type.WindowStateChange:
            if self.isMinimized() and self.tray_manager and self.tray_manager.is_available():
                # Auto-minimize to tray when minimized
                self.hide()
                event.ignore()
                return
        super().changeEvent(event)
        
    def closeEvent(self, event):
        """Handle application close event"""
        if self.tray_manager and self.tray_manager.is_available():
            # Ask user if they want to minimize to tray instead of closing
            from PyQt6.QtWidgets import QMessageBox
            reply = QMessageBox.question(
                self, 'Hackulator', 
                "Close to system tray instead of exiting?\n\n"
                "Click 'Yes' to minimize to tray\n"
                "Click 'No' to exit completely",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.hide()
                self.tray_manager.show_message(
                    "Hackulator", 
                    "Application closed to tray. Right-click tray icon to quit.",
                    QSystemTrayIcon.MessageIcon.Information
                )
                event.ignore()
                return
                
        self.status_bar.showMessage("Closing application...")
        # Stop memory monitoring
        from app.core.memory_manager import memory_manager
        memory_manager.stop_monitoring()
        
        # Hide tray icon
        if self.tray_manager:
            self.tray_manager.hide_tray()
            
        event.accept()
        
    def on_theme_changed(self, theme_name):
        """Handle theme change event"""
        theme_display_name = self.advanced_theme_manager.available_themes[theme_name]['name']
        self.status_bar.showMessage(f"Theme changed to: {theme_display_name}")