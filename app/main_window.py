# app/main_window_refactored.py
import os
from PyQt6.QtWidgets import QMainWindow, QStatusBar, QMenuBar, QMenu, QSystemTrayIcon
from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QFontDatabase, QAction, QKeySequence
from PyQt6.QtWidgets import QApplication

from app.core.unified_theme_manager import get_theme_manager
from app.ui.animations.background_effects import BackgroundEffectManager
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
from app.pages.running_scans_page import RunningScansPage
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
        self.theme_manager = get_theme_manager(self.project_root)
        self.theme_manager.theme_changed.connect(self.on_theme_changed)
        # self.theme_manager.theme_locked.connect(self.show_theme_upgrade_dialog)  # Removed - not needed
        
        # Initialize background effects manager
        self.background_effects = BackgroundEffectManager(self)
        
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
        self.running_scans_page = RunningScansPage(self)
        
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
        self.stack.addWidget(self.running_scans_page)
        
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
        self.running_scans_page.navigate_signal.connect(self.navigate_to)
        
        # Connect status signals
        self.home_page.status_updated.connect(self.update_status_bar)
        self.enum_page.status_updated.connect(self.update_status_bar)
        self.running_scans_page.status_updated.connect(self.update_status_bar)
        
        # Apply global styling
        self.apply_global_styling()
        
        # Initialize system tray
        self.setup_system_tray()
        
        # Initialize enhanced help panel
        from app.widgets.enhanced_help_panel import EnhancedHelpPanel
        self.enhanced_help_panel = EnhancedHelpPanel(self)
        self.enhanced_help_panel.hide()
        
        # Initialize license manager
        from app.core.license_manager import license_manager
        license_manager.check_license_expiry()
        
        # Apply initial theme
        self.theme_manager.apply_theme()
        
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
        
        # License action
        license_action = QAction('&License Manager', self)
        license_action.setStatusTip('Manage professional license')
        license_action.triggered.connect(self.open_license_manager)
        file_menu.addAction(license_action)
        
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
        
        # Theme selector action
        theme_selector_action = QAction('&Theme Selector...', self)
        theme_selector_action.setShortcut(QKeySequence('Ctrl+T'))
        theme_selector_action.setStatusTip('Open enhanced theme selector')
        theme_selector_action.triggered.connect(self.open_theme_selector)
        theme_menu.addAction(theme_selector_action)
        
        theme_menu.addSeparator()
        
        # Quick theme actions (available themes only)
        for theme_key, theme_name in self.theme_manager.get_available_themes():
            action = QAction(f'&{theme_name}', self)
            action.triggered.connect(lambda checked, key=theme_key: self.theme_manager.set_theme(key))
            theme_menu.addAction(action)
        
        view_menu.addSeparator()
        
        # Running Scans action
        running_scans_action = QAction('&Running Scans...', self)
        running_scans_action.setShortcut(QKeySequence('Ctrl+Shift+R'))
        running_scans_action.setStatusTip('Monitor and control active scans')
        running_scans_action.triggered.connect(self.show_running_scans)
        view_menu.addAction(running_scans_action)
        
        # Sessions action
        sessions_action = QAction('&Sessions', self)
        sessions_action.setShortcut(QKeySequence('Ctrl+Shift+S'))
        sessions_action.setStatusTip('Manage scanning sessions')
        sessions_action.triggered.connect(self.open_sessions_dialog)
        view_menu.addAction(sessions_action)
        
        # Reports action
        reports_action = QAction('&Reports', self)
        reports_action.setShortcut(QKeySequence('Ctrl+R'))
        reports_action.setStatusTip('Generate advanced reports from file')
        reports_action.triggered.connect(self.open_reports_dialog)
        view_menu.addAction(reports_action)
        
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
        
        view_menu.addSeparator()
        
        # Professional Features submenu
        pro_menu = view_menu.addMenu('&Professional Features')
        
        # Stealth Mode action
        stealth_action = QAction('&Stealth Mode', self)
        stealth_action.setStatusTip('Configure stealth and evasion settings')
        stealth_action.triggered.connect(self.open_stealth_config)
        pro_menu.addAction(stealth_action)
        
        # Hacking Mode action
        hacking_action = QAction('&Hacking Mode', self)
        hacking_action.setStatusTip('Access exploit frameworks and payloads')
        hacking_action.triggered.connect(self.open_hacking_mode)
        pro_menu.addAction(hacking_action)
        
        # ProxyChains action
        proxy_action = QAction('&ProxyChains', self)
        proxy_action.setStatusTip('Configure proxy chaining')
        proxy_action.triggered.connect(self.open_proxychains_config)
        pro_menu.addAction(proxy_action)
        
        pro_menu.addSeparator()
        
        # Web Scanner action
        web_scanner_action = QAction('&Web Scanner', self)
        web_scanner_action.setStatusTip('Web application security scanner')
        web_scanner_action.triggered.connect(self.open_web_scanner)
        pro_menu.addAction(web_scanner_action)
        
        # AD Enumeration action
        ad_enum_action = QAction('&AD Enumeration', self)
        ad_enum_action.setStatusTip('Active Directory enumeration and attacks')
        ad_enum_action.triggered.connect(self.open_ad_enumeration)
        pro_menu.addAction(ad_enum_action)
        
        pro_menu.addSeparator()
        
        # Enhanced Reporting action
        reporting_action = QAction('&Enhanced Reporting', self)
        reporting_action.setStatusTip('Executive dashboards and compliance reports')
        reporting_action.triggered.connect(self.open_enhanced_reporting)
        pro_menu.addAction(reporting_action)
        
        # Wireless Security action
        wireless_action = QAction('&Wireless Security', self)
        wireless_action.setStatusTip('WiFi and Bluetooth security testing')
        wireless_action.triggered.connect(self.open_wireless_security)
        pro_menu.addAction(wireless_action)
        
        pro_menu.addSeparator()
        
        # Social Engineering action
        se_action = QAction('&Social Engineering', self)
        se_action.setStatusTip('Phishing campaigns and credential harvesting')
        se_action.triggered.connect(self.open_social_engineering)
        pro_menu.addAction(se_action)
        
        # Anti-Forensics action
        forensics_action = QAction('&Anti-Forensics', self)
        forensics_action.setStatusTip('Log clearing and evasion techniques')
        forensics_action.triggered.connect(self.open_anti_forensics)
        pro_menu.addAction(forensics_action)
        
        # VPN action
        vpn_action = QAction('&VPN Connection', self)
        vpn_action.setStatusTip('Manage VPN connections')
        vpn_action.triggered.connect(self.open_vpn_manager)
        pro_menu.addAction(vpn_action)
        
        # Local DNS Server action
        local_dns_action = QAction('&Local DNS Server', self)
        local_dns_action.setStatusTip('Manage local DNS server for custom domain records')
        local_dns_action.triggered.connect(self.open_local_dns_manager)
        pro_menu.addAction(local_dns_action)
        
        # Help menu
        help_menu = menubar.addMenu('&Help')
        
        # Enhanced Help action
        help_action = QAction('&Tool Help', self)
        help_action.setShortcut(QKeySequence('F1'))
        help_action.setStatusTip('Show detailed tool help and documentation')
        help_action.triggered.connect(self.show_enhanced_help)
        help_menu.addAction(help_action)
        
        help_menu.addSeparator()
        
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
        elif page_name == "osint" or page_name == "osint_recon":
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
        elif page_name == "running_scans":
            self.stack.animate_to_widget(self.running_scans_page)
            self.status_bar.showMessage("Running Scans Monitor - Control active enumeration scans")
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
            
            # Resize background effects
            if hasattr(self, 'background_effects'):
                self.background_effects.resize_effect(size)
            
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
        
    def open_reports_dialog(self):
        """Open advanced reports dialog"""
        from app.widgets.advanced_reporting_widget import AdvancedReportingWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        # Create and show reports dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Advanced Reporting Engine")
        dialog.setModal(True)
        dialog.resize(1000, 750)
        
        layout = QVBoxLayout(dialog)
        
        # Create reporting widget
        reporting_widget = AdvancedReportingWidget(dialog)
        
        layout.addWidget(reporting_widget)
        
        self.status_bar.showMessage("Advanced Reporting Engine opened")
        dialog.exec()
    
    def open_sessions_dialog(self):
        """Open session management dialog"""
        from app.widgets.session_widget import SessionWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Session Management")
        dialog.setModal(True)
        dialog.resize(900, 700)
        
        layout = QVBoxLayout(dialog)
        session_widget = SessionWidget(dialog)
        layout.addWidget(session_widget)
        
        self.status_bar.showMessage("Session Management opened")
        dialog.exec()
        self.status_bar.showMessage("Session Management closed")
    
    def show_enhanced_help(self):
        """Show enhanced help panel"""
        if hasattr(self, 'enhanced_help_panel'):
            self.enhanced_help_panel.show()
            self.status_bar.showMessage("Enhanced help panel opened - F1 to close")
        else:
            self.status_bar.showMessage("Enhanced help panel not available")
    
    def show_running_scans(self):
        """Show the Running Scans page"""
        self.navigate_to("running_scans")
    
    def open_license_manager(self):
        """Open license management dialog"""
        from app.widgets.license_widget import LicenseWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("License Manager")
        dialog.setModal(True)
        dialog.resize(800, 600)
        
        layout = QVBoxLayout(dialog)
        license_widget = LicenseWidget(dialog)
        layout.addWidget(license_widget)
        
        self.status_bar.showMessage("License Manager opened")
        dialog.exec()
        
    def open_stealth_config(self):
        """Open stealth mode configuration"""
        from app.widgets.stealth_widget import StealthWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Stealth Mode Configuration")
        dialog.setModal(True)
        dialog.resize(600, 500)
        
        layout = QVBoxLayout(dialog)
        stealth_widget = StealthWidget(dialog)
        layout.addWidget(stealth_widget)
        
        self.status_bar.showMessage("Stealth Mode configuration opened")
        dialog.exec()
        
    def open_hacking_mode(self):
        """Open hacking mode interface"""
        from app.core.license_manager import license_manager
        from PyQt6.QtWidgets import QMessageBox
        
        if not license_manager.is_feature_enabled('hacking_mode'):
            QMessageBox.warning(self, "Professional Feature", 
                              "Hacking Mode requires Professional or Enterprise license.\n\n"
                              "Visit License Manager to upgrade.")
            return
            
        from app.widgets.hacking_mode_widget import HackingModeWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Hacking Mode - Exploit Framework")
        dialog.setModal(True)
        dialog.resize(900, 700)
        
        layout = QVBoxLayout(dialog)
        hacking_widget = HackingModeWidget(dialog)
        layout.addWidget(hacking_widget)
        
        self.status_bar.showMessage("Hacking Mode interface opened")
        dialog.exec()
        
    def open_proxychains_config(self):
        """Open proxychains configuration"""
        from app.core.license_manager import license_manager
        from PyQt6.QtWidgets import QMessageBox
        
        if not license_manager.is_feature_enabled('proxychains'):
            QMessageBox.warning(self, "Professional Feature", 
                              "ProxyChains requires Professional or Enterprise license.\n\n"
                              "Visit License Manager to upgrade.")
            return
            
        from app.widgets.proxychains_widget import ProxyChainsWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("ProxyChains Configuration")
        dialog.setModal(True)
        dialog.resize(800, 600)
        
        layout = QVBoxLayout(dialog)
        proxychains_widget = ProxyChainsWidget(dialog)
        layout.addWidget(proxychains_widget)
        
        self.status_bar.showMessage("ProxyChains configuration opened")
        dialog.exec()
        
    def open_web_scanner(self):
        """Open web application security scanner"""
        from app.core.license_manager import license_manager
        from PyQt6.QtWidgets import QMessageBox
        
        if not license_manager.is_feature_enabled('web_scanner'):
            QMessageBox.warning(self, "Professional Feature", 
                              "Web Scanner requires Professional or Enterprise license.\n\n"
                              "Visit License Manager to upgrade.")
            return
            
        from app.widgets.web_scanner_widget import WebScannerWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Web Application Security Scanner")
        dialog.setModal(True)
        dialog.resize(1000, 700)
        
        layout = QVBoxLayout(dialog)
        web_scanner_widget = WebScannerWidget(dialog)
        layout.addWidget(web_scanner_widget)
        
        self.status_bar.showMessage("Web Scanner opened")
        dialog.exec()
        
    def open_ad_enumeration(self):
        """Open Active Directory enumeration"""
        from app.core.license_manager import license_manager
        from PyQt6.QtWidgets import QMessageBox
        
        if not license_manager.is_feature_enabled('ad_enumeration'):
            QMessageBox.warning(self, "Enterprise Feature", 
                              "AD Enumeration requires Enterprise license.\n\n"
                              "Visit License Manager to upgrade.")
            return
            
        from app.widgets.ad_enumeration_widget import ADEnumerationWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Active Directory Enumeration & Attacks")
        dialog.setModal(True)
        dialog.resize(1100, 800)
        
        layout = QVBoxLayout(dialog)
        ad_enum_widget = ADEnumerationWidget(dialog)
        layout.addWidget(ad_enum_widget)
        
        self.status_bar.showMessage("AD Enumeration opened")
        dialog.exec()
        
    def open_enhanced_reporting(self):
        """Open enhanced reporting engine"""
        from app.core.license_manager import license_manager
        from PyQt6.QtWidgets import QMessageBox
        
        if not license_manager.is_feature_enabled('enhanced_reporting'):
            QMessageBox.warning(self, "Enterprise Feature", 
                              "Enhanced Reporting requires Enterprise license.\n\n"
                              "Visit License Manager to upgrade.")
            return
            
        from app.widgets.enhanced_reporting_widget import EnhancedReportingWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Enhanced Reporting Engine")
        dialog.setModal(True)
        dialog.resize(1200, 800)
        
        layout = QVBoxLayout(dialog)
        reporting_widget = EnhancedReportingWidget(dialog)
        layout.addWidget(reporting_widget)
        
        self.status_bar.showMessage("Enhanced Reporting opened")
        dialog.exec()
        
    def open_wireless_security(self):
        """Open wireless security testing"""
        from app.core.license_manager import license_manager
        from PyQt6.QtWidgets import QMessageBox
        
        if not license_manager.is_feature_enabled('wireless_security'):
            QMessageBox.warning(self, "Enterprise Feature", 
                              "Wireless Security requires Enterprise license.\n\n"
                              "Visit License Manager to upgrade.")
            return
            
        from app.widgets.wireless_security_widget import WirelessSecurityWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Wireless Security Testing Framework")
        dialog.setModal(True)
        dialog.resize(1100, 700)
        
        layout = QVBoxLayout(dialog)
        wireless_widget = WirelessSecurityWidget(dialog)
        layout.addWidget(wireless_widget)
        
        self.status_bar.showMessage("Wireless Security opened")
        dialog.exec()
        
    def open_social_engineering(self):
        """Open social engineering toolkit"""
        from app.core.license_manager import license_manager
        from PyQt6.QtWidgets import QMessageBox
        
        if not license_manager.is_feature_enabled('social_engineering'):
            QMessageBox.warning(self, "Enterprise Feature", 
                              "Social Engineering requires Enterprise license.\n\n"
                              "Visit License Manager to upgrade.")
            return
            
        from app.widgets.social_engineering_widget import SocialEngineeringWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Social Engineering Toolkit")
        dialog.setModal(True)
        dialog.resize(1200, 800)
        
        layout = QVBoxLayout(dialog)
        se_widget = SocialEngineeringWidget(dialog)
        layout.addWidget(se_widget)
        
        self.status_bar.showMessage("Social Engineering opened")
        dialog.exec()
        
    def open_anti_forensics(self):
        """Open anti-forensics toolkit"""
        from app.core.license_manager import license_manager
        from PyQt6.QtWidgets import QMessageBox
        
        if not license_manager.is_feature_enabled('anti_forensics'):
            QMessageBox.warning(self, "Enterprise Feature", 
                              "Anti-Forensics requires Enterprise license.\n\n"
                              "Visit License Manager to upgrade.")
            return
            
        from app.widgets.anti_forensics_widget import AntiForensicsWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Anti-Forensics & Evasion Techniques")
        dialog.setModal(True)
        dialog.resize(1100, 700)
        
        layout = QVBoxLayout(dialog)
        forensics_widget = AntiForensicsWidget(dialog)
        layout.addWidget(forensics_widget)
        
        self.status_bar.showMessage("Anti-Forensics opened")
        dialog.exec()
    
    def open_vpn_manager(self):
        """Open VPN connection manager"""
        from app.widgets.vpn_widget import VPNWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("VPN Connection Manager")
        dialog.setModal(True)
        dialog.resize(600, 500)
        
        layout = QVBoxLayout(dialog)
        vpn_widget = VPNWidget(dialog)
        layout.addWidget(vpn_widget)
        
        self.status_bar.showMessage("VPN Manager opened")
        dialog.exec()
    
    def open_local_dns_manager(self):
        """Open local DNS server manager"""
        from app.core.license_manager import license_manager
        from PyQt6.QtWidgets import QMessageBox
        
        if not license_manager.is_feature_enabled('local_dns_server'):
            QMessageBox.warning(self, "Professional Feature", 
                              "Local DNS Server requires Professional or Enterprise license.\n\n"
                              "Visit License Manager to upgrade.")
            return
            
        from app.widgets.local_dns_widget import LocalDNSWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Local DNS Server Manager")
        dialog.setModal(True)
        dialog.resize(1080, 900)
        
        layout = QVBoxLayout(dialog)
        dns_widget = LocalDNSWidget()
        layout.addWidget(dns_widget)
        
        self.status_bar.showMessage("Local DNS Server Manager opened")
        dialog.exec()
    
    def on_theme_changed(self, theme_name):
        """Handle theme change event"""
        theme_display_name = self.theme_manager.get_theme_colors(theme_name).get('name', theme_name)
        self.status_bar.showMessage(f"Theme changed to: {theme_display_name}")
        
        # Update background effects based on theme
        animations = self.theme_manager.get_theme_animations(theme_name)
        if animations.get('matrix_rain'):
            self.background_effects.set_effect('matrix_rain')
        elif animations.get('neon_glow'):
            self.background_effects.set_effect('neon_glow')
        elif animations.get('wave_effects'):
            self.background_effects.set_effect('wave_effects')
        elif animations.get('terminal_effects'):
            self.background_effects.set_effect('terminal_effects')
        elif animations.get('particle_field'):
            self.background_effects.set_effect('particle_field')
        else:
            self.background_effects.remove_effect()
    
    def open_theme_selector(self):
        """Open enhanced theme selector dialog"""
        from app.widgets.enhanced_theme_selector import ThemeSelectionDialog
        
        dialog = ThemeSelectionDialog(self.theme_manager, self)
        dialog.exec()
        
    def show_theme_upgrade_dialog(self, theme_name, message):
        """Show theme upgrade dialog"""
        from PyQt6.QtWidgets import QMessageBox
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Premium Theme")
        msg_box.setIcon(QMessageBox.Icon.Information)
        msg_box.setText(f"Theme '{theme_name}' is locked.")
        msg_box.setInformativeText(message)
        
        upgrade_btn = msg_box.addButton("Upgrade License", QMessageBox.ButtonRole.AcceptRole)
        msg_box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        
        result = msg_box.exec()
        if msg_box.clickedButton() == upgrade_btn:
            self.open_license_manager()