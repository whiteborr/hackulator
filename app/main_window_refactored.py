# app/main_window_refactored.py
import os
from PyQt6.QtWidgets import QMainWindow, QStatusBar, QMenuBar, QMenu
from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QFontDatabase, QAction, QKeySequence
from PyQt6.QtWidgets import QApplication

from app.theme_manager import ThemeManager
from app.widgets.animated_stacked_widget import AnimatedStackedWidget
from app.pages.home_page_refactored import HomePage
from app.pages.enumeration_page_refactored import EnumerationPage
# Import other refactored pages as you create them
# from app.pages.vuln_scanning_page_refactored import VulnScanningPage
# from app.pages.web_exploits_page_refactored import WebExploitsPage
# from app.pages.db_attacks_page_refactored import DbAttacksPage
# from app.pages.os_exploits_page_refactored import OSExploitsPage
# from app.pages.cracking_page_refactored import CrackingPage

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
        
        # Add pages to stack
        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.enum_page)
        
        # Connect navigation signals
        self.home_page.navigate_signal.connect(self.navigate_to)
        self.enum_page.navigate_signal.connect(self.navigate_to)
        
        # Connect status signals
        self.home_page.status_updated.connect(self.update_status_bar)
        self.enum_page.status_updated.connect(self.update_status_bar)
        
        # Apply global styling
        self.apply_global_styling()
        
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
        else:
            font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
            print(f"Custom font '{font_family}' loaded successfully.")
            
    def navigate_to(self, page_name):
        """Navigate to a specific page"""
        self.status_bar.showMessage(f"Navigating to {page_name}...")
        
        if page_name == "home":
            self.stack.animate_to_widget(self.home_page)
            self.status_bar.showMessage("Home - Select a tool to get started")
        elif page_name == "enumeration":
            self.stack.animate_to_widget(self.enum_page)
            self.status_bar.showMessage("Enumeration Tools - Select a tool from the left panel")
        # Add other page navigation as you create them
        # elif page_name == "vuln_scanning":
        #     self.stack.animate_to_widget(self.vuln_page)
        # elif page_name == "web_exploits":
        #     self.stack.animate_to_widget(self.web_exploits_page)
        # elif page_name == "databases":
        #     self.stack.animate_to_widget(self.db_attacks_page)
        # elif page_name == "os_exploits":
        #     self.stack.animate_to_widget(self.os_exploits_page)
        # elif page_name == "cracking":
        #     self.stack.animate_to_widget(self.cracking_page)
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
            <li>F11 - Toggle fullscreen</li>
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
        
    def closeEvent(self, event):
        """Handle application close event"""
        self.status_bar.showMessage("Closing application...")
        # Stop memory monitoring
        from app.core.memory_manager import memory_manager
        memory_manager.stop_monitoring()
        event.accept()