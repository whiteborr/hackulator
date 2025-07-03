# app/pages/home_page_refactored.py
import logging
import os
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QTextEdit, QVBoxLayout, QHBoxLayout, QGridLayout, QSizePolicy, QFrame)
from PyQt6.QtCore import pyqtSignal, QSize, Qt
from PyQt6.QtGui import QPixmap, QIcon, QFont

class HoverButton(QPushButton):
    enter_signal = pyqtSignal(str, list)
    leave_signal = pyqtSignal()
    
    def __init__(self, title, description_lines, parent=None):
        super().__init__(parent)
        self.title = title
        self.description_lines = description_lines
        
    def enterEvent(self, event):
        super().enterEvent(event)
        self.enter_signal.emit(self.title, self.description_lines)
        
    def leaveEvent(self, event):
        super().leaveEvent(event)
        self.leave_signal.emit()

class HomePage(QWidget):
    navigate_signal = pyqtSignal(str)
    status_updated = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("HomePage")
        
        # Create main layout
        self.main_layout = QHBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(20)
        
        # Create navigation panel (left side)
        self.nav_panel = self.create_navigation_panel()
        
        # Create info panel (right side)
        self.info_panel = self.create_info_panel()
        
        # Add panels to main layout with stretch factors
        self.main_layout.addWidget(self.nav_panel, 0)  # Fixed width
        self.main_layout.addWidget(self.info_panel, 1)  # Expandable
        
        self.apply_theme()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    def create_navigation_panel(self):
        """Create the left navigation panel with tool buttons"""
        nav_frame = QFrame()
        nav_frame.setObjectName("NavigationPanel")
        nav_frame.setFixedWidth(280)
        nav_frame.setStyleSheet("""
            QFrame#NavigationPanel {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 15px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        
        nav_layout = QVBoxLayout(nav_frame)
        nav_layout.setContentsMargins(15, 15, 15, 15)
        nav_layout.setSpacing(10)
        
        # Title
        title = QLabel("HACKULATOR")
        title.setObjectName("TitleLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            font-size: 18pt;
            font-weight: bold;
            color: #64C8FF;
            padding: 10px;
        """)
        nav_layout.addWidget(title)
        
        # Button data
        button_data = [
            {"name": "enumeration", "title": "ENUMERATION", "desc": ["Enumeration is the process of actively collecting information about a target system to identify potential entry points."], "icon": "resources/icons/1.png"},
            {"name": "vuln_scanning", "title": "VULN SCANNING", "desc": ["Identify known weaknesses in systems and services using automated tools."], "icon": "resources/icons/2.png"},
            {"name": "web_exploits", "title": "WEB EXPLOITS", "desc": ["Target vulnerabilities in web applications and client software."], "icon": "resources/icons/3.png"},
            {"name": "databases", "title": "DB ATTACKS", "desc": ["Exploit weaknesses in database queries and configurations."], "icon": "resources/icons/4.png"},
            {"name": "os_exploits", "title": "OS EXPLOITS", "desc": ["Leverage OS-level flaws for privilege escalation or persistence."], "icon": "resources/icons/5.png"},
            {"name": "cracking", "title": "CRACKING", "desc": ["Break passwords by capturing and cracking authentication hashes."], "icon": "resources/icons/6.png"},
            {"name": "osint", "title": "OSINT & RECON", "desc": ["Open Source Intelligence gathering and reconnaissance techniques."], "icon": "resources/icons/1A.png"},
            {"name": "findings", "title": "COMMON FINDINGS", "desc": ["Common penetration testing findings and vulnerabilities."], "icon": "resources/icons/1B.png"},
            {"name": "owasp_api", "title": "OWASP API TOP 10", "desc": ["OWASP API Security Top 10 - 2023 vulnerabilities and mitigations."], "icon": "resources/icons/1C.png"},
            {"name": "scripts", "title": "SCRIPTS & TOOLS", "desc": ["Useful scripts and code generators for penetration testing."], "icon": "resources/icons/1D.png"},
        ]
        
        # Create navigation buttons
        self.nav_buttons = []
        for btn_info in button_data:
            button = self.create_nav_button(btn_info)
            nav_layout.addWidget(button)
            self.nav_buttons.append(button)
        
        # Add stretch to push buttons to top
        nav_layout.addStretch()
        
        return nav_frame

    def create_nav_button(self, btn_info):
        """Create a navigation button with icon and text"""
        button = HoverButton(btn_info["title"], btn_info["desc"], self)
        
        # Set button properties
        button.setMinimumHeight(60)
        button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        
        # Load icon
        icon_path = os.path.join(self.main_window.project_root, btn_info["icon"])
        icon = QIcon(icon_path)
        if icon.isNull():
            logging.warning(f"Could not load icon at {icon_path}")
        
        button.setIcon(icon)
        button.setIconSize(QSize(32, 32))
        button.setText(btn_info["title"])
        
        # Style the button
        button.setStyleSheet("""
            QPushButton {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 10px;
                color: #DCDCDC;
                font-size: 12pt;
                font-weight: bold;
                text-align: left;
                padding: 8px 12px;
            }
            QPushButton:hover {
                background-color: rgba(40, 60, 80, 200);
                border: 2px solid #64C8FF;
                color: #FFFFFF;
            }
            QPushButton:pressed {
                background-color: rgba(60, 100, 140, 220);
                border: 2px solid #88DFFF;
            }
        """)
        
        # Connect signals
        button.clicked.connect(lambda checked, n=btn_info["name"]: self.navigate_signal.emit(n))
        button.enter_signal.connect(self.update_info_panel)
        button.leave_signal.connect(self.clear_info_panel)
        
        return button

    def create_info_panel(self):
        """Create the right info panel"""
        info_frame = QFrame()
        info_frame.setObjectName("InfoPanel")
        info_frame.setStyleSheet("""
            QFrame#InfoPanel {
                background-color: rgba(0, 0, 0, 150);
                border-radius: 15px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(20, 20, 20, 20)
        
        # Welcome message
        welcome_label = QLabel("Welcome to Hackulator")
        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_label.setStyleSheet("""
            font-size: 24pt;
            font-weight: bold;
            color: #64C8FF;
            padding: 20px;
        """)
        info_layout.addWidget(welcome_label)
        
        # Info text area
        self.info_text = QTextEdit()
        self.info_text.setObjectName("InfoTextArea")
        self.info_text.setReadOnly(True)
        # Apply Neuropol font directly
        from PyQt6.QtGui import QFont
        neuropol_font = QFont()
        neuropol_font.setFamily("Neuropol X")
        neuropol_font.setPointSize(14)
        self.info_text.setFont(neuropol_font)
        
        self.info_text.setStyleSheet("""
            QTextEdit#InfoTextArea {
                background-color: transparent;
                border: none;
                color: #DCDCDC;
            }
        """)
        
        # Default content
        self.info_text.setHtml("""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold; margin-bottom: 20px;'>
            Cybersecurity Toolkit
        </div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>
            Select a tool from the navigation panel to get started.<br><br>
            
            <b>Features:</b><br>
            • Comprehensive enumeration tools<br>
            • Vulnerability scanning capabilities<br>
            • Web application exploit testing<br>
            • Database attack vectors<br>
            • Operating system exploits<br>
            • Password cracking utilities<br><br>
            
            <i>Hover over any tool button to see detailed information.</i>
        </div>
        """)
        
        info_layout.addWidget(self.info_text)
        
        return info_frame

    def update_info_panel(self, title, description_lines):
        """Update the info panel with tool information"""
        desc_html = "<br>".join(description_lines)
        html_text = f"""
        <div style='color: #64C8FF; font-size: 22pt; font-weight: bold; padding-bottom: 20px;'>
            {title}
        </div>
        <div style='color: #DCDCDC; font-size: 16pt; line-height: 150%;'>
            {desc_html}
        </div>
        """
        self.info_text.setHtml(html_text)
    
    def clear_info_panel(self):
        """Reset info panel to default content"""
        self.info_text.setHtml("""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold; margin-bottom: 20px;'>
            Cybersecurity Toolkit
        </div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>
            Select a tool from the navigation panel to get started.<br><br>
            
            <b>Features:</b><br>
            • Comprehensive enumeration tools<br>
            • Vulnerability scanning capabilities<br>
            • Web application exploit testing<br>
            • Database attack vectors<br>
            • Operating system exploits<br>
            • Password cracking utilities<br><br>
            
            <i>Hover over any tool button to see detailed information.</i>
        </div>
        """)

    def apply_theme(self):
        """Apply background theme"""
        theme = self.main_window.theme_manager
        background_path = theme.get("backgrounds.home")
        if background_path:
            # Set background image using stylesheet
            self.setStyleSheet(f"""
                HomePage {{
                    background-image: url({background_path});
                    background-repeat: no-repeat;
                    background-position: center;
                    background-attachment: fixed;
                }}
            """)