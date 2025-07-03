# app/pages/findings_page_refactored.py
import logging
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QTextEdit, QScrollArea, 
                            QVBoxLayout, QHBoxLayout, QFrame, QSizePolicy)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QShortcut, QKeySequence

class HoverButton(QPushButton):
    enter_signal = pyqtSignal(str, str)
    leave_signal = pyqtSignal()

    def __init__(self, title, description, parent=None):
        super().__init__(parent)
        self.title = title
        self.description = description

    def enterEvent(self, event):
        super().enterEvent(event)
        self.enter_signal.emit(self.title, self.description)

    def leaveEvent(self, event):
        super().leaveEvent(event)
        self.leave_signal.emit()

class FindingsPage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("FindingsPage")

        # Create main layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(15)

        # Header
        self.create_header()
        
        # Content area
        self.create_content_area()
        
        self.setup_shortcuts()
        self.apply_theme()

    def create_header(self):
        header_frame = QFrame()
        header_frame.setFixedHeight(60)
        header_layout = QHBoxLayout(header_frame)
        
        self.back_button = QPushButton("← Back to Home")
        self.back_button.clicked.connect(lambda: self.navigate_signal.emit("home"))
        self.back_button.setFixedWidth(150)
        
        title = QLabel("Common Pentest Findings")
        title.setObjectName("TitleLabel")
        
        header_layout.addWidget(self.back_button)
        header_layout.addWidget(title, 1)
        header_layout.addStretch()
        
        self.main_layout.addWidget(header_frame)

    def create_content_area(self):
        content_layout = QHBoxLayout()
        
        # Left panel - findings list
        left_panel = self.create_left_panel()
        content_layout.addWidget(left_panel, 0)
        
        # Right panel - details
        right_panel = self.create_right_panel()
        content_layout.addWidget(right_panel, 1)
        
        self.main_layout.addLayout(content_layout)

    def create_left_panel(self):
        panel = QFrame()
        panel.setFixedWidth(300)
        layout = QVBoxLayout(panel)
        
        # Findings data
        self.findings_data = [
            {"id": "default_pages", "title": "Default Web Pages", "desc": "Identify default installation pages that reveal system information."},
            {"id": "historical_compromise", "title": "Historical Compromises", "desc": "Check for previously compromised accounts and credentials."},
            {"id": "insufficient_auth", "title": "Insufficient Authentication", "desc": "Weak or missing authentication controls."},
            {"id": "sql_injection", "title": "SQL Injection", "desc": "Database query manipulation vulnerabilities."},
            {"id": "weak_passwords", "title": "Weak Password Policy", "desc": "Inadequate password requirements and default credentials."},
        ]
        
        # Create scroll area
        scroll_area = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        self.finding_buttons = []
        for finding in self.findings_data:
            button = HoverButton(finding["title"], finding["desc"], self)
            button.setMinimumHeight(50)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.clicked.connect(lambda checked, f=finding: self.show_finding_details(f))
            button.enter_signal.connect(self.update_info_panel)
            button.leave_signal.connect(self.clear_info_panel)
            scroll_layout.addWidget(button)
            self.finding_buttons.append(button)

        scroll_area.setWidget(scroll_widget)
        scroll_area.setWidgetResizable(True)
        layout.addWidget(scroll_area)
        
        return panel

    def create_right_panel(self):
        panel = QFrame()
        layout = QVBoxLayout(panel)
        
        self.info_panel = QTextEdit()
        self.info_panel.setReadOnly(True)
        self.info_panel.setHtml("""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold; margin-bottom: 20px;'>Common Penetration Testing Findings</div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>
        This section covers the most frequently discovered vulnerabilities and misconfigurations during penetration tests.
        <br><br>
        <i>Select a category from the left to view detailed information and remediation guidance.</i>
        </div>
        """)
        layout.addWidget(self.info_panel)
        
        return panel

    def apply_theme(self):
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QLabel {
                color: #64C8FF;
                font-weight: bold;
            }
        """)

    def show_finding_details(self, finding):
        details = self.get_finding_details(finding["id"])
        self.info_panel.setHtml(f"""
        <div style='color: #64C8FF; font-size: 20pt; font-weight: bold; margin-bottom: 15px;'>{finding["title"]}</div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>{details}</div>
        """)

    def get_finding_details(self, finding_id):
        details = {
            "default_pages": """
            <b>Description:</b> Default web pages and configurations that reveal system information.
            <br><br><b>Risk:</b> Information disclosure, system fingerprinting
            <br><br><b>Remediation:</b> Remove or customize default pages, configure custom error pages
            """,
            "historical_compromise": """
            <b>Description:</b> Previously compromised accounts and credentials still in use.
            <br><br><b>Risk:</b> Account takeover, lateral movement
            <br><br><b>Remediation:</b> Force password resets, implement multi-factor authentication
            """,
            "insufficient_auth": """
            <b>Description:</b> Weak or missing authentication controls.
            <br><br><b>Risk:</b> Unauthorized access, privilege escalation
            <br><br><b>Remediation:</b> Implement strong authentication, enforce password policies
            """,
            "sql_injection": """
            <b>Description:</b> Database query manipulation vulnerabilities.
            <br><br><b>Risk:</b> Data breach, system compromise
            <br><br><b>Remediation:</b> Use parameterized queries, input validation
            """,
            "weak_passwords": """
            <b>Description:</b> Inadequate password requirements and default credentials.
            <br><br><b>Risk:</b> Brute force attacks, credential stuffing
            <br><br><b>Remediation:</b> Enforce strong password policies, remove default accounts
            """
        }
        return details.get(finding_id, "Detailed information not available.")

    def update_info_panel(self, title, description):
        self.info_panel.setHtml(f"""
        <div style='color: #64C8FF; font-size: 22pt; font-weight: bold;'>{title}</div>
        <div style='color: #DCDCDC; font-size: 16pt;'>{description}</div>
        """)
    
    def clear_info_panel(self):
        self.info_panel.setHtml("""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold; margin-bottom: 20px;'>Common Penetration Testing Findings</div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>
        Hover over a finding category to see a brief description, or click to view detailed information.
        </div>
        """)

    def setup_shortcuts(self):
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))