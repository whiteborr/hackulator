# app/pages/owasp_api_page_refactored.py
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

class OWASPAPIPage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("OWASPAPIPage")

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(15)

        self.create_header()
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
        
        title = QLabel("OWASP API Security Top 10 - 2023")
        title.setObjectName("TitleLabel")
        
        header_layout.addWidget(self.back_button)
        header_layout.addWidget(title, 1)
        header_layout.addStretch()
        
        self.main_layout.addWidget(header_frame)

    def create_content_area(self):
        content_layout = QHBoxLayout()
        
        left_panel = self.create_left_panel()
        content_layout.addWidget(left_panel, 0)
        
        right_panel = self.create_right_panel()
        content_layout.addWidget(right_panel, 1)
        
        self.main_layout.addLayout(content_layout)

    def create_left_panel(self):
        panel = QFrame()
        panel.setFixedWidth(300)
        layout = QVBoxLayout(panel)
        
        self.api_risks_data = [
            {"id": "api1", "title": "API1:2023 - Broken Object Level Authorization", "desc": "APIs expose endpoints that handle object identifiers, creating access control issues."},
            {"id": "api2", "title": "API2:2023 - Broken Authentication", "desc": "Authentication mechanisms are often implemented incorrectly."},
            {"id": "api3", "title": "API3:2023 - Broken Object Property Level Authorization", "desc": "Combines excessive data exposure and mass assignment vulnerabilities."},
            {"id": "api4", "title": "API4:2023 - Unrestricted Resource Consumption", "desc": "API requests consume resources without proper limits."},
            {"id": "api5", "title": "API5:2023 - Broken Function Level Authorization", "desc": "Complex access control policies create authorization confusion."},
        ]
        
        scroll_area = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        self.risk_buttons = []
        for risk in self.api_risks_data:
            button = HoverButton(risk["title"], risk["desc"], self)
            button.setMinimumHeight(50)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.clicked.connect(lambda checked, r=risk: self.show_risk_details(r))
            button.enter_signal.connect(self.update_info_panel)
            button.leave_signal.connect(self.clear_info_panel)
            scroll_layout.addWidget(button)
            self.risk_buttons.append(button)

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
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold; margin-bottom: 20px;'>OWASP API Security Top 10 - 2023</div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>
        The OWASP API Security Top 10 represents the most critical security risks to APIs.
        <br><br>
        <i>Click on any risk category to view detailed information, attack scenarios, and prevention methods.</i>
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

    def show_risk_details(self, risk):
        details = self.get_risk_details(risk["id"])
        self.info_panel.setHtml(f"""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold; margin-bottom: 15px;'>{risk["title"]}</div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>{details}</div>
        """)

    def get_risk_details(self, risk_id):
        details = {
            "api1": """
            <b>Description:</b> Broken Object Level Authorization
            <br><br><b>Attack:</b> Manipulate object IDs in API calls to access other users' data
            <br><br><b>Prevention:</b> Implement proper authorization checks for every object
            """,
            "api2": """
            <b>Description:</b> Broken Authentication
            <br><br><b>Attack:</b> Brute force attacks, token manipulation, session hijacking
            <br><br><b>Prevention:</b> Implement strong authentication and session management
            """,
            "api3": """
            <b>Description:</b> Broken Object Property Level Authorization
            <br><br><b>Attack:</b> Mass assignment and excessive data exposure
            <br><br><b>Prevention:</b> Use allow-lists for modifiable properties
            """,
            "api4": """
            <b>Description:</b> Unrestricted Resource Consumption
            <br><br><b>Attack:</b> DoS through resource exhaustion
            <br><br><b>Prevention:</b> Implement rate limiting and request size limits
            """,
            "api5": """
            <b>Description:</b> Broken Function Level Authorization
            <br><br><b>Attack:</b> Access unauthorized functions or admin features
            <br><br><b>Prevention:</b> Implement proper function-level access controls
            """
        }
        return details.get(risk_id, "Detailed information not available.")

    def update_info_panel(self, title, description):
        self.info_panel.setHtml(f"""
        <div style='color: #64C8FF; font-size: 16pt; font-weight: bold; margin-bottom: 10px;'>{title}</div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>{description}</div>
        """)
    
    def clear_info_panel(self):
        self.info_panel.setHtml("""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold; margin-bottom: 20px;'>OWASP API Security Top 10 - 2023</div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>
        Hover over an API risk to see a brief description, or click to view detailed information.
        </div>
        """)

    def setup_shortcuts(self):
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))