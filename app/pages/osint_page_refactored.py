# app/pages/osint_page_refactored.py
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, 
                            QVBoxLayout, QHBoxLayout, QFrame, QTabWidget)
from PyQt6.QtCore import pyqtSignal, QThreadPool
from PyQt6.QtGui import QShortcut, QKeySequence
from app.core.base_worker import CommandWorker

class OSINTPage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("OSINTPage")

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
        
        title = QLabel("OSINT & Reconnaissance")
        title.setObjectName("TitleLabel")
        
        header_layout.addWidget(self.back_button)
        header_layout.addWidget(title, 1)
        header_layout.addStretch()
        
        self.main_layout.addWidget(header_frame)

    def create_content_area(self):
        self.tab_widget = QTabWidget()
        
        # Breach Hunting Tab
        breach_tab = self.create_breach_tab()
        self.tab_widget.addTab(breach_tab, "Breach Hunting")
        
        # Employee Enumeration Tab
        employee_tab = self.create_employee_tab()
        self.tab_widget.addTab(employee_tab, "Employee Enum")
        
        # Social Media Tab
        social_tab = self.create_social_tab()
        self.tab_widget.addTab(social_tab, "Social Media")
        
        self.main_layout.addWidget(self.tab_widget)

    def create_breach_tab(self):
        tab = QWidget()
        layout = QHBoxLayout(tab)
        
        # Left panel - controls
        left_panel = QFrame()
        left_panel.setFixedWidth(200)
        left_layout = QVBoxLayout(left_panel)
        
        self.breach_target_input = QLineEdit()
        self.breach_target_input.setPlaceholderText("email@domain.com")
        left_layout.addWidget(QLabel("Email/Domain:"))
        left_layout.addWidget(self.breach_target_input)
        
        left_layout.addWidget(QLabel("Breach Sources:"))
        
        buttons = [
            ("Have I Been Pwned", self.run_hibp_check),
            ("Dehashed", self.run_dehashed),
            ("Breach Database", self.run_breach_db),
            ("All Sources", self.run_all_breach_checks)
        ]
        
        self.breach_buttons = []
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            left_layout.addWidget(btn)
            self.breach_buttons.append(btn)
        
        left_layout.addStretch()
        
        # Right panel - output
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        self.breach_output = QTextEdit()
        self.breach_output.setReadOnly(True)
        self.breach_output.setPlaceholderText("Breach hunting results will appear here...")
        right_layout.addWidget(self.breach_output)
        
        layout.addWidget(left_panel)
        layout.addWidget(right_panel)
        
        return tab

    def create_employee_tab(self):
        tab = QWidget()
        layout = QHBoxLayout(tab)
        
        # Left panel - controls
        left_panel = QFrame()
        left_panel.setFixedWidth(200)
        left_layout = QVBoxLayout(left_panel)
        
        self.employee_target_input = QLineEdit()
        self.employee_target_input.setPlaceholderText("company.com")
        left_layout.addWidget(QLabel("Company Domain:"))
        left_layout.addWidget(self.employee_target_input)
        
        left_layout.addWidget(QLabel("Employee Sources:"))
        
        buttons = [
            ("LinkedIn", self.run_linkedin_search),
            ("Hunter.io", self.run_hunter_io),
            ("Clearbit", self.run_clearbit),
            ("Email Patterns", self.generate_email_patterns)
        ]
        
        self.employee_buttons = []
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            left_layout.addWidget(btn)
            self.employee_buttons.append(btn)
        
        left_layout.addStretch()
        
        # Right panel - output
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        self.employee_output = QTextEdit()
        self.employee_output.setReadOnly(True)
        self.employee_output.setPlaceholderText("Employee enumeration results will appear here...")
        right_layout.addWidget(self.employee_output)
        
        layout.addWidget(left_panel)
        layout.addWidget(right_panel)
        
        return tab

    def create_social_tab(self):
        tab = QWidget()
        layout = QHBoxLayout(tab)
        
        # Left panel - controls
        left_panel = QFrame()
        left_panel.setFixedWidth(200)
        left_layout = QVBoxLayout(left_panel)
        
        self.social_target_input = QLineEdit()
        self.social_target_input.setPlaceholderText("username or company")
        left_layout.addWidget(QLabel("Target:"))
        left_layout.addWidget(self.social_target_input)
        
        left_layout.addWidget(QLabel("Social Platforms:"))
        
        buttons = [
            ("Twitter/X", self.search_twitter),
            ("Facebook", self.search_facebook),
            ("Instagram", self.search_instagram),
            ("GitHub", self.search_github),
            ("All Platforms", self.search_all_social)
        ]
        
        self.social_buttons = []
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            left_layout.addWidget(btn)
            self.social_buttons.append(btn)
        
        left_layout.addStretch()
        
        # Right panel - output
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        self.social_output = QTextEdit()
        self.social_output.setReadOnly(True)
        self.social_output.setPlaceholderText("Social media intelligence will appear here...")
        right_layout.addWidget(self.social_output)
        
        layout.addWidget(left_panel)
        layout.addWidget(right_panel)
        
        return tab

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
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QLineEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QLabel {
                color: #64C8FF;
                font-weight: bold;
            }
            QTabWidget::pane {
                border: 1px solid rgba(100, 200, 255, 50);
                background-color: rgba(0, 0, 0, 50);
            }
            QTabBar::tab {
                background-color: rgba(30, 40, 50, 150);
                color: #DCDCDC;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: rgba(50, 70, 90, 200);
                color: #64C8FF;
            }
        """)

    def run_hibp_check(self):
        target = self.breach_target_input.text().strip()
        if not target:
            self.breach_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter an email address</p>")
            return
        self.breach_output.clear()
        self.breach_output.setHtml(f"""
        <p style='color: #64C8FF;'>Checking {target} against Have I Been Pwned database...</p>
        <p style='color: #00FF41;'>[INFO] This would check against HIBP API</p>
        <p style='color: #DCDCDC;'>Note: Implement actual HIBP API integration</p>
        """)

    def run_dehashed(self):
        target = self.breach_target_input.text().strip()
        if not target:
            self.breach_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter an email or domain</p>")
            return
        self.breach_output.setHtml(f"""
        <p style='color: #64C8FF;'>Searching Dehashed for {target}...</p>
        <p style='color: #00FF41;'>[INFO] This would query Dehashed API</p>
        <p style='color: #DCDCDC;'>Note: Requires Dehashed API key</p>
        """)

    def run_breach_db(self):
        target = self.breach_target_input.text().strip()
        if not target:
            self.breach_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter an email or domain</p>")
            return
        self.breach_output.setHtml(f"""
        <p style='color: #64C8FF;'>Searching breach databases for {target}...</p>
        <p style='color: #00FF41;'>[INFO] This would search local breach databases</p>
        <p style='color: #DCDCDC;'>Note: Implement breach database integration</p>
        """)

    def run_all_breach_checks(self):
        target = self.breach_target_input.text().strip()
        if not target:
            self.breach_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter an email or domain</p>")
            return
        self.breach_output.setHtml(f"""
        <p style='color: #64C8FF;'>Running comprehensive breach check for {target}...</p>
        <p style='color: #00FF41;'>[INFO] Checking HIBP, Dehashed, and local databases</p>
        <p style='color: #DCDCDC;'>Note: This would run all breach checking tools</p>
        """)

    def run_linkedin_search(self):
        target = self.employee_target_input.text().strip()
        if not target:
            self.employee_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a company domain</p>")
            return
        self.employee_output.setHtml(f"""
        <p style='color: #64C8FF;'>Searching LinkedIn for employees at {target}...</p>
        <p style='color: #00FF41;'>[INFO] This would perform LinkedIn OSINT</p>
        <p style='color: #DCDCDC;'>Note: Implement LinkedIn scraping tools</p>
        """)

    def run_hunter_io(self):
        target = self.employee_target_input.text().strip()
        if not target:
            self.employee_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a company domain</p>")
            return
        self.employee_output.setHtml(f"""
        <p style='color: #64C8FF;'>Querying Hunter.io for {target} employees...</p>
        <p style='color: #00FF41;'>[INFO] This would use Hunter.io API</p>
        <p style='color: #DCDCDC;'>Note: Requires Hunter.io API key</p>
        """)

    def run_clearbit(self):
        target = self.employee_target_input.text().strip()
        if not target:
            self.employee_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a company domain</p>")
            return
        self.employee_output.setHtml(f"""
        <p style='color: #64C8FF;'>Searching Clearbit for {target} information...</p>
        <p style='color: #00FF41;'>[INFO] This would use Clearbit API</p>
        <p style='color: #DCDCDC;'>Note: Requires Clearbit API key</p>
        """)

    def generate_email_patterns(self):
        target = self.employee_target_input.text().strip()
        if not target:
            self.employee_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a company domain</p>")
            return
        self.employee_output.setHtml(f"""
        <p style='color: #64C8FF;'>Common Email Patterns for {target}:</p>
        <div style='color: #00FF41; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0;'>
        firstname.lastname@{target}<br>
        firstname@{target}<br>
        f.lastname@{target}<br>
        flastname@{target}<br>
        firstname_lastname@{target}<br>
        firstnamelastname@{target}
        </div>
        <p style='color: #DCDCDC;'>Use these patterns with discovered employee names</p>
        """)

    def search_twitter(self):
        target = self.social_target_input.text().strip()
        if not target:
            self.social_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a target</p>")
            return
        self.social_output.setHtml(f"""
        <p style='color: #64C8FF;'>Searching Twitter/X for {target}...</p>
        <p style='color: #00FF41;'>[INFO] This would search Twitter API</p>
        <p style='color: #DCDCDC;'>Note: Implement Twitter API integration</p>
        """)

    def search_facebook(self):
        target = self.social_target_input.text().strip()
        if not target:
            self.social_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a target</p>")
            return
        self.social_output.setHtml(f"""
        <p style='color: #64C8FF;'>Searching Facebook for {target}...</p>
        <p style='color: #00FF41;'>[INFO] This would search Facebook Graph API</p>
        <p style='color: #DCDCDC;'>Note: Limited by Facebook's privacy settings</p>
        """)

    def search_instagram(self):
        target = self.social_target_input.text().strip()
        if not target:
            self.social_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a target</p>")
            return
        self.social_output.setHtml(f"""
        <p style='color: #64C8FF;'>Searching Instagram for {target}...</p>
        <p style='color: #00FF41;'>[INFO] This would search Instagram API</p>
        <p style='color: #DCDCDC;'>Note: Implement Instagram scraping tools</p>
        """)

    def search_github(self):
        target = self.social_target_input.text().strip()
        if not target:
            self.social_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a target</p>")
            return
        self.social_output.setHtml(f"""
        <p style='color: #64C8FF;'>Searching GitHub for {target}...</p>
        <p style='color: #00FF41;'>[INFO] This would search GitHub API</p>
        <p style='color: #DCDCDC;'>Note: Look for exposed credentials and sensitive data</p>
        """)

    def search_all_social(self):
        target = self.social_target_input.text().strip()
        if not target:
            self.social_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a target</p>")
            return
        self.social_output.setHtml(f"""
        <p style='color: #64C8FF;'>Comprehensive social media search for {target}...</p>
        <p style='color: #00FF41;'>[INFO] Searching Twitter, Facebook, Instagram, GitHub</p>
        <p style='color: #DCDCDC;'>Note: This would run all social media tools</p>
        """)

    def setup_shortcuts(self):
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))