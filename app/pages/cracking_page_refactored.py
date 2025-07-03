# app/pages/cracking_page_refactored.py
import logging
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, 
                            QVBoxLayout, QHBoxLayout, QFrame)
from PyQt6.QtCore import pyqtSignal, QThreadPool
from PyQt6.QtGui import QShortcut, QKeySequence
from app.core.base_worker import CommandWorker

class CrackingPage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("CrackingPage")

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
        
        title = QLabel("Password Cracking")
        title.setObjectName("TitleLabel")
        
        header_layout.addWidget(self.back_button)
        header_layout.addWidget(title, 1)
        header_layout.addStretch()
        
        self.main_layout.addWidget(header_frame)

    def create_content_area(self):
        content_layout = QHBoxLayout()
        
        # Left panel - controls
        left_panel = self.create_left_panel()
        content_layout.addWidget(left_panel, 0)
        
        # Right panel - output
        right_panel = self.create_right_panel()
        content_layout.addWidget(right_panel, 1)
        
        self.main_layout.addLayout(content_layout)

    def create_left_panel(self):
        panel = QFrame()
        panel.setFixedWidth(200)
        layout = QVBoxLayout(panel)
        
        # Input controls
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Hash file path...")
        layout.addWidget(QLabel("Target:"))
        layout.addWidget(self.target_input)
        
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Hash value...")
        layout.addWidget(QLabel("Hash:"))
        layout.addWidget(self.hash_input)
        
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setPlaceholderText("Wordlist path...")
        layout.addWidget(QLabel("Wordlist:"))
        layout.addWidget(self.wordlist_input)
        
        layout.addWidget(QLabel("Cracking Tools:"))
        
        # Cracking buttons
        buttons = [
            ("Hashcat", self.run_hashcat),
            ("John the Ripper", self.run_john),
            ("Hydra", self.run_hydra),
            ("Responder", self.run_responder),
            ("Identify Hash", self.identify_hash),
            ("Show Rules", self.show_rules)
        ]
        
        self.crack_buttons = []
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            layout.addWidget(btn)
            self.crack_buttons.append(btn)
        
        layout.addStretch()
        return panel

    def create_right_panel(self):
        panel = QFrame()
        layout = QVBoxLayout(panel)
        
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setPlaceholderText("Password cracking results will appear here...")
        layout.addWidget(self.terminal_output)
        
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
        """)

    def run_hashcat(self):
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter hash file path")
            return
        wordlist = self.wordlist_input.text().strip() or "/usr/share/wordlists/rockyou.txt"
        cmd = ["python", "tools/cracking_tools.py", "--hashcat", target, "--wordlist", wordlist, "--hash-mode", "1000"]
        self.run_crack_command(cmd, f"Running hashcat on {target}")

    def run_john(self):
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter hash file path")
            return
        wordlist = self.wordlist_input.text().strip() or "/usr/share/wordlists/rockyou.txt"
        cmd = ["python", "tools/cracking_tools.py", "--john", target, "--wordlist", wordlist]
        self.run_crack_command(cmd, f"Running John the Ripper on {target}")

    def run_hydra(self):
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter target IP")
            return
        passlist = self.wordlist_input.text().strip() or "/usr/share/wordlists/rockyou.txt"
        cmd = ["python", "tools/cracking_tools.py", "--hydra", target, "--service", "ssh", "--username", "admin", "--passlist", passlist]
        self.run_crack_command(cmd, f"Running Hydra brute force on {target}")

    def run_responder(self):
        interface = self.target_input.text().strip() or "eth0"
        cmd = ["python", "tools/cracking_tools.py", "--responder", interface, "--timeout", "60"]
        self.run_crack_command(cmd, f"Starting Responder on interface {interface}")

    def identify_hash(self):
        hash_value = self.hash_input.text().strip()
        if not hash_value:
            self.show_error("Please enter a hash value to identify")
            return
        cmd = ["python", "tools/cracking_tools.py", "--identify-hash", hash_value]
        self.run_crack_command(cmd, "Identifying hash type")

    def show_rules(self):
        cmd = ["python", "tools/cracking_tools.py", "--show-rules"]
        self.run_crack_command(cmd, "Displaying common password mutation rules")

    def run_crack_command(self, cmd, description):
        self.terminal_output.clear()
        self.set_buttons_enabled(False)
        worker = CommandWorker(cmd, description, str(self.main_window.project_root))
        worker.signals.output.connect(self.append_terminal_output)
        worker.signals.finished.connect(lambda: self.set_buttons_enabled(True))
        QThreadPool.globalInstance().start(worker)

    def show_error(self, message):
        self.terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {message}</p>")

    def append_terminal_output(self, text):
        self.terminal_output.insertHtml(text)
        scrollbar = self.terminal_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def set_buttons_enabled(self, enabled):
        for button in self.crack_buttons:
            button.setEnabled(enabled)

    def setup_shortcuts(self):
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))
        self.clear_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.clear_shortcut.activated.connect(lambda: self.terminal_output.clear())