# app/pages/vuln_scanning_page_refactored.py
import logging
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, 
                            QVBoxLayout, QHBoxLayout, QFrame, QSizePolicy)
from PyQt6.QtCore import pyqtSignal, QThreadPool
from PyQt6.QtGui import QShortcut, QKeySequence
from app.core.base_worker import CommandWorker

class VulnScanningPage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("VulnScanningPage")

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
        
        title = QLabel("Vulnerability Scanning")
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
        self.target_input.setPlaceholderText("Target IP/hostname...")
        layout.addWidget(QLabel("Target:"))
        layout.addWidget(self.target_input)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port (optional)")
        layout.addWidget(QLabel("Port:"))
        layout.addWidget(self.port_input)
        
        self.cve_input = QLineEdit()
        self.cve_input.setPlaceholderText("CVE-2021-41773")
        layout.addWidget(QLabel("CVE:"))
        layout.addWidget(self.cve_input)
        
        layout.addWidget(QLabel("Scan Types:"))
        
        # Scan buttons
        buttons = [
            ("All Vulnerabilities", self.run_all_vulns),
            ("Common Vulns", self.run_common_vulns),
            ("Specific CVE", self.run_specific_cve),
            ("List Scripts", self.list_vuln_scripts)
        ]
        
        self.scan_buttons = []
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            layout.addWidget(btn)
            self.scan_buttons.append(btn)
        
        layout.addStretch()
        return panel

    def create_right_panel(self):
        panel = QFrame()
        layout = QVBoxLayout(panel)
        
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setPlaceholderText("Vulnerability scan results will appear here...")
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

    def run_all_vulns(self):
        port = self.port_input.text().strip()
        cmd = ["python", "tools/nse_vuln_scanner.py"]
        if port:
            cmd.extend(["--port", port])
        cmd.append("--all")
        self.run_nse_command(cmd, "Running comprehensive vulnerability scan")

    def run_common_vulns(self):
        port = self.port_input.text().strip() or "443"
        cmd = ["python", "tools/nse_vuln_scanner.py", "--common", "--port", port]
        self.run_nse_command(cmd, f"Scanning for common vulnerabilities on port {port}")

    def run_specific_cve(self):
        cve = self.cve_input.text().strip()
        if not cve:
            self.show_error("Please enter a CVE identifier")
            return
        port = self.port_input.text().strip() or "443"
        cmd = ["python", "tools/nse_vuln_scanner.py", "--cve", cve, "--port", port]
        self.run_nse_command(cmd, f"Scanning for {cve} on port {port}")

    def list_vuln_scripts(self):
        cmd = ["python", "tools/nse_vuln_scanner.py", "--list"]
        self.terminal_output.clear()
        self.set_buttons_enabled(False)
        worker = CommandWorker(cmd, "Listing available NSE vulnerability scripts", str(self.main_window.project_root))
        worker.signals.output.connect(self.append_terminal_output)
        worker.signals.finished.connect(lambda: self.set_buttons_enabled(True))
        QThreadPool.globalInstance().start(worker)

    def run_nse_command(self, cmd, description):
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        self.terminal_output.clear()
        self.set_buttons_enabled(False)
        full_cmd = cmd + [target]
        worker = CommandWorker(full_cmd, description, str(self.main_window.project_root))
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
        for button in self.scan_buttons:
            button.setEnabled(enabled)

    def setup_shortcuts(self):
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))
        self.clear_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.clear_shortcut.activated.connect(lambda: self.terminal_output.clear())