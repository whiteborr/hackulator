# app/pages/vuln_scanning_page.py
import logging
from PyQt6.QtWidgets import QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox
from PyQt6.QtCore import pyqtSignal, QSize, Qt, QThreadPool
from PyQt6.QtGui import QPixmap, QIcon, QShortcut, QKeySequence
from app.core.base_worker import CommandWorker

class VulnScanningPage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("VulnScanningPage")

        self.background_label = QLabel(self)
        self.background_label.setScaledContents(True)

        # --- Create UI Elements ---
        self.title = QLabel("Vulnerability Scanning", self)
        self.title.setObjectName("TitleLabel")
        
        self.back_button = QPushButton("< Back", self)
        self.back_button.setProperty("class", "backButton")
        self.back_button.clicked.connect(lambda: self.navigate_signal.emit("home"))
        
        self.target_input = QLineEdit(self)
        self.target_input.setObjectName("TargetInput")
        self.target_input.setPlaceholderText("Enter target IP or hostname...")
        
        self.port_input = QLineEdit(self)
        self.port_input.setObjectName("TargetInput")
        self.port_input.setPlaceholderText("Port (optional)")
        
        self.cve_input = QLineEdit(self)
        self.cve_input.setObjectName("TargetInput")
        self.cve_input.setPlaceholderText("CVE (e.g., CVE-2021-41773)")

        self.terminal_output = QTextEdit(self)
        self.terminal_output.setObjectName("InfoPanel")
        self.terminal_output.setReadOnly(True)

        # --- NSE Tool Buttons ---
        self.nse_buttons_data = [
            {"id": "vuln_all", "text": "ALL VULNS", "rect": (135, 225, 105, 30)},
            {"id": "vuln_common", "text": "COMMON", "rect": (135, 283, 105, 30)},
            {"id": "vuln_cve", "text": "SPECIFIC CVE", "rect": (135, 341, 105, 30)},
            {"id": "vuln_list", "text": "LIST SCRIPTS", "rect": (135, 398, 105, 30)},
        ]

        self.nse_buttons = []
        for button_data in self.nse_buttons_data:
            button = QPushButton(button_data["text"], self)
            button.setProperty("class", "dnsToolButton")
            
            if button_data["id"] == "vuln_all":
                button.clicked.connect(self.run_all_vulns)
            elif button_data["id"] == "vuln_common":
                button.clicked.connect(self.run_common_vulns)
            elif button_data["id"] == "vuln_cve":
                button.clicked.connect(self.run_specific_cve)
            elif button_data["id"] == "vuln_list":
                button.clicked.connect(self.list_vuln_scripts)
                
            self.nse_buttons.append(button)

        self.setup_shortcuts()
        self.resizeEvent(None)
        self.apply_theme()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    def resizeEvent(self, event):
        if event: super().resizeEvent(event)
        
        self.background_label.setGeometry(0, 0, self.width(), self.height())
        
        new_size = self.main_window.size()
        original_size = self.main_window.original_size
        ws = new_size.width() / original_size.width()
        hs = new_size.height() / original_size.height()

        self.title.setGeometry(int(340 * ws), int(40 * hs), int(400 * ws), int(50 * hs))
        self.back_button.setGeometry(int(20 * ws), int(20 * hs), int(150 * ws), int(50 * hs))
        
        term_x, term_y, term_w, term_h = 340, 175, 1731 - 340, 770 - 175
        self.terminal_output.setGeometry(term_x, term_y, term_w, term_h)

        controls_y = term_y + term_h + 20
        control_height = 36
        
        self.target_input.setGeometry(term_x, controls_y, 300, control_height)
        self.port_input.setGeometry(term_x + 320, controls_y, 100, control_height)
        self.cve_input.setGeometry(term_x + 440, controls_y, 200, control_height)

        for i, button in enumerate(self.nse_buttons):
            x, y, w, h = self.nse_buttons_data[i]["rect"]
            button.setGeometry(x, y, w, h)

    def apply_theme(self):
        theme = self.main_window.theme_manager
        bg_path = theme.get("backgrounds.enumeration")
        if bg_path: self.background_label.setPixmap(QPixmap(bg_path))

    def append_terminal_output(self, text):
        self.terminal_output.insertHtml(text)
        self.terminal_output.verticalScrollBar().setValue(self.terminal_output.verticalScrollBar().maximum())

    def set_buttons_enabled(self, enabled):
        for button in self.nse_buttons:
            button.setEnabled(enabled)

    def show_error(self, message):
        self.terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {message}</p>")

    def run_nse_command(self, cmd, description):
        target = self.target_input.text().strip()
        if not target:
            return self.show_error("Please enter a target")
        
        self.terminal_output.clear()
        self.set_buttons_enabled(False)
        
        full_cmd = cmd + [target]
        worker = CommandWorker(full_cmd, description, str(self.main_window.project_root))
        worker.signals.output.connect(self.append_terminal_output)
        worker.signals.error.connect(self.append_terminal_output)
        worker.signals.finished.connect(lambda: self.set_buttons_enabled(True))
        QThreadPool.globalInstance().start(worker)

    def run_all_vulns(self):
        port = self.port_input.text().strip()
        cmd = ["python", "tools/nse_vuln_scanner.py"]
        if port:
            cmd.extend(["--port", port])
        cmd.append("--all")
        self.run_nse_command(cmd, f"Running comprehensive vulnerability scan")

    def run_common_vulns(self):
        port = self.port_input.text().strip() or "443"
        cmd = ["python", "tools/nse_vuln_scanner.py", "--common", "--port", port]
        self.run_nse_command(cmd, f"Scanning for common vulnerabilities on port {port}")

    def run_specific_cve(self):
        cve = self.cve_input.text().strip()
        if not cve:
            return self.show_error("Please enter a CVE identifier")
        
        port = self.port_input.text().strip() or "443"
        cmd = ["python", "tools/nse_vuln_scanner.py", "--cve", cve, "--port", port]
        self.run_nse_command(cmd, f"Scanning for {cve} on port {port}")

    def list_vuln_scripts(self):
        cmd = ["python", "tools/nse_vuln_scanner.py", "--list"]
        # For listing, we don't need a target
        self.terminal_output.clear()
        self.set_buttons_enabled(False)
        
        worker = CommandWorker(cmd, "Listing available NSE vulnerability scripts", str(self.main_window.project_root))
        worker.signals.output.connect(self.append_terminal_output)
        worker.signals.error.connect(self.append_terminal_output)
        worker.signals.finished.connect(lambda: self.set_buttons_enabled(True))
        QThreadPool.globalInstance().start(worker)

    def setup_shortcuts(self):
        self.clear_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.clear_shortcut.activated.connect(self.clear_terminal)
        
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))
    
    def clear_terminal(self):
        self.terminal_output.clear()