# app/pages/cracking_page.py
import logging
import subprocess
import threading
from PyQt6.QtWidgets import QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox
from PyQt6.QtCore import pyqtSignal, QSize, Qt
from PyQt6.QtGui import QPixmap, QIcon, QShortcut, QKeySequence

class CrackingPage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("CrackingPage")

        self.background_label = QLabel(self)
        self.background_label.setScaledContents(True)

        # --- Create UI Elements ---
        self.title = QLabel("Password Cracking", self)
        self.title.setObjectName("TitleLabel")
        
        self.back_button = QPushButton("< Back", self)
        self.back_button.setProperty("class", "backButton")
        self.back_button.clicked.connect(lambda: self.navigate_signal.emit("home"))
        
        self.target_input = QLineEdit(self)
        self.target_input.setObjectName("TargetInput")
        self.target_input.setPlaceholderText("Target IP or hash file...")
        
        self.hash_input = QLineEdit(self)
        self.hash_input.setObjectName("TargetInput")
        self.hash_input.setPlaceholderText("Hash value (for identification)")
        
        self.wordlist_input = QLineEdit(self)
        self.wordlist_input.setObjectName("TargetInput")
        self.wordlist_input.setPlaceholderText("Wordlist path")

        self.terminal_output = QTextEdit(self)
        self.terminal_output.setObjectName("InfoPanel")
        self.terminal_output.setReadOnly(True)

        # --- Cracking Tool Buttons ---
        self.crack_buttons_data = [
            {"id": "hashcat", "text": "HASHCAT", "rect": (135, 225, 105, 30)},
            {"id": "john", "text": "JOHN", "rect": (135, 283, 105, 30)},
            {"id": "hydra", "text": "HYDRA", "rect": (135, 341, 105, 30)},
            {"id": "responder", "text": "RESPONDER", "rect": (135, 398, 105, 30)},
            {"id": "identify", "text": "IDENTIFY", "rect": (135, 458, 105, 30)},
            {"id": "rules", "text": "SHOW RULES", "rect": (135, 518, 105, 30)},
        ]

        self.crack_buttons = []
        for button_data in self.crack_buttons_data:
            button = QPushButton(button_data["text"], self)
            button.setProperty("class", "dnsToolButton")
            
            if button_data["id"] == "hashcat":
                button.clicked.connect(self.run_hashcat)
            elif button_data["id"] == "john":
                button.clicked.connect(self.run_john)
            elif button_data["id"] == "hydra":
                button.clicked.connect(self.run_hydra)
            elif button_data["id"] == "responder":
                button.clicked.connect(self.run_responder)
            elif button_data["id"] == "identify":
                button.clicked.connect(self.identify_hash)
            elif button_data["id"] == "rules":
                button.clicked.connect(self.show_rules)
                
            self.crack_buttons.append(button)

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
        
        self.target_input.setGeometry(term_x, controls_y, 200, control_height)
        self.hash_input.setGeometry(term_x + 220, controls_y, 200, control_height)
        self.wordlist_input.setGeometry(term_x + 440, controls_y, 200, control_height)

        for i, button in enumerate(self.crack_buttons):
            x, y, w, h = self.crack_buttons_data[i]["rect"]
            button.setGeometry(x, y, w, h)

    def apply_theme(self):
        theme = self.main_window.theme_manager
        bg_path = theme.get("backgrounds.enumeration")
        if bg_path: self.background_label.setPixmap(QPixmap(bg_path))

    def append_terminal_output(self, text):
        self.terminal_output.insertHtml(text)
        self.terminal_output.verticalScrollBar().setValue(self.terminal_output.verticalScrollBar().maximum())

    def set_buttons_enabled(self, enabled):
        for button in self.crack_buttons:
            button.setEnabled(enabled)

    def show_error(self, message):
        self.terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {message}</p>")

    def run_crack_command(self, cmd, description):
        self.terminal_output.clear()
        self.set_buttons_enabled(False)
        self.append_terminal_output(f"<p style='color: #64C8FF;'>[*] {description}</p>")
        
        def run_tool():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.main_window.project_root))
                self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result.stdout}</pre>")
                if result.stderr:
                    self.append_terminal_output(f"<p style='color: #FF4500;'>{result.stderr}</p>")
            except Exception as e:
                self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] {str(e)}</p>")
            finally:
                self.set_buttons_enabled(True)
        
        threading.Thread(target=run_tool, daemon=True).start()

    def run_hashcat(self):
        target = self.target_input.text().strip()
        if not target:
            return self.show_error("Please enter hash file path")
        
        wordlist = self.wordlist_input.text().strip() or "/usr/share/wordlists/rockyou.txt"
        
        cmd = ["python", "tools/cracking_tools.py", "--hashcat", target, "--wordlist", wordlist, "--hash-mode", "1000"]
        self.run_crack_command(cmd, f"Running hashcat on {target}")

    def run_john(self):
        target = self.target_input.text().strip()
        if not target:
            return self.show_error("Please enter hash file path")
        
        wordlist = self.wordlist_input.text().strip() or "/usr/share/wordlists/rockyou.txt"
        
        cmd = ["python", "tools/cracking_tools.py", "--john", target, "--wordlist", wordlist]
        self.run_crack_command(cmd, f"Running John the Ripper on {target}")

    def run_hydra(self):
        target = self.target_input.text().strip()
        if not target:
            return self.show_error("Please enter target IP")
        
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
            return self.show_error("Please enter a hash value to identify")
        
        cmd = ["python", "tools/cracking_tools.py", "--identify-hash", hash_value]
        self.run_crack_command(cmd, f"Identifying hash type")

    def show_rules(self):
        cmd = ["python", "tools/cracking_tools.py", "--show-rules"]
        self.run_crack_command(cmd, "Displaying common password mutation rules")

    def setup_shortcuts(self):
        self.clear_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.clear_shortcut.activated.connect(self.clear_terminal)
        
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))
    
    def clear_terminal(self):
        self.terminal_output.clear()