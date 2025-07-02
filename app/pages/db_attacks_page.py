# app/pages/db_attacks_page.py
import logging
from PyQt6.QtWidgets import QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox
from PyQt6.QtCore import pyqtSignal, QSize, Qt, QThreadPool
from PyQt6.QtGui import QPixmap, QIcon, QShortcut, QKeySequence
from app.core.base_worker import CommandWorker

class DbAttacksPage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("DbAttacksPage")

        self.background_label = QLabel(self)
        self.background_label.setScaledContents(True)

        # --- Create UI Elements ---
        self.title = QLabel("Database Attacks", self)
        self.title.setObjectName("TitleLabel")
        
        self.back_button = QPushButton("< Back", self)
        self.back_button.setProperty("class", "backButton")
        self.back_button.clicked.connect(lambda: self.navigate_signal.emit("home"))
        
        self.target_input = QLineEdit(self)
        self.target_input.setObjectName("TargetInput")
        self.target_input.setPlaceholderText("Enter target URL or IP...")
        
        self.username_input = QLineEdit(self)
        self.username_input.setObjectName("TargetInput")
        self.username_input.setPlaceholderText("Username (sa, root)")
        
        self.password_input = QLineEdit(self)
        self.password_input.setObjectName("TargetInput")
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.terminal_output = QTextEdit(self)
        self.terminal_output.setObjectName("InfoPanel")
        self.terminal_output.setReadOnly(True)

        # --- Database Attack Tool Buttons ---
        self.db_buttons_data = [
            {"id": "sql_inject", "text": "SQL INJECT", "rect": (135, 225, 105, 30)},
            {"id": "blind_sql", "text": "BLIND SQL", "rect": (135, 283, 105, 30)},
            {"id": "union_sql", "text": "UNION SQL", "rect": (135, 341, 105, 30)},
            {"id": "mssql_attack", "text": "MSSQL", "rect": (135, 398, 105, 30)},
            {"id": "mysql_attack", "text": "MYSQL", "rect": (135, 458, 105, 30)},
            {"id": "all_attacks", "text": "ALL TESTS", "rect": (135, 518, 105, 30)},
        ]

        self.db_buttons = []
        for button_data in self.db_buttons_data:
            button = QPushButton(button_data["text"], self)
            button.setProperty("class", "dnsToolButton")
            
            if button_data["id"] == "sql_inject":
                button.clicked.connect(self.test_sql_injection)
            elif button_data["id"] == "blind_sql":
                button.clicked.connect(self.test_blind_sql)
            elif button_data["id"] == "union_sql":
                button.clicked.connect(self.test_union_sql)
            elif button_data["id"] == "mssql_attack":
                button.clicked.connect(self.test_mssql)
            elif button_data["id"] == "mysql_attack":
                button.clicked.connect(self.test_mysql)
            elif button_data["id"] == "all_attacks":
                button.clicked.connect(self.test_all_attacks)
                
            self.db_buttons.append(button)

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
        
        self.target_input.setGeometry(term_x, controls_y, 250, control_height)
        self.username_input.setGeometry(term_x + 270, controls_y, 150, control_height)
        self.password_input.setGeometry(term_x + 440, controls_y, 150, control_height)

        for i, button in enumerate(self.db_buttons):
            x, y, w, h = self.db_buttons_data[i]["rect"]
            button.setGeometry(x, y, w, h)

    def apply_theme(self):
        theme = self.main_window.theme_manager
        bg_path = theme.get("backgrounds.enumeration")
        if bg_path: self.background_label.setPixmap(QPixmap(bg_path))

    def append_terminal_output(self, text):
        self.terminal_output.insertHtml(text)
        self.terminal_output.verticalScrollBar().setValue(self.terminal_output.verticalScrollBar().maximum())

    def set_buttons_enabled(self, enabled):
        for button in self.db_buttons:
            button.setEnabled(enabled)

    def show_error(self, message):
        self.terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {message}</p>")

    def run_db_command(self, cmd, description):
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

    def test_sql_injection(self):
        cmd = ["python", "tools/db_attacks.py", "--sql-inject"]
        self.run_db_command(cmd, "Testing for SQL injection vulnerabilities")

    def test_blind_sql(self):
        cmd = ["python", "tools/db_attacks.py", "--blind-sql"]
        self.run_db_command(cmd, "Testing for blind SQL injection")

    def test_union_sql(self):
        cmd = ["python", "tools/db_attacks.py", "--union-sql"]
        self.run_db_command(cmd, "Testing for UNION-based SQL injection")

    def test_mssql(self):
        username = self.username_input.text().strip() or "sa"
        password = self.password_input.text().strip()
        
        cmd = ["python", "tools/db_attacks.py", "--mssql", "--username", username]
        if password:
            cmd.extend(["--password", password])
        
        self.run_db_command(cmd, f"Testing MSSQL connection and exploitation")

    def test_mysql(self):
        username = self.username_input.text().strip() or "root"
        password = self.password_input.text().strip()
        
        cmd = ["python", "tools/db_attacks.py", "--mysql", "--username", username]
        if password:
            cmd.extend(["--password", password])
        
        self.run_db_command(cmd, f"Testing MySQL connection and exploitation")

    def test_all_attacks(self):
        cmd = ["python", "tools/db_attacks.py", "--all"]
        self.run_db_command(cmd, "Running comprehensive database attack tests")

    def setup_shortcuts(self):
        self.clear_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.clear_shortcut.activated.connect(self.clear_terminal)
        
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))
    
    def clear_terminal(self):
        self.terminal_output.clear()