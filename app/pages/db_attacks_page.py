# app/pages/db_attacks_page_refactored.py
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, 
                            QVBoxLayout, QHBoxLayout, QFrame)
from PyQt6.QtCore import pyqtSignal, QThreadPool
from PyQt6.QtGui import QShortcut, QKeySequence
from app.core.base_worker import CommandWorker

class DbAttacksPage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("DbAttacksPage")

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
        
        title = QLabel("Database Attacks")
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
        panel.setFixedWidth(200)
        layout = QVBoxLayout(panel)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Target URL/IP...")
        layout.addWidget(QLabel("Target:"))
        layout.addWidget(self.target_input)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("sa, root")
        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password_input)
        
        layout.addWidget(QLabel("Attack Types:"))
        
        buttons = [
            ("SQL Injection", self.test_sql_injection),
            ("Blind SQL", self.test_blind_sql),
            ("Union SQL", self.test_union_sql),
            ("MSSQL", self.test_mssql),
            ("MySQL", self.test_mysql),
            ("All Tests", self.test_all_attacks)
        ]
        
        self.db_buttons = []
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            layout.addWidget(btn)
            self.db_buttons.append(btn)
        
        layout.addStretch()
        return panel

    def create_right_panel(self):
        panel = QFrame()
        layout = QVBoxLayout(panel)
        
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setPlaceholderText("Database attack results will appear here...")
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

    def _run_command(self, tool, args, description):
        """Helper function to run a command-line tool."""
        from app.core.error_context import handle_errors
        
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target")
            return

        with handle_errors(f"Command Execution: {description}"):
            self.terminal_output.clear()
            self.set_buttons_enabled(False)

            full_cmd = ["python", f"tools/{tool}.py", target] + args
            worker = CommandWorker(full_cmd, description, str(self.main_window.project_root))
            worker.signals.output.connect(self.append_terminal_output)
            worker.signals.finished.connect(lambda: self.set_buttons_enabled(True))
            QThreadPool.globalInstance().start(worker)

    def test_sql_injection(self):
        self._run_command("db_attacks", ["--sql-inject"], "Testing for SQL injection vulnerabilities")

    def test_blind_sql(self):
        self._run_command("db_attacks", ["--blind-sql"], "Testing for blind SQL injection")

    def test_union_sql(self):
        self._run_command("db_attacks", ["--union-sql"], "Testing for UNION-based SQL injection")

    def test_mssql(self):
        username = self.username_input.text().strip() or "sa"
        password = self.password_input.text().strip()
        args = ["--mssql", "--username", username]
        if password:
            args.extend(["--password", password])
        self._run_command("db_attacks", args, "Testing MSSQL connection and exploitation")

    def test_mysql(self):
        username = self.username_input.text().strip() or "root"
        password = self.password_input.text().strip()
        args = ["--mysql", "--username", username]
        if password:
            args.extend(["--password", password])
        self._run_command("db_attacks", args, "Testing MySQL connection and exploitation")

    def test_all_attacks(self):
        self._run_command("db_attacks", ["--all"], "Running comprehensive database attack tests")



    def show_error(self, message):
        self.terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {message}</p>")

    def append_terminal_output(self, text):
        self.terminal_output.insertHtml(text)
        scrollbar = self.terminal_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def set_buttons_enabled(self, enabled):
        for button in self.db_buttons:
            button.setEnabled(enabled)

    def setup_shortcuts(self):
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))
        self.clear_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.clear_shortcut.activated.connect(lambda: self.terminal_output.clear())