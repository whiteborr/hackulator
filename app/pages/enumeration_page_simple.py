# app/pages/enumeration_page_simple.py
import logging
import os
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, 
                            QComboBox, QCheckBox, QVBoxLayout, QHBoxLayout, 
                            QFrame, QSizePolicy, QScrollArea, QStatusBar)
from PyQt6.QtCore import pyqtSignal, QSize, Qt, QThreadPool
from PyQt6.QtGui import QPixmap, QIcon, QShortcut, QKeySequence

from app.core import custom_scripts
from app.core.validators import InputValidator
from app.core.exporter import exporter
from app.core.base_worker import CommandWorker
from app.widgets.progress_widget import ProgressWidget

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

class EnumerationPage(QWidget):
    navigate_signal = pyqtSignal(str)
    status_updated = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.current_submenu = "dns"
        self.setObjectName("EnumerationPage")

        # Create main layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(10)

        # Create header
        self.header = self.create_header()
        self.main_layout.addWidget(self.header)

        # Create content area
        self.content_area = QHBoxLayout()
        self.main_layout.addLayout(self.content_area)

        # Create tool selection panel (left)
        self.tool_panel = self.create_tool_panel()
        self.content_area.addWidget(self.tool_panel, 0)

        # Create main work area (right)
        self.work_area = self.create_work_area()
        self.content_area.addWidget(self.work_area, 1)

        # Initialize data and setup
        self.setup_tool_data()
        self.setup_shortcuts()
        self.apply_theme()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    def create_header(self):
        header_frame = QFrame()
        header_frame.setFixedHeight(60)
        header_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)

        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(15, 10, 15, 10)

        self.back_button = QPushButton("← Back to Home")
        self.back_button.clicked.connect(lambda: self.navigate_signal.emit("home"))
        self.back_button.setFixedWidth(150)

        self.title_label = QLabel("Enumeration Tools")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        header_layout.addWidget(self.back_button)
        header_layout.addWidget(self.title_label, 1)
        header_layout.addStretch()

        return header_frame

    def create_tool_panel(self):
        tool_frame = QFrame()
        tool_frame.setFixedWidth(300)
        tool_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        tool_widget = QWidget()
        self.tool_layout = QVBoxLayout(tool_widget)
        self.tool_layout.setContentsMargins(10, 10, 10, 10)
        self.tool_layout.setSpacing(8)

        scroll_area.setWidget(tool_widget)

        frame_layout = QVBoxLayout(tool_frame)
        frame_layout.setContentsMargins(5, 5, 5, 5)
        frame_layout.addWidget(scroll_area)

        return tool_frame

    def create_work_area(self):
        work_frame = QFrame()
        work_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)

        work_layout = QVBoxLayout(work_frame)
        work_layout.setContentsMargins(15, 15, 15, 15)
        work_layout.setSpacing(10)

        # Controls section
        self.controls_section = self.create_controls_section()
        work_layout.addWidget(self.controls_section)

        # Output section
        self.output_section = self.create_output_section()
        work_layout.addWidget(self.output_section, 1)

        # Progress section
        self.progress_widget = ProgressWidget(self)
        self.progress_widget.setVisible(False)
        work_layout.addWidget(self.progress_widget)

        return work_frame

    def create_controls_section(self):
        controls_frame = QFrame()
        controls_frame.setFixedHeight(120)

        controls_layout = QVBoxLayout(controls_frame)
        controls_layout.setContentsMargins(10, 10, 10, 10)
        controls_layout.setSpacing(8)

        # First row: Target input and wordlist
        first_row = QHBoxLayout()
        
        target_label = QLabel("Target:")
        target_label.setFixedWidth(60)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target (IP, domain, or range)...")
        
        wordlist_label = QLabel("Wordlist:")
        wordlist_label.setFixedWidth(70)
        
        self.wordlist_combo = QComboBox()
        self.wordlist_combo.setFixedWidth(200)
        self.populate_wordlists()

        first_row.addWidget(target_label)
        first_row.addWidget(self.target_input, 1)
        first_row.addWidget(wordlist_label)
        first_row.addWidget(self.wordlist_combo)

        # Second row: Record types and export controls
        second_row = QHBoxLayout()
        
        record_label = QLabel("Types:")
        record_label.setFixedWidth(60)
        
        self.record_type_checkboxes = {}
        for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
            checkbox = QCheckBox(record_type)
            if record_type == 'A':
                checkbox.setChecked(True)
            self.record_type_checkboxes[record_type] = checkbox
            second_row.addWidget(checkbox)

        second_row.addStretch()

        self.export_combo = QComboBox()
        self.export_combo.addItems(["JSON", "CSV", "XML"])
        self.export_combo.setFixedWidth(110)

        self.export_button = QPushButton("Export")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        self.export_button.setFixedWidth(80)

        second_row.addWidget(self.export_combo)
        second_row.addWidget(self.export_button)

        controls_layout.addLayout(first_row)
        controls_layout.addLayout(second_row)

        return controls_frame

    def create_output_section(self):
        output_frame = QFrame()
        output_layout = QHBoxLayout(output_frame)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.setSpacing(10)

        # Tool buttons panel (left)
        self.tool_buttons_panel = QFrame()
        self.tool_buttons_panel.setFixedWidth(120)

        self.tool_buttons_layout = QVBoxLayout(self.tool_buttons_panel)
        self.tool_buttons_layout.setContentsMargins(5, 5, 5, 5)
        self.tool_buttons_layout.setSpacing(5)

        # Terminal output (right)
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setPlaceholderText("Tool output will appear here...")

        output_layout.addWidget(self.tool_buttons_panel)
        output_layout.addWidget(self.terminal_output, 1)

        return output_frame

    def setup_tool_data(self):
        self.main_tools_data = [
            {"id": "dns_enum", "title": "DNS Enumeration", "desc": "Discover domains, subdomains, and IPs.", "icon": "resources/icons/1A.png"},
            {"id": "port_scan", "title": "Port Scanning", "desc": "Identify open ports and services running.", "icon": "resources/icons/1B.png"},
            {"id": "smb_enum", "title": "SMB Enumeration", "desc": "List shares and users via Windows SMB.", "icon": "resources/icons/1C.png"},
            {"id": "smtp_enum", "title": "SMTP Enumeration", "desc": "Probe mail servers for valid emails.", "icon": "resources/icons/1D.png"},
            {"id": "snmp_enum", "title": "SNMP Enumeration", "desc": "Extract network device info using SNMP.", "icon": "resources/icons/1E.png"},
            {"id": "http_fingerprint", "title": "HTTP/S Fingerprinting", "desc": "Identify web server type and technologies.", "icon": "resources/icons/1F.png"},
        ]

        # Create main tool buttons
        self.main_tool_buttons = []
        for tool in self.main_tools_data:
            button = self.create_main_tool_button(tool)
            self.tool_layout.addWidget(button)
            self.main_tool_buttons.append(button)

        self.tool_layout.addStretch()

        # Setup tool-specific data
        self.dns_tools_data = [
            {"id": "dns_hosts", "text": "HOSTS", "method": self.run_host_wordlist_scan},
            {"id": "dns_ptr", "text": "PTR", "method": self.run_ptr_scan},
        ]

        self.last_scan_results = {}
        self.last_scan_target = ""

    def create_main_tool_button(self, tool_data):
        button = HoverButton(tool_data["title"], tool_data["desc"], self)
        button.setMinimumHeight(50)
        button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        icon_path = os.path.join(self.main_window.project_root, tool_data["icon"])
        icon = QIcon(icon_path)
        if not icon.isNull():
            button.setIcon(icon)
            button.setIconSize(QSize(24, 24))

        button.setText(tool_data["title"])
        button.clicked.connect(lambda: self.activate_tool_submenu(tool_data["id"]))
        button.enter_signal.connect(self.update_status_bar)
        button.leave_signal.connect(self.clear_status_bar)

        return button

    def activate_tool_submenu(self, tool_id):
        self.current_submenu = tool_id
        self.update_tool_buttons()
        self.status_updated.emit(f"Selected: {tool_id.replace('_', ' ').title()}")

    def update_tool_buttons(self):
        # Clear existing buttons
        for i in reversed(range(self.tool_buttons_layout.count())):
            child = self.tool_buttons_layout.itemAt(i).widget()
            if child:
                child.setParent(None)

        # Add new buttons based on current submenu
        if self.current_submenu == "dns_enum":
            for tool_data in self.dns_tools_data:
                button = QPushButton(tool_data["text"])
                button.setMinimumHeight(35)
                button.clicked.connect(tool_data["method"])
                self.tool_buttons_layout.addWidget(button)

        self.tool_buttons_layout.addStretch()

    def populate_wordlists(self):
        wordlist_dir = os.path.join(self.main_window.project_root, "resources", "wordlists")
        if os.path.exists(wordlist_dir):
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt"):
                    self.wordlist_combo.addItem(filename, os.path.join(wordlist_dir, filename))

    def update_status_bar(self, title, description):
        self.status_updated.emit(f"{title}: {description}")

    def clear_status_bar(self):
        self.status_updated.emit("")

    def apply_theme(self):
        pass

    def setup_shortcuts(self):
        self.scan_shortcut = QShortcut(QKeySequence("F5"), self)
        self.scan_shortcut.activated.connect(self.run_host_wordlist_scan)
        
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))

    def run_host_wordlist_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target domain")
            return

        wordlist_path = self.wordlist_combo.currentData()
        selected_types = [rtype for rtype, cb in self.record_type_checkboxes.items() if cb.isChecked()]

        self.terminal_output.clear()
        self.progress_widget.setVisible(True)
        self.status_updated.emit(f"Starting DNS enumeration on {target}...")

        custom_scripts.enumerate_hostnames(
            target=target,
            wordlist_path=wordlist_path,
            record_types=selected_types,
            output_callback=self.append_terminal_output,
            status_callback=self.update_status_bar_text,
            finished_callback=self.on_scan_finished,
            results_callback=self.store_scan_results,
            progress_callback=self.update_progress,
            progress_start_callback=self.start_progress
        )

    def run_ptr_scan(self):
        self.show_info("PTR scan functionality")

    def show_error(self, message):
        self.terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {message}</p>")
        self.status_updated.emit(f"Error: {message}")

    def show_info(self, message):
        self.terminal_output.setHtml(f"<p style='color: #64C8FF;'>[INFO] {message}</p>")

    def append_terminal_output(self, text):
        self.terminal_output.insertHtml(text)
        scrollbar = self.terminal_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def update_status_bar_text(self, text):
        self.status_updated.emit(text)

    def store_scan_results(self, results):
        self.last_scan_results = results
        self.export_button.setEnabled(True)

    def start_progress(self, total_items):
        self.progress_widget.start_progress(total_items, "Scanning...")

    def update_progress(self, completed_items, results_found):
        self.progress_widget.update_progress(completed_items, results_found)

    def on_scan_finished(self):
        self.progress_widget.finish_progress("Scan Complete")
        self.status_updated.emit("Scan completed successfully")

    def export_results(self):
        if not self.last_scan_results:
            self.show_error("No scan results to export")
            return

        format_type = self.export_combo.currentText().lower()
        success, filepath, message = exporter.export_results(
            self.last_scan_results,
            self.last_scan_target,
            format_type
        )

        if success:
            self.show_info(f"Results exported to: {filepath}")
        else:
            self.show_error(f"Export failed: {message}")