# --- FULL UPDATED enumeration_page.py ---
import os
import logging
import time
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
import time

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
        self.current_submenu = "dns_enum"
        self.setObjectName("EnumerationPage")

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(10)

        self.header = self.create_header()
        self.main_layout.addWidget(self.header)

        self.content_area = QHBoxLayout()
        self.main_layout.addLayout(self.content_area)

        self.tool_panel = self.create_tool_panel()
        self.content_area.addWidget(self.tool_panel, 0)

        self.work_area = self.create_work_area()
        self.content_area.addWidget(self.work_area, 1)

        self.setup_tool_data()
        self.update_tool_buttons()
        self.highlight_selected_tool("dns_enum")
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

        self.back_button = QPushButton("\u2190 Back to Home")
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

        self.controls_section = self.create_controls_section()
        work_layout.addWidget(self.controls_section)

        self.output_section = self.create_output_section()
        work_layout.addWidget(self.output_section, 1)

        self.progress_widget = ProgressWidget(self)
        self.progress_widget.setVisible(False)
        work_layout.addWidget(self.progress_widget)

        return work_frame

    def create_controls_section(self):
        from PyQt6.QtWidgets import QSpinBox, QStackedWidget

        controls_frame = QFrame()
        controls_layout = QVBoxLayout(controls_frame)
        controls_layout.setContentsMargins(10, 10, 10, 10)
        controls_layout.setSpacing(8)

        # === First Row: Target Input ===
        target_row = QHBoxLayout()
        target_label = QLabel("Target:")
        target_label.setFixedWidth(110)
        target_row.addWidget(target_label)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target (IP, domain, or range)...")
        self.target_input.textChanged.connect(self.check_target_type)
        target_row.addWidget(self.target_input)
        controls_layout.addLayout(target_row)

        # === Second Row: Record Type Checkboxes ===
        record_row = QHBoxLayout()
        types_label = QLabel("Types:")
        types_label.setFixedWidth(110)
        types_label.setFixedHeight(30)
        record_row.addWidget(types_label)
        checkbox_style = """
            QCheckBox {
                spacing: 5px;
                color: #DCDCDC;
                font-size: 11pt;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border-radius: 8px;
                border: 2px solid #64C8FF;
                background-color: transparent;
            }
            QCheckBox::indicator:checked {
                background-color: #64C8FF;
                border: 2px solid #64C8FF;
            }
            QCheckBox::indicator:hover {
                border: 2px solid #87CEEB;
            }
            QCheckBox::indicator:disabled {
                border: 2px solid #555;
                background-color: transparent;
            }
        """
        
        self.all_checkbox = QCheckBox("ALL")
        self.all_checkbox.setStyleSheet(checkbox_style)
        self.all_checkbox.stateChanged.connect(self.toggle_all_records)
        record_row.addWidget(self.all_checkbox)
        record_row.addSpacing(10)

        self.record_type_checkboxes = {}
        for rtype in ['A', 'CNAME', 'MX', 'TXT', 'NS']:
            cb = QCheckBox(rtype)
            cb.setStyleSheet(checkbox_style)
            cb.stateChanged.connect(self.update_all_checkbox)
            self.record_type_checkboxes[rtype] = cb
            record_row.addWidget(cb)
            record_row.addSpacing(10)

        self.ptr_checkbox = QCheckBox("PTR")
        self.ptr_checkbox.setStyleSheet(checkbox_style)
        self.ptr_checkbox.setEnabled(False)
        self.ptr_checkbox.stateChanged.connect(self.update_all_checkbox)
        record_row.addWidget(self.ptr_checkbox)

        record_row.addStretch()
        controls_layout.addLayout(record_row)

        # === DNS Row ===
        dns_row = QHBoxLayout()
        dns_label = QLabel("DNS:")
        dns_label.setFixedWidth(110)
        dns_row.addWidget(dns_label)
        self.dns_input = QLineEdit()
        self.dns_input.setPlaceholderText("DNS Server (optional)")
        self.dns_input.setFixedWidth(400)
        dns_row.addWidget(self.dns_input)
        dns_row.addStretch()
        controls_layout.addLayout(dns_row)

        # === Third Row: Method & Wordlist/Bruteforce ===
        method_row = QHBoxLayout()
        method_label = QLabel("Method:")
        method_label.setFixedWidth(110)
        method_row.addWidget(method_label)
        self.method_combo = QComboBox()
        self.method_combo.addItems(["Wordlist", "Bruteforce"])
        self.method_combo.setFixedWidth(150)
        self.method_combo.currentTextChanged.connect(self.toggle_method_options)
        method_row.addWidget(self.method_combo)

        self.wordlist_combo = QComboBox()
        self.populate_wordlists()
        method_row.addWidget(self.wordlist_combo, 1)

        # Bruteforce options on same line
        self.bruteforce_label = QLabel("Charset:")
        self.char_checkboxes = {}
        self.char_options = {'0-9': True, 'a-z': True, '-': False}
        self.length_label = QLabel("Length:")
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(1, 12)
        self.length_spinbox.setValue(3)
        self.length_spinbox.setFixedWidth(60)

        method_row.addWidget(self.bruteforce_label)
        for k, v in self.char_options.items():
            cb = QCheckBox(k)
            cb.setChecked(v)
            self.char_checkboxes[k] = cb
            method_row.addWidget(cb)
        method_row.addWidget(self.length_label)
        method_row.addWidget(self.length_spinbox)
        method_row.addStretch()

        self.method_row_layout = method_row
        controls_layout.addLayout(method_row)

        # === Fourth Row: Actions ===
        action_row = QHBoxLayout()
        action_row.addStretch()
        self.run_button = QPushButton("Run")
        self.run_button.setFixedWidth(80)
        self.run_button.clicked.connect(self.toggle_scan)
        action_row.addWidget(self.run_button)

        self.export_combo = QComboBox()
        self.export_combo.addItems(["JSON", "CSV", "XML", "Advanced Report", "Sessions"])
        self.export_combo.setFixedWidth(130)
        action_row.addWidget(self.export_combo)

        self.export_button = QPushButton("Export")
        self.export_button.setFixedWidth(80)
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_results)
        action_row.addWidget(self.export_button)

        controls_layout.addLayout(action_row)

        # === Visibility Toggle ===
        self.toggle_method_options("Wordlist")
        return controls_frame

    def create_output_section(self):
        output_frame = QFrame()
        output_layout = QVBoxLayout(output_frame)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.setSpacing(10)

        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setPlaceholderText("Tool output will appear here...")

        output_layout.addWidget(self.terminal_output)
        return output_frame

    def setup_tool_data(self):
        self.main_tools_data = [
            {"id": "dns_enum", "title": "DNS Enumeration", "desc": "Discover domains, subdomains, and IPs.", "icon": "resources/icons/1A.png"},
            {"id": "port_scan", "title": "Port Scanning", "desc": "Identify open ports and services running.", "icon": "resources/icons/1B.png"},
            {"id": "rpc_enum", "title": "RPC Enumeration", "desc": "Enumerate RPC services and endpoints.", "icon": "resources/icons/1C.png"},
            {"id": "smb_enum", "title": "SMB Enumeration", "desc": "Discover SMB shares and NetBIOS info.", "icon": "resources/icons/1D.png"},
            {"id": "smtp_enum", "title": "SMTP Enumeration", "desc": "Enumerate email users via SMTP.", "icon": "resources/icons/1E.png"},
            {"id": "snmp_enum", "title": "SNMP Enumeration", "desc": "Query SNMP for device information.", "icon": "resources/icons/1F.png"},
            {"id": "http_enum", "title": "HTTP/S Fingerprinting", "desc": "Web server identification and analysis.", "icon": "resources/icons/1G.png"},
            {"id": "api_enum", "title": "API Enumeration", "desc": "Discover and test API endpoints.", "icon": "resources/icons/1H.png"},
            {"id": "ldap_enum", "title": "LDAP/S Enumeration", "desc": "Query LDAP directory services.", "icon": "resources/icons/1I.png"},
            {"id": "db_enum", "title": "Database Enumeration", "desc": "Scan for database services and info.", "icon": "resources/icons/1J.png"},
            {"id": "ike_enum", "title": "IKE Enumeration", "desc": "Scan IKE/IPSec configurations.", "icon": "resources/icons/1K.png"},
            {"id": "osint_enum", "title": "OSINT Gathering", "desc": "Contactless information gathering.", "icon": "resources/icons/1L.png"},
            {"id": "av_detect", "title": "AV/Firewall Detection", "desc": "Detect security controls and evasion.", "icon": "resources/icons/1M.png"},
        ]

        self.main_tool_buttons = []
        for tool in self.main_tools_data:
            button = self.create_main_tool_button(tool)
            self.tool_layout.addWidget(button)
            self.main_tool_buttons.append(button)

        self.tool_layout.addStretch()
        self.dns_tools_data = [
            {"id": "dns_hosts", "text": "BruteForce", "method": self.run_host_wordlist_scan},
            {"id": "dns_ptr", "text": "PTR", "method": self.run_ptr_scan},
            {"id": "dns_zone_transfer", "text": "Zone Transfer", "method": self.run_zone_transfer},
            {"id": "dns_ns_records", "text": "NS/MX/TXT", "method": self.run_basic_records},
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
        button.setStyleSheet("text-align: left; padding-left: 5px;")
        button.clicked.connect(lambda: self.activate_tool_submenu(tool_data["id"]))
        button.enter_signal.connect(self.update_status_bar)
        button.leave_signal.connect(self.clear_status_bar)
        return button

    def activate_tool_submenu(self, tool_id):
        self.current_submenu = tool_id
        self.update_tool_buttons()
        self.highlight_selected_tool(tool_id)
        self.status_updated.emit(f"Selected: {tool_id.replace('_', ' ').title()}")
    
    def highlight_selected_tool(self, selected_id):
        for i, button in enumerate(self.main_tool_buttons):
            if self.main_tools_data[i]["id"] == selected_id:
                button.setStyleSheet("text-align: left; padding-left: 5px; background-color: rgba(100, 200, 255, 100);")
            else:
                button.setStyleSheet("text-align: left; padding-left: 5px;")

    def update_tool_buttons(self):
        pass  # Tool buttons removed

    def toggle_all_records(self, state):
        if self.ptr_checkbox.isEnabled():
            self.ptr_checkbox.setChecked(state == 2)
        else:
            for checkbox in self.record_type_checkboxes.values():
                checkbox.setChecked(state == 2)
    
    def update_all_checkbox(self):
        all_checked = all(cb.isChecked() for cb in self.record_type_checkboxes.values()) and (not self.ptr_checkbox.isEnabled() or self.ptr_checkbox.isChecked())
        self.all_checkbox.setChecked(all_checked)
    
    def check_target_type(self, text):
        # Check if target looks like IP (3 octets with dots)
        import re
        ip_pattern = r'^(\d{1,3}\.){3}'
        is_ip_like = bool(re.match(ip_pattern, text))
        
        if is_ip_like:
            # Enable PTR, disable and uncheck others
            self.ptr_checkbox.setEnabled(True)
            self.ptr_checkbox.setChecked(True)
            self.all_checkbox.setEnabled(False)
            self.all_checkbox.setChecked(False)
            for checkbox in self.record_type_checkboxes.values():
                checkbox.setEnabled(False)
                checkbox.setChecked(False)
            # Hide method row when PTR is active
            for i in range(self.method_row_layout.count()):
                item = self.method_row_layout.itemAt(i)
                if item and item.widget():
                    item.widget().setVisible(False)
        else:
            # Enable others, disable PTR
            self.ptr_checkbox.setEnabled(False)
            self.ptr_checkbox.setChecked(False)
            self.all_checkbox.setEnabled(True)
            for checkbox in self.record_type_checkboxes.values():
                checkbox.setEnabled(True)
            # Show method row when PTR is not active
            for i in range(self.method_row_layout.count()):
                item = self.method_row_layout.itemAt(i)
                if item and item.widget():
                    item.widget().setVisible(True)
            # Re-apply method visibility settings
            self.toggle_method_options(self.method_combo.currentText())
    
    def toggle_method_options(self, method):
        is_wordlist = (method == "Wordlist")
        self.wordlist_combo.setVisible(is_wordlist)
        
        # Toggle bruteforce options visibility
        self.bruteforce_label.setVisible(not is_wordlist)
        self.length_label.setVisible(not is_wordlist)
        self.length_spinbox.setVisible(not is_wordlist)
        for checkbox in self.char_checkboxes.values():
            checkbox.setVisible(not is_wordlist)

    def toggle_scan(self):
        if self.is_scanning:
            self.cancel_scan()
        else:
            self.run_host_wordlist_scan()
    
    def cancel_scan(self):
        if self.current_worker:
            self.current_worker.is_running = False
        self.is_scanning = False
        self.run_button.setText("Run")
        self.run_button.setStyleSheet("")
        self.status_updated.emit("Scan cancelled")
    
    def run_host_wordlist_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target domain")
            return
        
        dns_server = self.dns_input.text().strip() or None
        
        if self.ptr_checkbox.isEnabled() and self.ptr_checkbox.isChecked():
            # PTR query for IP targets - no wordlist/bruteforce needed
            self.is_scanning = True
            self.run_button.setText("Cancel")
            self.run_button.setStyleSheet("background-color: red; color: white;")
            
            self.terminal_output.clear()
            self.progress_widget.setVisible(True)
            
            # Clear previous scan results
            self.last_scan_results = {}
            self.export_button.setEnabled(False)
            
            self.current_worker = custom_scripts.query_ptr_records(
                ip_range=target,
                dns_server=dns_server,
                output_callback=self.append_terminal_output,
                results_callback=self.store_scan_results
            )
            # Connect all PTR worker signals
            self.current_worker.signals.finished.connect(self.on_scan_finished)
            self.current_worker.signals.progress_start.connect(self.start_progress)
            self.current_worker.signals.progress_update.connect(self.update_progress)
            return
        
        selected_types = []
        direct_query_types = []
        
        # For domain targets, process normally
        for rtype, cb in self.record_type_checkboxes.items():
            if cb.isChecked():
                if rtype == 'A':
                    selected_types.extend(['A', 'AAAA'])
                elif rtype in ['CNAME']:
                    selected_types.append(rtype)
                else:
                    direct_query_types.append(rtype)
        
        if not selected_types and not direct_query_types:
            self.show_error("Please select at least one record type")
            return
            
        method = self.method_combo.currentText()
        wordlist_path = self.wordlist_combo.currentData() if method == "Wordlist" else None
        char_sets = [k for k, v in self.char_checkboxes.items() if v.isChecked()] if method == "Bruteforce" else None
        max_length = self.length_spinbox.value() if method == "Bruteforce" else 3
        
        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        
        self.terminal_output.clear()
        self.progress_widget.setVisible(True)
        self.status_updated.emit(f"Starting DNS enumeration on {target}...")
        
        # Clear previous scan results
        self.last_scan_results = {}
        self.export_button.setEnabled(False)
        
        # Show enumeration message at the beginning
        if selected_types or direct_query_types:
            self.append_terminal_output(f"<p style='color: #00BFFF;'>Enumerating.... Please wait....</p><br>")
        
        # Handle direct queries for MX, NS, TXT first
        if direct_query_types:
            custom_scripts.query_direct_records(
                target=target,
                record_types=direct_query_types,
                dns_server=dns_server,
                output_callback=self.append_terminal_output,
                results_callback=self.store_scan_results
            )
        
        # Handle wordlist/bruteforce for A and CNAME
        if selected_types:
            self.current_worker = custom_scripts.enumerate_hostnames(
                target=target,
                wordlist_path=wordlist_path,
                record_types=selected_types,
                use_bruteforce=(method == "Bruteforce"),
                char_sets=char_sets,
                max_length=max_length,
                dns_server=dns_server,
                output_callback=self.append_terminal_output,
                status_callback=self.update_status_bar_text,
                finished_callback=self.on_scan_finished,
                results_callback=self.store_scan_results,
                progress_callback=self.update_progress,
                progress_start_callback=self.start_progress
            )
        else:
            self.on_scan_finished()

    def run_ptr_scan(self):
        self.show_info("PTR scan functionality not yet implemented.")

    def run_zone_transfer(self):
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target domain")
            return
        self.terminal_output.clear()
        self.progress_widget.setVisible(False)
        self.status_updated.emit(f"Attempting zone transfer on {target}...")
        custom_scripts.run_zone_transfer(
            target=target,
            output_callback=self.append_terminal_output,
            status_callback=self.update_status_bar_text,
            finished_callback=self.on_scan_finished
        )

    def run_basic_records(self):
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target domain")
            return
        self.terminal_output.clear()
        self.progress_widget.setVisible(False)
        self.status_updated.emit(f"Fetching NS/MX/TXT records for {target}...")
        records = custom_scripts.fetch_basic_records(target)
        for rtype, values in records.items():
            if values:
                self.append_terminal_output(f"<p style='color:#00FF41;'><b>{rtype} Records:</b></p>")
                for value in values:
                    self.append_terminal_output(f"<p style='color:#DCDCDC;'>&nbsp;&nbsp;&nbsp;-&gt; {value}</p>")
        self.status_updated.emit("Basic record scan complete")
        self.on_scan_finished()

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

    def append_terminal_output(self, text):
        self.terminal_output.insertHtml(text)
        scrollbar = self.terminal_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def update_status_bar_text(self, text):
        self.status_updated.emit(text)

    def store_scan_results(self, results):
        if not hasattr(self, 'last_scan_results') or not self.last_scan_results:
            self.last_scan_results = {}
        
        
        # Merge new results with existing results
        for domain, record_types in results.items():
            if domain not in self.last_scan_results:
                self.last_scan_results[domain] = {}
            for record_type, values in record_types.items():
                if record_type not in self.last_scan_results[domain]:
                    self.last_scan_results[domain][record_type] = []
                # Avoid duplicates
                for value in values:
                    if value not in self.last_scan_results[domain][record_type]:
                        self.last_scan_results[domain][record_type].append(value)
        
        self.export_button.setEnabled(True)

    def start_progress(self, total_items):
        self.progress_widget.start_progress(total_items, "Scanning...")

    def update_progress(self, completed_items, results_found):
        self.progress_widget.update_progress(completed_items, results_found)

    def on_scan_finished(self):
        self.progress_widget.finish_progress("Scan Complete")
        self.status_updated.emit("Scan completed successfully")
        self.is_scanning = False
        self.run_button.setText("Run")
        self.run_button.setStyleSheet("")
        self.current_worker = None

    def show_error(self, message):
        self.terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {message}</p>")
        self.status_updated.emit(f"Error: {message}")

    def show_info(self, message):
        self.terminal_output.setHtml(f"<p style='color: #64C8FF;'>[INFO] {message}</p>")

    def export_results(self):
        export_format = self.export_combo.currentText()
        
        if export_format == "Sessions":
            self.open_session_management()
            return
        
        if not self.last_scan_results:
            self.show_error("No scan results to export")
            return
        
        target = self.target_input.text().strip() or "unknown"
        
        if export_format == "Advanced Report":
            self.open_advanced_reporting()
            return
        
        try:
            import time
            exports_dir = os.path.join(self.main_window.project_root, "exports")
            os.makedirs(exports_dir, exist_ok=True)
            
            if export_format == "JSON":
                import json
                filename = f"scan_results_{target}_{int(time.time())}.json"
                filepath = os.path.join(exports_dir, filename)
                with open(filepath, 'w') as f:
                    json.dump(self.last_scan_results, f, indent=2)
            elif export_format == "CSV":
                import csv
                filename = f"scan_results_{target}_{int(time.time())}.csv"
                filepath = os.path.join(exports_dir, filename)
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Domain", "Type", "Value"])
                    for domain, record_types in self.last_scan_results.items():
                        for record_type, values in record_types.items():
                            for value in values:
                                writer.writerow([domain, record_type, value])
            elif export_format == "XML":
                filename = f"scan_results_{target}_{int(time.time())}.xml"
                filepath = os.path.join(exports_dir, filename)
                with open(filepath, 'w') as f:
                    f.write('<?xml version="1.0" encoding="UTF-8"?>\n<scan_results>\n')
                    for domain, record_types in self.last_scan_results.items():
                        f.write(f'  <domain name="{domain}">\n')
                        for record_type, values in record_types.items():
                            f.write(f'    <{record_type.lower()}_records>\n')
                            for value in values:
                                f.write(f'      <record>{value}</record>\n')
                            f.write(f'    </{record_type.lower()}_records>\n')
                        f.write('  </domain>\n')
                    f.write('</scan_results>\n')
            
            self.append_terminal_output(f"<p style='color: #00FF41;'>[EXPORT] Results exported to exports/{filename}</p><br>")
        except Exception as e:
            self.append_terminal_output(f"<p style='color: #FF4500;'>[EXPORT ERROR] Export failed: {str(e)}</p><br>")
    
    def open_advanced_reporting(self):
        """Open advanced reporting dialog"""
        from app.widgets.advanced_reporting_widget import AdvancedReportingWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Advanced Reporting")
        dialog.setModal(True)
        dialog.resize(800, 600)
        
        layout = QVBoxLayout(dialog)
        
        # Create reporting widget
        reporting_widget = AdvancedReportingWidget(dialog)
        
        # Load current scan data
        scan_data = {
            'target': self.target_input.text().strip(),
            'scan_type': 'dns_enum',
            'results': self.last_scan_results,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': 'Unknown'
        }
        reporting_widget.load_scan_data(scan_data)
        
        layout.addWidget(reporting_widget)
        dialog.exec()
    
    def open_session_management(self):
        """Open session management dialog"""
        from app.widgets.session_widget import SessionWidget
        from app.core.session_manager import session_manager
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Session Management")
        dialog.setModal(True)
        dialog.resize(900, 700)
        
        layout = QVBoxLayout(dialog)
        
        # Create session widget
        session_widget = SessionWidget(dialog)
        
        # Connect session change signal to handle scan association
        session_widget.session_changed.connect(self.on_session_changed)
        
        layout.addWidget(session_widget)
        dialog.exec()
    
    def on_session_changed(self, session_id):
        """Handle session change event"""
        from app.core.session_manager import session_manager
        from app.core.scan_database import scan_db
        
        # If we have scan results, associate them with the current session
        if self.last_scan_results and session_id:
            try:
                # Save current scan to database
                target = self.target_input.text().strip() or "unknown"
                scan_id = scan_db.save_scan(
                    target=target,
                    scan_type='dns_enum',
                    results=self.last_scan_results,
                    duration=0  # Duration not tracked in this context
                )
                
                if scan_id:
                    # Associate scan with session
                    session_manager.add_scan_to_session(session_id, scan_id)
                    self.append_terminal_output(
                        f"<p style='color: #00FF41;'>[SESSION] Scan results associated with session</p><br>"
                    )
                
            except Exception as e:
                self.append_terminal_output(
                    f"<p style='color: #FF4500;'>[SESSION ERROR] Failed to associate scan: {str(e)}</p><br>"
                )
