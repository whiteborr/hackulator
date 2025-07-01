# app/pages/enumeration_page.py
import logging
import os
from PyQt6.QtWidgets import QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox, QCheckBox, QHBoxLayout
from PyQt6.QtCore import pyqtSignal, QSize, Qt
from PyQt6.QtGui import QPixmap, QIcon, QFont, QTextCursor, QShortcut, QKeySequence

from app.core import custom_scripts
from app.core.validators import InputValidator, ValidationError
from app.core.exporter import exporter
from app.widgets.progress_widget import ProgressWidget

# ============================================================================
# Custom HoverButton Widget (for displaying info on hover)
# ============================================================================
class HoverButton(QPushButton):
    """A custom QPushButton that emits signals on mouse enter and leave events."""
    enter_signal = pyqtSignal(str, str) # title, description
    leave_signal = pyqtSignal()

    def __init__(self, title, description, parent=None):
        super().__init__(parent)
        self.title = title
        self.description = description

    def enterEvent(self, event):
        """Called when the mouse enters the widget's area."""
        super().enterEvent(event)
        self.enter_signal.emit(self.title, self.description)

    def leaveEvent(self, event):
        """Called when the mouse leaves the widget's area."""
        super().leaveEvent(event)
        self.leave_signal.emit()

# ============================================================================
# The Main Enumeration Page Widget
# ============================================================================
class EnumerationPage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.is_submenu_active = False
        self.setObjectName("EnumerationPage")

        self.background_label = QLabel(self)
        self.background_label.setScaledContents(True)

        # --- Data for UI Elements ---
        self.main_tools_data = [
            {"id": "dns_enum", "title": "DNS Enumeration", "desc": "Discover domains, subdomains, and IPs.", "icon": "resources/icons/1A.png", "center": (49, 157), "size": (39, 59)},
            {"id": "port_scan", "title": "Port Scanning", "desc": "Identify open ports and services running.", "icon": "resources/icons/1B.png", "center": (49, 234), "size": (39, 59)},
            {"id": "smb_enum", "title": "SMB Enumeration", "desc": "List shares and users via Windows SMB.", "icon": "resources/icons/1C.png", "center": (49, 311), "size": (39, 59)},
            {"id": "smtp_enum", "title": "SMTP Enumeration", "desc": "Probe mail servers for valid emails.", "icon": "resources/icons/1D.png", "center": (49, 389), "size": (39, 59)},
            {"id": "snmp_enum", "title": "SNMP Enumeration", "desc": "Extract network device info using SNMP.", "icon": "resources/icons/1E.png", "center": (49, 468), "size": (39, 59)},
            {"id": "http_fingerprint", "title": "HTTP/S Fingerprinting", "desc": "Identify web server type and technologies.", "icon": "resources/icons/1F.png", "center": (49, 545), "size": (39, 59)},
            {"id": "api_enum", "title": "API Enumeration & Abuse", "desc": "Discover and misuse APIs for data.", "icon": "resources/icons/1G.png", "center": (49, 620), "size": (39, 59)},
            {"id": "db_enum", "title": "Database Enumeration", "desc": "Find databases, tables, and credentials.", "icon": "resources/icons/1H.png", "center": (49, 700), "size": (39, 59)},
            {"id": "contactless_info", "title": "Contactless Info Gathering", "desc": "Use NFC/RFID tools to gather wireless data.", "icon": "resources/icons/1I.png", "center": (49, 779), "size": (39, 59)},
            {"id": "av_detect", "title": "AV Detection", "desc": "Check which antivirus tools are active.", "icon": "resources/icons/1J.png", "center": (49, 857), "size": (39, 59)},
        ]
        
        self.dns_tools_data = [
            {"id": "dns_hosts",    "text": "HOSTS",    "rect": (135, 225, 105, 30)},
            {"id": "dns_ptr",      "text": "PTR",      "rect": (135, 283, 105, 30)},
            {"id": "dns_dnsrecon", "text": "DNSRecon", "rect": (135, 341, 105, 30)},
            {"id": "dns_dnsenum",  "text": "DNSEnum",  "rect": (135, 398, 105, 30)},
            {"id": "dns_xfer",     "text": "XFER",     "rect": (135, 458, 105, 30)},
            {"id": "dns_nslookup", "text": "NSLOOKUP", "rect": (135, 518, 105, 30)},
        ]
        
        self.port_tools_data = [
            {"id": "port_tcp",     "text": "TCP SCAN",  "rect": (135, 225, 105, 30)},
            {"id": "port_sweep",   "text": "SWEEP",     "rect": (135, 283, 105, 30)},
            {"id": "port_top",     "text": "TOP PORTS", "rect": (135, 341, 105, 30)},
            {"id": "port_service", "text": "SERVICE",   "rect": (135, 398, 105, 30)},
        ]
        
        self.smb_tools_data = [
            {"id": "smb_scan",     "text": "SMB SCAN",  "rect": (135, 225, 105, 30)},
            {"id": "smb_netbios",  "text": "NETBIOS",   "rect": (135, 283, 105, 30)},
            {"id": "smb_os",       "text": "OS DETECT", "rect": (135, 341, 105, 30)},
            {"id": "smb_range",    "text": "RANGE",     "rect": (135, 398, 105, 30)},
        ]
        
        self.smtp_tools_data = [
            {"id": "smtp_vrfy",    "text": "VRFY",      "rect": (135, 225, 105, 30)},
            {"id": "smtp_expn",    "text": "EXPN",      "rect": (135, 283, 105, 30)},
            {"id": "smtp_rcpt",    "text": "RCPT TO",   "rect": (135, 341, 105, 30)},
        ]
        
        self.snmp_tools_data = [
            {"id": "snmp_scan",    "text": "SCAN",      "rect": (135, 225, 105, 30)},
            {"id": "snmp_comm",    "text": "COMMUNITY", "rect": (135, 283, 105, 30)},
            {"id": "snmp_walk",    "text": "WALK",      "rect": (135, 341, 105, 30)},
            {"id": "snmp_range",   "text": "RANGE",     "rect": (135, 398, 105, 30)},
        ]
        
        self.http_tools_data = [
            {"id": "http_finger",  "text": "FINGERPRINT", "rect": (135, 225, 105, 30)},
            {"id": "http_ssl",     "text": "SSL SCAN",   "rect": (135, 283, 105, 30)},
            {"id": "http_dir",     "text": "DIR SCAN",   "rect": (135, 341, 105, 30)},
        ]
        
        self.api_tools_data = [
            {"id": "api_discover", "text": "DISCOVER",   "rect": (135, 225, 105, 30)},
            {"id": "api_methods",  "text": "METHODS",    "rect": (135, 283, 105, 30)},
            {"id": "api_auth",     "text": "AUTH TEST",  "rect": (135, 341, 105, 30)},
        ]
        
        self.db_tools_data = [
            {"id": "db_scan",      "text": "DB SCAN",    "rect": (135, 225, 105, 30)},
            {"id": "db_detailed",  "text": "DETAILED",   "rect": (135, 283, 105, 30)},
        ]

        # --- Create Main Menu Widgets ---
        self.main_title = QLabel("Enumeration Tools", self)
        self.main_title.setObjectName("TitleLabel")
        
        self.main_back_button = QPushButton("< Back", self)
        self.main_back_button.setProperty("class", "backButton")
        self.main_back_button.clicked.connect(lambda: self.navigate_signal.emit("home"))
        
        self.info_panel = QTextEdit(self)
        self.info_panel.setObjectName("InfoPanel")
        self.info_panel.setReadOnly(True)
        
        self.main_tool_buttons = []
        for tool in self.main_tools_data:
            button = HoverButton(tool["title"], tool["desc"], self)
            icon_path = str(self.main_window.project_root / tool["icon"])
            self.setup_icon_button(button, tool["center"], tool["size"], icon_path)

            if tool["id"] == "dns_enum":
                button.clicked.connect(lambda: self.set_submenu_active(True))
            elif tool["id"] == "port_scan":
                button.clicked.connect(lambda: self.set_submenu_active(True, "port_scan"))
            elif tool["id"] == "smb_enum":
                button.clicked.connect(lambda: self.set_submenu_active(True, "smb_enum"))
            elif tool["id"] == "smtp_enum":
                button.clicked.connect(lambda: self.set_submenu_active(True, "smtp_enum"))
            elif tool["id"] == "snmp_enum":
                button.clicked.connect(lambda: self.set_submenu_active(True, "snmp_enum"))
            elif tool["id"] == "http_fingerprint":
                button.clicked.connect(lambda: self.set_submenu_active(True, "http_fingerprint"))
            elif tool["id"] == "api_enum":
                button.clicked.connect(lambda: self.set_submenu_active(True, "api_enum"))
            elif tool["id"] == "db_enum":
                button.clicked.connect(lambda: self.set_submenu_active(True, "db_enum"))
            
            button.enter_signal.connect(self.update_info_panel)
            button.leave_signal.connect(self.clear_info_panel)
            self.main_tool_buttons.append(button)

        self.main_widgets = [self.main_title, self.main_back_button, self.info_panel] + self.main_tool_buttons

        # --- Create DNS Sub-menu Widgets ---
        self.dns_back_button = QPushButton("< Back", self)
        self.dns_back_button.setProperty("class", "backButton")
        self.dns_back_button.clicked.connect(lambda: self.set_submenu_active(False))

        self.target_input = QLineEdit(self)
        self.target_input.setObjectName("TargetInput")
        self.target_input.setPlaceholderText("Enter target...")

        self.dns_terminal_output = QTextEdit(self)
        self.dns_terminal_output.setObjectName("InfoPanel")
        self.dns_terminal_output.setReadOnly(True)
        
        # Progress widget
        self.progress_widget = ProgressWidget(self)
        self.progress_widget.setVisible(False)
        
        self.wordlist_combo = QComboBox(self)
        self.wordlist_combo.setProperty("class", "wordlistCombo")
        self.populate_wordlists()

        self.record_type_container = QWidget(self)
        self.record_type_layout = QHBoxLayout(self.record_type_container)
        self.record_type_checkboxes = {}
        for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
            checkbox = QCheckBox(record_type, self)
            checkbox.setStyleSheet("color: #DCDCDC; font-size: 12pt;")
            if record_type == 'A': checkbox.setChecked(True)
            self.record_type_layout.addWidget(checkbox)
            self.record_type_checkboxes[record_type] = checkbox
        
        # Export controls
        self.export_combo = QComboBox(self)
        self.export_combo.setProperty("class", "exportCombo")
        self.export_combo.addItems(["JSON", "CSV", "XML"])
        
        self.export_button = QPushButton("Export Results", self)
        self.export_button.setProperty("class", "exportButton")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)  # Disabled until results available
        
        # Store last scan results for export
        self.last_scan_results = {}
        self.last_scan_target = ""

        self.dns_tool_buttons = []
        for tool_data in self.dns_tools_data:
            button = QPushButton(tool_data["text"], self)
            button.setProperty("class", "dnsToolButton")
            if tool_data["id"] == "dns_hosts":
                button.clicked.connect(self.run_host_wordlist_scan)
            self.dns_tool_buttons.append(button)
        
        self.port_tool_buttons = []
        for tool_data in self.port_tools_data:
            button = QPushButton(tool_data["text"], self)
            button.setProperty("class", "dnsToolButton")
            if tool_data["id"] == "port_tcp":
                button.clicked.connect(self.run_port_scan)
            elif tool_data["id"] == "port_sweep":
                button.clicked.connect(self.run_port_sweep)
            elif tool_data["id"] == "port_top":
                button.clicked.connect(self.run_top_ports)
            elif tool_data["id"] == "port_service":
                button.clicked.connect(self.run_service_scan)
            self.port_tool_buttons.append(button)
        
        self.smb_tool_buttons = []
        for tool_data in self.smb_tools_data:
            button = QPushButton(tool_data["text"], self)
            button.setProperty("class", "dnsToolButton")
            if tool_data["id"] == "smb_scan":
                button.clicked.connect(self.run_smb_scan)
            elif tool_data["id"] == "smb_netbios":
                button.clicked.connect(self.run_netbios_scan)
            elif tool_data["id"] == "smb_os":
                button.clicked.connect(self.run_smb_os_detect)
            elif tool_data["id"] == "smb_range":
                button.clicked.connect(self.run_smb_range)
            self.smb_tool_buttons.append(button)
        
        # Create tool buttons for other enumeration types
        self.smtp_tool_buttons = []
        for tool_data in self.smtp_tools_data:
            button = QPushButton(tool_data["text"], self)
            button.setProperty("class", "dnsToolButton")
            if tool_data["id"] == "smtp_vrfy":
                button.clicked.connect(self.run_smtp_enum)
            self.smtp_tool_buttons.append(button)
        
        self.snmp_tool_buttons = []
        for tool_data in self.snmp_tools_data:
            button = QPushButton(tool_data["text"], self)
            button.setProperty("class", "dnsToolButton")
            if tool_data["id"] == "snmp_scan":
                button.clicked.connect(self.run_snmp_scan)
            elif tool_data["id"] == "snmp_comm":
                button.clicked.connect(self.run_snmp_community)
            elif tool_data["id"] == "snmp_walk":
                button.clicked.connect(self.run_snmp_walk)
            elif tool_data["id"] == "snmp_range":
                button.clicked.connect(self.run_snmp_range)
            self.snmp_tool_buttons.append(button)
        
        self.http_tool_buttons = []
        for tool_data in self.http_tools_data:
            button = QPushButton(tool_data["text"], self)
            button.setProperty("class", "dnsToolButton")
            if tool_data["id"] == "http_finger":
                button.clicked.connect(self.run_http_fingerprint)
            elif tool_data["id"] == "http_ssl":
                button.clicked.connect(self.run_http_ssl)
            elif tool_data["id"] == "http_dir":
                button.clicked.connect(self.run_http_dir)
            self.http_tool_buttons.append(button)
        
        self.api_tool_buttons = []
        for tool_data in self.api_tools_data:
            button = QPushButton(tool_data["text"], self)
            button.setProperty("class", "dnsToolButton")
            if tool_data["id"] == "api_discover":
                button.clicked.connect(self.run_api_discover)
            elif tool_data["id"] == "api_methods":
                button.clicked.connect(self.run_api_methods)
            elif tool_data["id"] == "api_auth":
                button.clicked.connect(self.run_api_auth)
            self.api_tool_buttons.append(button)
        
        self.db_tool_buttons = []
        for tool_data in self.db_tools_data:
            button = QPushButton(tool_data["text"], self)
            button.setProperty("class", "dnsToolButton")
            if tool_data["id"] == "db_scan":
                button.clicked.connect(self.run_db_scan)
            elif tool_data["id"] == "db_detailed":
                button.clicked.connect(self.run_db_detailed)
            self.db_tool_buttons.append(button)
        
        # **FIX**: Removed the separate wildcard status label
        self.submenu_widgets = [self.dns_back_button, self.target_input, self.dns_terminal_output, self.wordlist_combo, self.record_type_container, self.export_combo, self.export_button, self.progress_widget] + self.dns_tool_buttons + self.port_tool_buttons + self.smb_tool_buttons + self.smtp_tool_buttons + self.snmp_tool_buttons + self.http_tool_buttons + self.api_tool_buttons + self.db_tool_buttons
        
        self.current_submenu = "dns"
        
        self.setup_shortcuts()
        self.resizeEvent(None) 
        self.set_submenu_active(False)
        self.apply_theme()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)


    def setup_icon_button(self, button, center, size, icon_path):
        new_size = self.main_window.size()
        original_size = self.main_window.original_size
        ws = new_size.width() / original_size.width()
        hs = new_size.height() / original_size.height()

        scaled_cx = int(center[0] * ws)
        scaled_cy = int(center[1] * hs)
        scaled_w = int(size[0] * ws)
        scaled_h = int(size[1] * hs)
        
        button.setGeometry(scaled_cx - scaled_w // 2, scaled_cy - scaled_h // 2, scaled_w, scaled_h)
        
        icon = QIcon(icon_path)
        if icon.isNull(): logging.warning(f"Could not load icon at: {icon_path}")
        button.setIcon(icon)
        button.setIconSize(QSize(int(scaled_w * 0.9), int(scaled_h * 0.9)))
        
        border_radius = scaled_h // 2
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(0, 0, 0, 1); border: none;
                border-radius: {border_radius}px;
            }}
            QPushButton:hover {{
                background-color: rgba(255, 255, 255, 40);
                border-radius: {border_radius}px;
            }}
        """)

    def populate_wordlists(self):
        wordlist_dir = self.main_window.project_root / "resources" / "wordlists"
        if not os.path.isdir(wordlist_dir):
            logging.warning(f"Wordlist directory not found: {wordlist_dir}")
            return
        
        for filename in os.listdir(wordlist_dir):
            if filename.endswith(".txt"):
                self.wordlist_combo.addItem(filename, str(wordlist_dir / filename))

    def set_submenu_active(self, active, submenu_type="dns"):
        self.is_submenu_active = active
        self.current_submenu = submenu_type
        
        for widget in self.main_widgets: widget.setVisible(not active)
        
        # Show/hide common submenu widgets
        common_widgets = [self.dns_back_button, self.target_input, self.dns_terminal_output, self.export_combo, self.export_button, self.progress_widget]
        for widget in common_widgets: widget.setVisible(active)
        
        # Show/hide specific tool buttons and controls
        if active:
            if submenu_type == "dns":
                for widget in self.dns_tool_buttons: widget.setVisible(True)
                self.wordlist_combo.setVisible(True)
                self.record_type_container.setVisible(True)
                for widget in self.port_tool_buttons: widget.setVisible(False)
                for widget in self.smb_tool_buttons: widget.setVisible(False)
            elif submenu_type == "port_scan":
                for widget in self.port_tool_buttons: widget.setVisible(True)
                self.wordlist_combo.setVisible(False)
                self.record_type_container.setVisible(False)
                for widget in self.dns_tool_buttons: widget.setVisible(False)
                for widget in self.smb_tool_buttons: widget.setVisible(False)
            elif submenu_type == "smb_enum":
                for widget in self.smb_tool_buttons: widget.setVisible(True)
                self.wordlist_combo.setVisible(False)
                self.record_type_container.setVisible(False)
                for widget in self.dns_tool_buttons: widget.setVisible(False)
                for widget in self.port_tool_buttons: widget.setVisible(False)
                self.hide_other_tools(["smb"])
            elif submenu_type == "smtp_enum":
                for widget in self.smtp_tool_buttons: widget.setVisible(True)
                self.wordlist_combo.setVisible(True)
                self.record_type_container.setVisible(False)
                self.hide_other_tools(["smtp"])
            elif submenu_type == "snmp_enum":
                for widget in self.snmp_tool_buttons: widget.setVisible(True)
                self.wordlist_combo.setVisible(False)
                self.record_type_container.setVisible(False)
                self.hide_other_tools(["snmp"])
            elif submenu_type == "http_fingerprint":
                for widget in self.http_tool_buttons: widget.setVisible(True)
                self.wordlist_combo.setVisible(False)
                self.record_type_container.setVisible(False)
                self.hide_other_tools(["http"])
            elif submenu_type == "api_enum":
                for widget in self.api_tool_buttons: widget.setVisible(True)
                self.wordlist_combo.setVisible(False)
                self.record_type_container.setVisible(False)
                self.hide_other_tools(["api"])
            elif submenu_type == "db_enum":
                for widget in self.db_tool_buttons: widget.setVisible(True)
                self.wordlist_combo.setVisible(False)
                self.record_type_container.setVisible(False)
                self.hide_other_tools(["db"])
        else:
            self.hide_all_tool_buttons()
            self.wordlist_combo.setVisible(False)
            self.record_type_container.setVisible(False)
        
        if self.main_tool_buttons: self.main_tool_buttons[0].setVisible(True)
        self.update_background()

    def update_background(self):
        theme = self.main_window.theme_manager
        bg_path = theme.get("backgrounds.enumeration_dns") if self.is_submenu_active else theme.get("backgrounds.enumeration")
        if bg_path: self.background_label.setPixmap(QPixmap(bg_path))

    def apply_theme(self): self.update_background()

    def resizeEvent(self, event):
        if event: super().resizeEvent(event)
        
        self.background_label.setGeometry(0, 0, self.width(), self.height())
        
        new_size = self.main_window.size()
        original_size = self.main_window.original_size
        ws = new_size.width() / original_size.width()
        hs = new_size.height() / original_size.height()

        self.main_title.setGeometry(int(340 * ws), int(40 * hs), int(400 * ws), int(50 * hs))
        self.main_back_button.setGeometry(int(20 * ws), int(20 * hs), int(150 * ws), int(50 * hs))
        
        term_x, term_y, term_w, term_h = 340, 175, 1731 - 340, 770 - 175
        self.info_panel.setGeometry(term_x, term_y, term_w, term_h)
        self.dns_terminal_output.setGeometry(term_x, term_y, term_w, term_h)

        self.dns_back_button.setGeometry(int(40 * ws), int(850 * hs), int(150 * ws), int(50 * hs))

        controls_y = term_y + term_h + 80
        padding = 15
        control_height = 36

        target_width = int(term_w * 0.25)
        wordlist_width = int(term_w * 0.35)
        checkbox_width = term_w - target_width - wordlist_width - (padding * 2)

        target_x = term_x
        wordlist_x = target_x + target_width + padding
        checkbox_x = wordlist_x + wordlist_width + padding

        self.target_input.setGeometry(target_x, controls_y, target_width, control_height)
        self.wordlist_combo.setGeometry(wordlist_x, controls_y, wordlist_width, control_height)
        self.record_type_container.setGeometry(checkbox_x, controls_y, checkbox_width, control_height)
        
        # Progress widget positioning
        progress_y = controls_y + control_height + 15
        progress_height = 60
        self.progress_widget.setGeometry(target_x, progress_y, term_w, progress_height)
        
        # Export controls positioning
        export_y = progress_y + progress_height + 15
        export_combo_width = 100
        export_button_width = 120
        
        self.export_combo.setGeometry(target_x, export_y, export_combo_width, control_height)
        self.export_button.setGeometry(target_x + export_combo_width + 15, export_y, export_button_width, control_height)

        for i, button in enumerate(self.dns_tool_buttons):
            x, y, w, h = self.dns_tools_data[i]["rect"]
            button.setGeometry(x, y, w, h)
        
        for i, button in enumerate(self.port_tool_buttons):
            x, y, w, h = self.port_tools_data[i]["rect"]
            button.setGeometry(x, y, w, h)
        
        for i, button in enumerate(self.smb_tool_buttons):
            x, y, w, h = self.smb_tools_data[i]["rect"]
            button.setGeometry(x, y, w, h)
        
        for i, button in enumerate(self.smtp_tool_buttons):
            x, y, w, h = self.smtp_tools_data[i]["rect"]
            button.setGeometry(x, y, w, h)
        
        for i, button in enumerate(self.snmp_tool_buttons):
            x, y, w, h = self.snmp_tools_data[i]["rect"]
            button.setGeometry(x, y, w, h)
        
        for i, button in enumerate(self.http_tool_buttons):
            x, y, w, h = self.http_tools_data[i]["rect"]
            button.setGeometry(x, y, w, h)
        
        for i, button in enumerate(self.api_tool_buttons):
            x, y, w, h = self.api_tools_data[i]["rect"]
            button.setGeometry(x, y, w, h)
        
        for i, button in enumerate(self.db_tool_buttons):
            x, y, w, h = self.db_tools_data[i]["rect"]
            button.setGeometry(x, y, w, h)
        
    def update_info_panel(self, title, description):
        self.info_panel.setHtml(f"""
        <div style='color: #64C8FF; font-size: 22pt; font-weight: bold;'>{title}</div>
        <div style='color: #DCDCDC; font-size: 16pt; font-family: "Neuropol";'>{description}</div>
        """)
    
    def clear_info_panel(self): self.info_panel.clear()

    # --- Script Execution and UI Update Methods ---
    def run_host_wordlist_scan(self):
        target = self.target_input.text()
        wordlist_path = self.wordlist_combo.currentData()
        selected_types = [rtype for rtype, cb in self.record_type_checkboxes.items() if cb.isChecked()]

        # Validate domain input
        domain_valid, domain_result = InputValidator.validate_domain(target)
        if not domain_valid:
            self.dns_terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] Invalid domain: {domain_result}</p>")
            return
        target = domain_result  # Use sanitized domain
        
        # Validate wordlist path
        wordlist_valid, wordlist_error, validated_path = InputValidator.validate_wordlist_path(wordlist_path)
        if not wordlist_valid:
            self.dns_terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] Wordlist validation failed: {wordlist_error}</p>")
            return
        wordlist_path = validated_path  # Use validated path
        
        # Validate record types
        types_valid, types_error, validated_types = InputValidator.validate_record_types(selected_types)
        if not types_valid:
            self.dns_terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] Record type validation failed: {types_error}</p>")
            return
        selected_types = validated_types  # Use validated types
        
        self.dns_terminal_output.clear()
        self.set_buttons_enabled(False)
        self.progress_widget.setVisible(True)
        self.progress_widget.reset_progress()

        # Store current scan info for export
        self.last_scan_target = target
        
        custom_scripts.enumerate_hostnames(
            target=target, wordlist_path=wordlist_path, record_types=selected_types,
            output_callback=self.append_terminal_output,
            status_callback=self.update_status,
            finished_callback=self.on_script_finished,
            wildcard_callback=self.update_wildcard_status,
            results_callback=self.store_scan_results,
            progress_callback=self.update_progress,
            progress_start_callback=self.start_progress
        )

    def append_terminal_output(self, text):
        self.dns_terminal_output.insertHtml(text)
        self.dns_terminal_output.verticalScrollBar().setValue(self.dns_terminal_output.verticalScrollBar().maximum())

    def update_status(self, status_text): print(f"STATUS: {status_text}")
    
    def update_wildcard_status(self, text):
        """
        **FIX**: This slot now handles the wildcard status by inserting text at the top
        of the terminal window.
        """
        # If this is the "Checking..." message, just insert it.
        if "Checking" in text:
            self.dns_terminal_output.setHtml(text + "<br>")
        else:
            # If it's the result, replace the first line.
            cursor = self.dns_terminal_output.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.select(QTextCursor.SelectionType.LineUnderCursor)
            cursor.removeSelectedText()
            cursor.insertHtml(text + "<br>")

    def store_scan_results(self, results):
        """Store scan results for export functionality"""
        self.last_scan_results = results
        self.export_button.setEnabled(bool(results))
    
    def export_results(self):
        """Export the last scan results"""
        if not self.last_scan_results:
            self.append_terminal_output("<p style='color: #FF4500;'>[ERROR] No scan results to export</p>")
            return
        
        format_type = self.export_combo.currentText().lower()
        success, filepath, message = exporter.export_results(
            self.last_scan_results, 
            self.last_scan_target, 
            format_type
        )
        
        if success:
            self.append_terminal_output(f"<p style='color: #00FF41;'>[✓] Results exported to: {filepath}</p>")
        else:
            self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] Export failed: {message}</p>")
    
    def start_progress(self, total_items):
        """Start progress tracking"""
        self.progress_widget.start_progress(total_items, "Enumerating hostnames...")
    
    def update_progress(self, completed_items, results_found):
        """Update progress tracking"""
        self.progress_widget.update_progress(completed_items, results_found)
    
    def on_script_finished(self):
        self.set_buttons_enabled(True)
        self.progress_widget.finish_progress("Scan Complete")
        self.append_terminal_output("<br><p style='color: #64C8FF;'>--- Scan Finished ---</p>")

    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        # F5 - Start scan
        self.scan_shortcut = QShortcut(QKeySequence("F5"), self)
        self.scan_shortcut.activated.connect(self.run_host_wordlist_scan)
        
        # Ctrl+E - Export results
        self.export_shortcut = QShortcut(QKeySequence("Ctrl+E"), self)
        self.export_shortcut.activated.connect(self.export_results)
        
        # Ctrl+L - Clear terminal
        self.clear_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.clear_shortcut.activated.connect(self.clear_terminal)
        
        # Escape - Go back
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(self.handle_escape)
    
    def clear_terminal(self):
        """Clear the terminal output"""
        self.dns_terminal_output.clear()
    
    def handle_escape(self):
        """Handle escape key press"""
        if self.is_submenu_active:
            self.set_submenu_active(False)
        else:
            self.navigate_signal.emit("home")
    
    def hide_other_tools(self, keep_visible):
        all_tools = {
            "dns": self.dns_tool_buttons,
            "port": self.port_tool_buttons, 
            "smb": self.smb_tool_buttons,
            "smtp": self.smtp_tool_buttons,
            "snmp": self.snmp_tool_buttons,
            "http": self.http_tool_buttons,
            "api": self.api_tool_buttons,
            "db": self.db_tool_buttons
        }
        
        for tool_type, buttons in all_tools.items():
            visible = tool_type in keep_visible
            for button in buttons:
                button.setVisible(visible)
    
    def hide_all_tool_buttons(self):
        all_buttons = (self.dns_tool_buttons + self.port_tool_buttons + self.smb_tool_buttons + 
                      self.smtp_tool_buttons + self.snmp_tool_buttons + self.http_tool_buttons + 
                      self.api_tool_buttons + self.db_tool_buttons)
        for button in all_buttons:
            button.setVisible(False)
    
    def set_buttons_enabled(self, enabled):
        all_buttons = (self.dns_tool_buttons + self.port_tool_buttons + self.smb_tool_buttons + 
                      self.smtp_tool_buttons + self.snmp_tool_buttons + self.http_tool_buttons + 
                      self.api_tool_buttons + self.db_tool_buttons)
        for button in all_buttons:
            button.setEnabled(enabled)
        self.scan_shortcut.setEnabled(enabled)
    
    # Port Scanning Methods
    def run_port_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.dns_terminal_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a target IP</p>")
            return
        
        self.dns_terminal_output.clear()
        self.set_buttons_enabled(False)
        self.append_terminal_output(f"<p style='color: #64C8FF;'>[*] Starting TCP scan on {target}</p>")
        
        import subprocess
        import threading
        
        def run_scan():
            try:
                cmd = ["python", "tools/port_scanner.py", target, "-p", "1-1000"]
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.main_window.project_root))
                self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result.stdout}</pre>")
                if result.stderr:
                    self.append_terminal_output(f"<p style='color: #FF4500;'>{result.stderr}</p>")
            except Exception as e:
                self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] {str(e)}</p>")
            finally:
                self.set_buttons_enabled(True)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def run_port_sweep(self):
        target = self.target_input.text().strip()
        if not target:
            self.dns_terminal_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a network range</p>")
            return
        
        self.dns_terminal_output.clear()
        self.set_buttons_enabled(False)
        self.append_terminal_output(f"<p style='color: #64C8FF;'>[*] Starting network sweep on {target}</p>")
        
        import subprocess
        import threading
        
        def run_scan():
            try:
                cmd = ["python", "tools/port_scanner.py", target, "--sweep"]
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.main_window.project_root))
                self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result.stdout}</pre>")
                if result.stderr:
                    self.append_terminal_output(f"<p style='color: #FF4500;'>{result.stderr}</p>")
            except Exception as e:
                self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] {str(e)}</p>")
            finally:
                self.set_buttons_enabled(True)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def run_top_ports(self):
        target = self.target_input.text().strip()
        if not target:
            self.dns_terminal_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a target IP</p>")
            return
        
        self.dns_terminal_output.clear()
        self.set_buttons_enabled(False)
        self.append_terminal_output(f"<p style='color: #64C8FF;'>[*] Scanning top 20 ports on {target}</p>")
        
        import subprocess
        import threading
        
        def run_scan():
            try:
                cmd = ["python", "tools/port_scanner.py", target, "--top-ports", "20"]
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.main_window.project_root))
                self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result.stdout}</pre>")
                if result.stderr:
                    self.append_terminal_output(f"<p style='color: #FF4500;'>{result.stderr}</p>")
            except Exception as e:
                self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] {str(e)}</p>")
            finally:
                self.set_buttons_enabled(True)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def run_service_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.dns_terminal_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a target IP</p>")
            return
        
        self.dns_terminal_output.clear()
        self.set_buttons_enabled(False)
        self.append_terminal_output(f"<p style='color: #64C8FF;'>[*] Scanning with service detection on {target}</p>")
        
        import subprocess
        import threading
        
        def run_scan():
            try:
                cmd = ["python", "tools/port_scanner.py", target, "--top-ports", "20", "--service-detect"]
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.main_window.project_root))
                self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result.stdout}</pre>")
                if result.stderr:
                    self.append_terminal_output(f"<p style='color: #FF4500;'>{result.stderr}</p>")
            except Exception as e:
                self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] {str(e)}</p>")
            finally:
                self.set_buttons_enabled(True)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    # SMB Enumeration Methods
    def run_smb_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.dns_terminal_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a target IP</p>")
            return
        
        self.dns_terminal_output.clear()
        self.set_buttons_enabled(False)
        self.append_terminal_output(f"<p style='color: #64C8FF;'>[*] Scanning SMB ports on {target}</p>")
        
        import subprocess
        import threading
        
        def run_scan():
            try:
                cmd = ["python", "tools/smb_enum.py", target]
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.main_window.project_root))
                self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result.stdout}</pre>")
                if result.stderr:
                    self.append_terminal_output(f"<p style='color: #FF4500;'>{result.stderr}</p>")
            except Exception as e:
                self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] {str(e)}</p>")
            finally:
                self.set_buttons_enabled(True)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def run_netbios_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.dns_terminal_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a target IP</p>")
            return
        
        self.dns_terminal_output.clear()
        self.set_buttons_enabled(False)
        self.append_terminal_output(f"<p style='color: #64C8FF;'>[*] NetBIOS enumeration on {target}</p>")
        
        import subprocess
        import threading
        
        def run_scan():
            try:
                cmd = ["python", "tools/smb_enum.py", target, "--netbios"]
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.main_window.project_root))
                self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result.stdout}</pre>")
                if result.stderr:
                    self.append_terminal_output(f"<p style='color: #FF4500;'>{result.stderr}</p>")
            except Exception as e:
                self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] {str(e)}</p>")
            finally:
                self.set_buttons_enabled(True)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def run_smb_os_detect(self):
        target = self.target_input.text().strip()
        if not target:
            self.dns_terminal_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a target IP</p>")
            return
        
        self.dns_terminal_output.clear()
        self.set_buttons_enabled(False)
        self.append_terminal_output(f"<p style='color: #64C8FF;'>[*] SMB OS detection on {target}</p>")
        
        import subprocess
        import threading
        
        def run_scan():
            try:
                cmd = ["python", "tools/smb_enum.py", target, "--os-detect"]
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.main_window.project_root))
                self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result.stdout}</pre>")
                if result.stderr:
                    self.append_terminal_output(f"<p style='color: #FF4500;'>{result.stderr}</p>")
            except Exception as e:
                self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] {str(e)}</p>")
            finally:
                self.set_buttons_enabled(True)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def run_smb_range(self):
        target = self.target_input.text().strip()
        if not target:
            self.dns_terminal_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter a network range (e.g., 192.168.1)</p>")
            return
        
        self.dns_terminal_output.clear()
        self.set_buttons_enabled(False)
        self.append_terminal_output(f"<p style='color: #64C8FF;'>[*] SMB range scan on {target}.1-254</p>")
        
        import subprocess
        import threading
        
        def run_scan():
            try:
                cmd = ["python", "tools/smb_enum.py", target, "--range"]
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.main_window.project_root))
                self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result.stdout}</pre>")
                if result.stderr:
                    self.append_terminal_output(f"<p style='color: #FF4500;'>{result.stderr}</p>")
            except Exception as e:
                self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] {str(e)}</p>")
            finally:
                self.set_buttons_enabled(True)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def run_smtp_enum(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter target")
        domain = target.split('.')[0] if '.' in target else "example.com"
        wordlist = self.wordlist_combo.currentData() or "resources/wordlists/subdomains-top1000.txt"
        self.run_tool_command(["python", "tools/smtp_enum.py", target, "--domain", domain, "--wordlist", wordlist], f"SMTP enumeration on {target}")
    
    def run_snmp_scan(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter a target IP")
        self.run_tool_command(["python", "tools/snmp_enum.py", target], f"SNMP scan on {target}")
    
    def run_snmp_community(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter a target IP")
        self.run_tool_command(["python", "tools/snmp_enum.py", target, "--community", "public"], f"SNMP community test on {target}")
    
    def run_snmp_walk(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter a target IP")
        self.run_tool_command(["python", "tools/snmp_enum.py", target, "--walk"], f"SNMP walk on {target}")
    
    def run_snmp_range(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter a network range")
        self.run_tool_command(["python", "tools/snmp_enum.py", target, "--range"], f"SNMP range scan on {target}")
    
    def run_http_fingerprint(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter a target")
        self.run_tool_command(["python", "tools/http_enum.py", target], f"HTTP fingerprinting on {target}")
    
    def run_http_ssl(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter a target")
        self.run_tool_command(["python", "tools/http_enum.py", target, "--https", "--ssl-scan"], f"SSL scan on {target}")
    
    def run_http_dir(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter a target")
        self.run_tool_command(["python", "tools/http_enum.py", target, "--dir-scan"], f"Directory scan on {target}")
    
    def run_api_discover(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter a target")
        self.run_tool_command(["python", "tools/api_enum.py", target], f"API discovery on {target}")
    
    def run_api_methods(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter a target")
        self.run_tool_command(["python", "tools/api_enum.py", target, "--methods"], f"API methods test on {target}")
    
    def run_api_auth(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter a target")
        self.run_tool_command(["python", "tools/api_enum.py", target, "--auth-bypass"], f"API auth bypass test on {target}")
    
    def run_db_scan(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter a target IP")
        self.run_tool_command(["python", "tools/db_enum.py", target], f"Database scan on {target}")
    
    def run_db_detailed(self):
        target = self.target_input.text().strip()
        if not target: return self.show_error("Please enter a target IP")
        self.run_tool_command(["python", "tools/db_enum.py", target, "--detailed"], f"Detailed database scan on {target}")
    
    def show_error(self, message):
        self.dns_terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {message}</p>")
    
    def run_tool_command(self, cmd, description):
        self.dns_terminal_output.clear()
        self.set_buttons_enabled(False)
        self.append_terminal_output(f"<p style='color: #64C8FF;'>[*] {description}</p>")
        
        import subprocess, threading
        def run_scan():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.main_window.project_root))
                self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result.stdout}</pre>")
                if result.stderr: self.append_terminal_output(f"<p style='color: #FF4500;'>{result.stderr}</p>")
            except Exception as e:
                self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] {str(e)}</p>")
            finally: self.set_buttons_enabled(True)
        threading.Thread(target=run_scan, daemon=True).start()
