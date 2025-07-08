# --- FULL UPDATED enumeration_page.py ---
import os
import logging
import time
import json
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, 
                             QComboBox, QCheckBox, QVBoxLayout, QHBoxLayout, 
                             QFrame, QSizePolicy, QScrollArea, QStatusBar, QStackedWidget,
                             QTreeView, QToolButton)
from PyQt6.QtCore import pyqtSignal, QSize, Qt, QThreadPool
from PyQt6.QtGui import QPixmap, QIcon, QShortcut, QKeySequence, QStandardItemModel, QStandardItem

from app.tools import dns_utils
from app.core.validators import InputValidator
from app.core.exporter import exporter
from app.core.base_worker import CommandWorker
from app.widgets.progress_widget import ProgressWidget
from app.core.control_panel_factory import ControlPanelFactory
import json
import os

def load_tool_configs():
    """Load tool configurations from JSON file"""
    config_path = os.path.join(os.path.dirname(__file__), '..', 'core', 'tool_configs.json')
    with open(config_path, 'r') as f:
        return json.load(f)

TOOL_CONFIGS = load_tool_configs()
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
        
        # Terminal history and state for each tool
        self.terminal_history = {}
        self.tool_states = {}  # Store scan state, progress, results for each tool

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
        self.switch_tool_controls("dns")
        self.setup_shortcuts()
        self.apply_theme()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    def create_header(self):
        header_frame = QFrame()
        header_frame.setObjectName("header_frame")
        header_frame.setFixedHeight(60)
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(15, 10, 15, 10)

        self.back_button = QPushButton("\u2190 Back to Home")
        self.back_button.clicked.connect(self.navigate_home)
        self.back_button.setFixedWidth(150)

        self.title_label = QLabel("Enumeration Tools")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        header_layout.addWidget(self.back_button)
        header_layout.addWidget(self.title_label, 1)
        header_layout.addStretch()

        return header_frame

    def create_tool_panel(self):
        tool_frame = QFrame()
        tool_frame.setObjectName("tool_panel_frame")
        tool_frame.setFixedWidth(300)
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
        work_frame.setObjectName("work_area_frame")
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

    def _create_record_checkboxes(self, parent_layout):
        """Helper to create record type checkboxes"""
        self.all_checkbox = QCheckBox("ALL")
        self.all_checkbox.setProperty("class", "record_type")
        self.all_checkbox.stateChanged.connect(self.toggle_all_records)
        parent_layout.addWidget(self.all_checkbox)
        parent_layout.addSpacing(10)

        self.record_type_checkboxes = {}
        for rtype in ['A', 'CNAME', 'MX', 'TXT', 'NS', 'SRV']:
            cb = QCheckBox(rtype)
            cb.setProperty("class", "record_type")
            cb.stateChanged.connect(self.update_all_checkbox)
            self.record_type_checkboxes[rtype] = cb
            parent_layout.addWidget(cb)
            parent_layout.addSpacing(10)

        self.ptr_checkbox = QCheckBox("PTR")
        self.ptr_checkbox.setProperty("class", "record_type")
        self.ptr_checkbox.setEnabled(False)
        self.ptr_checkbox.stateChanged.connect(self.update_all_checkbox)
        parent_layout.addWidget(self.ptr_checkbox)
    
    def _create_bruteforce_options(self, parent_layout):
        """Helper to create bruteforce option widgets"""
        from PyQt6.QtWidgets import QSpinBox
        
        self.bruteforce_label = QLabel("Charset:")
        self.char_checkboxes = {}
        self.char_options = {'0-9': True, 'a-z': True, '-': False}
        self.length_label = QLabel("Length:")
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(1, 12)
        self.length_spinbox.setValue(3)
        self.length_spinbox.setFixedWidth(60)

        parent_layout.addWidget(self.bruteforce_label)
        for k, v in self.char_options.items():
            cb = QCheckBox(k)
            cb.setChecked(v)
            self.char_checkboxes[k] = cb
            parent_layout.addWidget(cb)
        parent_layout.addWidget(self.length_label)
        parent_layout.addWidget(self.length_spinbox)

    def create_controls_section(self):
        from PyQt6.QtWidgets import QSpinBox, QStackedWidget

        controls_frame = QFrame()
        controls_frame.setMaximumHeight(200)  # Limit height to make more room for terminal
        controls_layout = QVBoxLayout(controls_frame)
        controls_layout.setContentsMargins(10, 5, 10, 5)  # Reduce margins
        controls_layout.setSpacing(5)  # Reduce spacing

        # === First Row: Target Input ===
        target_row = QHBoxLayout()
        target_label = QLabel("Target:")
        target_label.setFixedWidth(110)
        target_row.addWidget(target_label)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target (IP, domain, or range)...")
        self.target_input.textChanged.connect(self.check_target_type)
        self.target_input.returnPressed.connect(self.toggle_scan)
        target_row.addWidget(self.target_input)
        controls_layout.addLayout(target_row)
        
        # Create stacked widget for different tool controls
        self.controls_stack = QStackedWidget()
        self.tool_controls = {}
        
        # Create DNS controls first
        dns_controls = self.create_dns_controls()
        self.tool_controls['dns'] = dns_controls
        self.controls_stack.addWidget(dns_controls)
        
        # Create controls using factory for configured tools
        for tool_name, config in TOOL_CONFIGS.items():
            if tool_name != 'dns':  # Skip DNS as we created it above
                control_panel = ControlPanelFactory.create_panel(config, self)
                self.tool_controls[tool_name] = control_panel
                self.controls_stack.addWidget(control_panel)
                
                # Connect tool-specific button actions
                self.connect_tool_buttons(tool_name, control_panel)
        
        # Create remaining controls using existing methods (to be migrated)
        remaining_tools = ['rpc', 'http', 'api', 'ldap', 'db', 'ike', 'av_firewall']
        for tool in remaining_tools:
            method_name = f'create_{tool}_controls'
            if hasattr(self, method_name):
                control_panel = getattr(self, method_name)()
                self.tool_controls[tool] = control_panel
                self.controls_stack.addWidget(control_panel)
        
        controls_layout.addWidget(self.controls_stack)
        
        # === Actions Row ===
        action_row = QHBoxLayout()
        action_row.addStretch()
        self.run_button = QPushButton("Run")
        self.run_button.setFixedWidth(80)
        self.run_button.clicked.connect(self.toggle_scan)
        action_row.addWidget(self.run_button)

        # View selection buttons
        text_icon_path = os.path.join(self.main_window.project_root, "resources", "icons", "text.png")
        graph_icon_path = os.path.join(self.main_window.project_root, "resources", "icons", "graph.png")
        
        self.text_view_btn = QToolButton()
        if os.path.exists(text_icon_path):
            self.text_view_btn.setIcon(QIcon(text_icon_path))
        else:
            self.text_view_btn.setText("Text")
        self.text_view_btn.setFixedWidth(40)
        self.text_view_btn.setCheckable(True)
        self.text_view_btn.setChecked(True)
        self.text_view_btn.clicked.connect(lambda: self.set_results_view(True))
        action_row.addWidget(self.text_view_btn)
        
        self.graph_view_btn = QToolButton()
        if os.path.exists(graph_icon_path):
            self.graph_view_btn.setIcon(QIcon(graph_icon_path))
        else:
            self.graph_view_btn.setText("Graph")
        self.graph_view_btn.setFixedWidth(40)
        self.graph_view_btn.setCheckable(True)
        self.graph_view_btn.clicked.connect(lambda: self.set_results_view(False))
        action_row.addWidget(self.graph_view_btn)

        self.export_combo = QComboBox()
        self.export_combo.addItems(["JSON", "CSV", "XML", "Advanced Report", "Create Session"])
        self.export_combo.setFixedWidth(130)
        action_row.addWidget(self.export_combo)

        self.export_button = QPushButton("Export")
        self.export_button.setFixedWidth(80)
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_results)
        action_row.addWidget(self.export_button)

        controls_layout.addLayout(action_row)
        return controls_frame
    
    def create_dns_controls(self):
        """Create DNS-specific controls"""
        dns_widget = QWidget()
        layout = QVBoxLayout(dns_widget)
        layout.setSpacing(5)  # Reduce spacing between rows

        # Record Type Checkboxes - moved up
        record_row = QHBoxLayout()
        types_label = QLabel("Types:")
        types_label.setFixedWidth(110)
        record_row.addWidget(types_label)
        
        self._create_record_checkboxes(record_row)
        record_row.addStretch()
        layout.addLayout(record_row)

        # DNS Server - moved up
        dns_row = QHBoxLayout()
        dns_label = QLabel("DNS:")
        dns_label.setFixedWidth(110)
        dns_row.addWidget(dns_label)
        self.dns_input = QLineEdit()
        self.dns_input.setPlaceholderText("DNS Server (optional)")
        self.dns_input.setFixedWidth(400)
        self.dns_input.returnPressed.connect(self.toggle_scan)
        dns_row.addWidget(self.dns_input)
        dns_row.addStretch()
        layout.addLayout(dns_row)

        # Method & Wordlist/Bruteforce - moved up
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

        # Bruteforce options
        self._create_bruteforce_options(method_row)
        method_row.addStretch()
        self.method_row_layout = method_row
        layout.addLayout(method_row)
        
        # Add stretch to push everything up
        layout.addStretch()
        
        self.toggle_method_options("Wordlist")
        
        # Set default selections - only A record
        self.record_type_checkboxes['A'].setChecked(True)
        self._set_default_wordlist()
        
        return dns_widget
    
    def _set_default_wordlist(self):
        """Set default wordlist to subdomains-top1000.txt"""
        default_wordlist_path = os.path.join(self.main_window.project_root, "resources", "wordlists", "subdomains-top1000.txt")
        for i in range(self.wordlist_combo.count()):
            if self.wordlist_combo.itemData(i) == default_wordlist_path:
                self.wordlist_combo.setCurrentIndex(i)
                break
    

    
    def create_rpc_controls(self):
        """Create RPC enumeration specific controls"""
        rpc_widget = QWidget()
        layout = QVBoxLayout(rpc_widget)
        
        # Authentication
        auth_row = QHBoxLayout()
        auth_label = QLabel("Auth:")
        auth_label.setFixedWidth(110)
        auth_row.addWidget(auth_label)
        self.auth_combo = QComboBox()
        self.auth_combo.addItems(["Anonymous", "Credentials"])
        self.auth_combo.setFixedWidth(150)
        self.auth_combo.currentTextChanged.connect(self.toggle_rpc_auth)
        auth_row.addWidget(self.auth_combo)
        auth_row.addStretch()
        layout.addLayout(auth_row)
        
        # Username
        user_row = QHBoxLayout()
        user_label = QLabel("Username:")
        user_label.setFixedWidth(110)
        user_row.addWidget(user_label)
        self.rpc_username = QLineEdit()
        self.rpc_username.setPlaceholderText("Domain username")
        self.rpc_username.setVisible(False)
        user_row.addWidget(self.rpc_username)
        layout.addLayout(user_row)
        
        # Password
        pass_row = QHBoxLayout()
        pass_label = QLabel("Password:")
        pass_label.setFixedWidth(110)
        pass_row.addWidget(pass_label)
        self.rpc_password = QLineEdit()
        self.rpc_password.setPlaceholderText("Password")
        self.rpc_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.rpc_password.setVisible(False)
        pass_row.addWidget(self.rpc_password)
        layout.addLayout(pass_row)
        
        return rpc_widget
    
    def toggle_rpc_auth(self, auth_type):
        """Toggle RPC authentication fields"""
        show_creds = (auth_type == "Credentials")
        self.rpc_username.setVisible(show_creds)
        self.rpc_password.setVisible(show_creds)
    
    def create_smb_controls(self):
        """Create SMB enumeration specific controls"""
        smb_widget = QWidget()
        layout = QVBoxLayout(smb_widget)
        
        # Scan Type
        scan_type_row = QHBoxLayout()
        scan_type_label = QLabel("Scan Type:")
        scan_type_label.setFixedWidth(110)
        scan_type_row.addWidget(scan_type_label)
        self.smb_scan_type = QComboBox()
        self.smb_scan_type.addItems(["Basic Info", "Share Enumeration", "Vulnerability Scan"])
        self.smb_scan_type.setFixedWidth(150)
        scan_type_row.addWidget(self.smb_scan_type)
        scan_type_row.addStretch()
        layout.addLayout(scan_type_row)
        
        # Authentication
        auth_row = QHBoxLayout()
        auth_label = QLabel("Auth:")
        auth_label.setFixedWidth(110)
        auth_row.addWidget(auth_label)
        self.smb_auth_combo = QComboBox()
        self.smb_auth_combo.addItems(["Anonymous", "Credentials"])
        self.smb_auth_combo.setFixedWidth(150)
        self.smb_auth_combo.currentTextChanged.connect(self.toggle_smb_auth)
        auth_row.addWidget(self.smb_auth_combo)
        auth_row.addStretch()
        layout.addLayout(auth_row)
        
        # Username
        user_row = QHBoxLayout()
        user_label = QLabel("Username:")
        user_label.setFixedWidth(110)
        user_row.addWidget(user_label)
        self.smb_username = QLineEdit()
        self.smb_username.setPlaceholderText("Domain\\username or username")
        self.smb_username.setVisible(False)
        user_row.addWidget(self.smb_username)
        layout.addLayout(user_row)
        
        # Password
        pass_row = QHBoxLayout()
        pass_label = QLabel("Password:")
        pass_label.setFixedWidth(110)
        pass_row.addWidget(pass_label)
        self.smb_password = QLineEdit()
        self.smb_password.setPlaceholderText("Password")
        self.smb_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.smb_password.setVisible(False)
        pass_row.addWidget(self.smb_password)
        layout.addLayout(pass_row)
        
        return smb_widget
    
    def toggle_smb_auth(self, auth_type):
        """Toggle SMB authentication fields"""
        show_creds = (auth_type == "Credentials")
        self.smb_username.setVisible(show_creds)
        self.smb_password.setVisible(show_creds)
    
    def create_smtp_controls(self):
        """Create SMTP enumeration specific controls"""
        smtp_widget = QWidget()
        layout = QVBoxLayout(smtp_widget)
        
        # Port
        port_row = QHBoxLayout()
        port_label = QLabel("Port:")
        port_label.setFixedWidth(110)
        port_row.addWidget(port_label)
        self.smtp_port = QLineEdit()
        self.smtp_port.setText("25")
        self.smtp_port.setFixedWidth(100)
        port_row.addWidget(self.smtp_port)
        port_row.addStretch()
        layout.addLayout(port_row)
        
        # Domain
        domain_row = QHBoxLayout()
        domain_label = QLabel("Domain:")
        domain_label.setFixedWidth(110)
        domain_row.addWidget(domain_label)
        self.smtp_domain = QLineEdit()
        self.smtp_domain.setPlaceholderText("Target domain for RCPT TO (optional)")
        domain_row.addWidget(self.smtp_domain)
        layout.addLayout(domain_row)
        
        # HELO Name
        helo_row = QHBoxLayout()
        helo_label = QLabel("HELO Name:")
        helo_label.setFixedWidth(110)
        helo_row.addWidget(helo_label)
        self.smtp_helo = QLineEdit()
        self.smtp_helo.setText("test.local")
        self.smtp_helo.setPlaceholderText("HELO/EHLO identifier")
        helo_row.addWidget(self.smtp_helo)
        layout.addLayout(helo_row)
        
        # Wordlist
        wordlist_row = QHBoxLayout()
        wordlist_label = QLabel("Wordlist:")
        wordlist_label.setFixedWidth(110)
        wordlist_row.addWidget(wordlist_label)
        self.smtp_wordlist = QComboBox()
        self.populate_smtp_wordlists()
        wordlist_row.addWidget(self.smtp_wordlist)
        layout.addLayout(wordlist_row)
        
        return smtp_widget
    
    def populate_smtp_wordlists(self):
        """Populate SMTP wordlist dropdown"""
        self.smtp_wordlist.addItem("Default usernames", None)
        wordlist_dir = os.path.join(self.main_window.project_root, "resources", "wordlists")
        if os.path.exists(wordlist_dir):
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt"):
                    self.smtp_wordlist.addItem(filename, os.path.join(wordlist_dir, filename))
    
    def create_snmp_controls(self):
        """Create SNMP enumeration specific controls"""
        snmp_widget = QWidget()
        layout = QVBoxLayout(snmp_widget)
        
        # SNMP Version
        version_row = QHBoxLayout()
        version_label = QLabel("Version:")
        version_label.setFixedWidth(110)
        version_row.addWidget(version_label)
        self.snmp_version = QComboBox()
        self.snmp_version.addItems(["2c", "1", "3"])
        self.snmp_version.setFixedWidth(100)
        version_row.addWidget(self.snmp_version)
        version_row.addStretch()
        layout.addLayout(version_row)
        
        # Scan Type
        scan_type_row = QHBoxLayout()
        scan_type_label = QLabel("Scan Type:")
        scan_type_label.setFixedWidth(110)
        scan_type_row.addWidget(scan_type_label)
        self.snmp_scan_type = QComboBox()
        self.snmp_scan_type.addItems(["Basic Info", "Users", "Processes", "Software", "Network", "Full Enumeration"])
        self.snmp_scan_type.setFixedWidth(150)
        scan_type_row.addWidget(self.snmp_scan_type)
        scan_type_row.addStretch()
        layout.addLayout(scan_type_row)
        
        # Community Strings
        community_row = QHBoxLayout()
        community_label = QLabel("Communities:")
        community_label.setFixedWidth(110)
        community_row.addWidget(community_label)
        self.snmp_communities = QLineEdit()
        self.snmp_communities.setText("public,private,community")
        self.snmp_communities.setPlaceholderText("Comma-separated community strings")
        community_row.addWidget(self.snmp_communities)
        layout.addLayout(community_row)
        
        # Quick community buttons
        quick_comm_row = QHBoxLayout()
        quick_comm_label = QLabel("Quick:")
        quick_comm_label.setFixedWidth(110)
        quick_comm_row.addWidget(quick_comm_label)
        
        self.default_comm_btn = QPushButton("Default")
        self.default_comm_btn.clicked.connect(lambda: self.snmp_communities.setText("public,private,community"))
        quick_comm_row.addWidget(self.default_comm_btn)
        
        self.extended_comm_btn = QPushButton("Extended")
        self.extended_comm_btn.clicked.connect(lambda: self.snmp_communities.setText("public,private,community,manager,admin,administrator,root,guest,read,write,test,cisco,default,snmp"))
        quick_comm_row.addWidget(self.extended_comm_btn)
        
        quick_comm_row.addStretch()
        layout.addLayout(quick_comm_row)
        
        return snmp_widget
    
    def create_http_controls(self):
        """Create HTTP enumeration specific controls"""
        http_widget = QWidget()
        layout = QVBoxLayout(http_widget)
        
        # Scan Type
        scan_type_row = QHBoxLayout()
        scan_type_label = QLabel("Scan Type:")
        scan_type_label.setFixedWidth(110)
        scan_type_row.addWidget(scan_type_label)
        self.http_scan_type = QComboBox()
        self.http_scan_type.addItems(["Basic Fingerprint", "Directory Enum", "Nmap Scripts", "Nikto Scan", "Full Scan"])
        self.http_scan_type.setFixedWidth(150)
        scan_type_row.addWidget(self.http_scan_type)
        scan_type_row.addStretch()
        layout.addLayout(scan_type_row)
        
        # Extensions
        ext_row = QHBoxLayout()
        ext_label = QLabel("Extensions:")
        ext_label.setFixedWidth(110)
        ext_row.addWidget(ext_label)
        self.http_extensions = QLineEdit()
        self.http_extensions.setText(".php,.html,.asp,.aspx,.jsp")
        self.http_extensions.setPlaceholderText("Comma-separated file extensions")
        ext_row.addWidget(self.http_extensions)
        layout.addLayout(ext_row)
        
        # Wordlist
        wordlist_row = QHBoxLayout()
        wordlist_label = QLabel("Wordlist:")
        wordlist_label.setFixedWidth(110)
        wordlist_row.addWidget(wordlist_label)
        self.http_wordlist = QComboBox()
        self.populate_http_wordlists()
        wordlist_row.addWidget(self.http_wordlist)
        layout.addLayout(wordlist_row)
        
        # Quick extension buttons
        quick_ext_row = QHBoxLayout()
        quick_ext_label = QLabel("Quick:")
        quick_ext_label.setFixedWidth(110)
        quick_ext_row.addWidget(quick_ext_label)
        
        self.php_ext_btn = QPushButton("PHP")
        self.php_ext_btn.clicked.connect(lambda: self.http_extensions.setText(".php,.phtml,.php3,.php4,.php5"))
        quick_ext_row.addWidget(self.php_ext_btn)
        
        self.asp_ext_btn = QPushButton("ASP")
        self.asp_ext_btn.clicked.connect(lambda: self.http_extensions.setText(".asp,.aspx,.asmx,.ashx"))
        quick_ext_row.addWidget(self.asp_ext_btn)
        
        self.jsp_ext_btn = QPushButton("JSP")
        self.jsp_ext_btn.clicked.connect(lambda: self.http_extensions.setText(".jsp,.jsf,.jspx,.do"))
        quick_ext_row.addWidget(self.jsp_ext_btn)
        
        quick_ext_row.addStretch()
        layout.addLayout(quick_ext_row)
        
        return http_widget
    
    def populate_http_wordlists(self):
        """Populate HTTP wordlist dropdown"""
        self.http_wordlist.addItem("Default directories", None)
        wordlist_dir = os.path.join(self.main_window.project_root, "resources", "wordlists")
        if os.path.exists(wordlist_dir):
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt"):
                    self.http_wordlist.addItem(filename, os.path.join(wordlist_dir, filename))
    
    def create_api_controls(self):
        """Create API enumeration specific controls"""
        api_widget = QWidget()
        layout = QVBoxLayout(api_widget)
        
        # Scan Type
        scan_type_row = QHBoxLayout()
        scan_type_label = QLabel("Scan Type:")
        scan_type_label.setFixedWidth(110)
        scan_type_row.addWidget(scan_type_label)
        self.api_scan_type = QComboBox()
        self.api_scan_type.addItems(["Basic Discovery", "Gobuster Enum", "HTTP Methods", "Auth Bypass", "Vulnerability Test", "Full Scan"])
        self.api_scan_type.setFixedWidth(150)
        scan_type_row.addWidget(self.api_scan_type)
        scan_type_row.addStretch()
        layout.addLayout(scan_type_row)
        
        # Wordlist
        wordlist_row = QHBoxLayout()
        wordlist_label = QLabel("Wordlist:")
        wordlist_label.setFixedWidth(110)
        wordlist_row.addWidget(wordlist_label)
        self.api_wordlist = QComboBox()
        self.populate_api_wordlists()
        wordlist_row.addWidget(self.api_wordlist)
        layout.addLayout(wordlist_row)
        
        # Common API patterns info
        info_row = QHBoxLayout()
        info_label = QLabel("Patterns:")
        info_label.setFixedWidth(110)
        info_row.addWidget(info_label)
        patterns_text = QLabel("/api, /api/v1, /rest, /graphql, /swagger")
        patterns_text.setStyleSheet("color: #888; font-size: 10pt;")
        info_row.addWidget(patterns_text)
        layout.addLayout(info_row)
        
        return api_widget
    
    def populate_api_wordlists(self):
        """Populate API wordlist dropdown"""
        self.api_wordlist.addItem("Default API endpoints", None)
        wordlist_dir = os.path.join(self.main_window.project_root, "resources", "wordlists")
        if os.path.exists(wordlist_dir):
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt"):
                    self.api_wordlist.addItem(filename, os.path.join(wordlist_dir, filename))
    
    def create_ldap_controls(self):
        """Create LDAP enumeration specific controls"""
        ldap_widget = QWidget()
        layout = QVBoxLayout(ldap_widget)
        
        # Port and SSL
        port_row = QHBoxLayout()
        port_label = QLabel("Port:")
        port_label.setFixedWidth(110)
        port_row.addWidget(port_label)
        self.ldap_port = QLineEdit()
        self.ldap_port.setText("389")
        self.ldap_port.setFixedWidth(100)
        port_row.addWidget(self.ldap_port)
        
        self.ldap_ssl_checkbox = QCheckBox("Use SSL/TLS (636)")
        self.ldap_ssl_checkbox.stateChanged.connect(self.toggle_ldap_ssl)
        port_row.addWidget(self.ldap_ssl_checkbox)
        port_row.addStretch()
        layout.addLayout(port_row)
        
        # Scan Type
        scan_type_row = QHBoxLayout()
        scan_type_label = QLabel("Scan Type:")
        scan_type_label.setFixedWidth(110)
        scan_type_row.addWidget(scan_type_label)
        self.ldap_scan_type = QComboBox()
        self.ldap_scan_type.addItems(["Basic Info", "Anonymous Enum", "Authenticated Enum", "Full Scan"])
        self.ldap_scan_type.setFixedWidth(150)
        self.ldap_scan_type.currentTextChanged.connect(self.toggle_ldap_auth)
        scan_type_row.addWidget(self.ldap_scan_type)
        scan_type_row.addStretch()
        layout.addLayout(scan_type_row)
        
        # Base DN
        base_dn_row = QHBoxLayout()
        base_dn_label = QLabel("Base DN:")
        base_dn_label.setFixedWidth(110)
        base_dn_row.addWidget(base_dn_label)
        self.ldap_base_dn = QLineEdit()
        self.ldap_base_dn.setPlaceholderText("DC=domain,DC=com (auto-detected if empty)")
        base_dn_row.addWidget(self.ldap_base_dn)
        layout.addLayout(base_dn_row)
        
        # Authentication section
        auth_label = QLabel("Authentication (for Authenticated Enum):")
        auth_label.setStyleSheet("color: #87CEEB; font-weight: bold;")
        layout.addWidget(auth_label)
        
        # Username
        user_row = QHBoxLayout()
        user_label = QLabel("Username:")
        user_label.setFixedWidth(110)
        user_row.addWidget(user_label)
        self.ldap_username = QLineEdit()
        self.ldap_username.setPlaceholderText("Domain\\username or username@domain.com")
        self.ldap_username.setVisible(False)
        user_row.addWidget(self.ldap_username)
        layout.addLayout(user_row)
        
        # Password
        pass_row = QHBoxLayout()
        pass_label = QLabel("Password:")
        pass_label.setFixedWidth(110)
        pass_row.addWidget(pass_label)
        self.ldap_password = QLineEdit()
        self.ldap_password.setPlaceholderText("Password")
        self.ldap_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.ldap_password.setVisible(False)
        pass_row.addWidget(self.ldap_password)
        layout.addLayout(pass_row)
        
        return ldap_widget
    
    def toggle_ldap_ssl(self, state):
        """Toggle LDAP SSL port"""
        if state == 2:  # Checked
            self.ldap_port.setText("636")
        else:
            self.ldap_port.setText("389")
    
    def toggle_ldap_auth(self, scan_type):
        """Toggle LDAP authentication fields"""
        show_auth = scan_type in ["Authenticated Enum", "Full Scan"]
        self.ldap_username.setVisible(show_auth)
        self.ldap_password.setVisible(show_auth)
    
    def create_db_controls(self):
        """Create database enumeration specific controls"""
        db_widget = QWidget()
        layout = QVBoxLayout(db_widget)
        
        # Database Type
        db_type_row = QHBoxLayout()
        db_type_label = QLabel("DB Type:")
        db_type_label.setFixedWidth(110)
        db_type_row.addWidget(db_type_label)
        self.db_type_combo = QComboBox()
        self.db_type_combo.addItems(["MSSQL", "Oracle"])
        self.db_type_combo.setFixedWidth(150)
        self.db_type_combo.currentTextChanged.connect(self.toggle_db_type)
        db_type_row.addWidget(self.db_type_combo)
        db_type_row.addStretch()
        layout.addLayout(db_type_row)
        
        # Port
        port_row = QHBoxLayout()
        port_label = QLabel("Port:")
        port_label.setFixedWidth(110)
        port_row.addWidget(port_label)
        self.db_port = QLineEdit()
        self.db_port.setText("1433")
        self.db_port.setFixedWidth(100)
        port_row.addWidget(self.db_port)
        port_row.addStretch()
        layout.addLayout(port_row)
        
        # Scan Type
        scan_type_row = QHBoxLayout()
        scan_type_label = QLabel("Scan Type:")
        scan_type_label.setFixedWidth(110)
        scan_type_row.addWidget(scan_type_label)
        self.db_scan_type = QComboBox()
        self.db_scan_type.addItems(["Basic Info", "Scripts", "Custom Query", "Full Scan"])
        self.db_scan_type.setFixedWidth(150)
        self.db_scan_type.currentTextChanged.connect(self.toggle_db_options)
        scan_type_row.addWidget(self.db_scan_type)
        scan_type_row.addStretch()
        layout.addLayout(scan_type_row)
        
        # Oracle SID (for Oracle only)
        sid_row = QHBoxLayout()
        sid_label = QLabel("Oracle SID:")
        sid_label.setFixedWidth(110)
        sid_row.addWidget(sid_label)
        self.oracle_sid = QLineEdit()
        self.oracle_sid.setText("DB11g")
        self.oracle_sid.setPlaceholderText("Oracle SID for brute force")
        self.oracle_sid.setVisible(False)
        sid_row.addWidget(self.oracle_sid)
        layout.addLayout(sid_row)
        
        # Custom Query
        query_row = QHBoxLayout()
        query_label = QLabel("Query:")
        query_label.setFixedWidth(110)
        query_row.addWidget(query_label)
        self.db_query = QLineEdit()
        self.db_query.setPlaceholderText("SELECT name FROM sys.databases")
        self.db_query.setVisible(False)
        query_row.addWidget(self.db_query)
        layout.addLayout(query_row)
        
        # Quick query buttons
        quick_query_row = QHBoxLayout()
        quick_query_label = QLabel("Quick:")
        quick_query_label.setFixedWidth(110)
        quick_query_row.addWidget(quick_query_label)
        
        self.list_dbs_btn = QPushButton("List DBs")
        self.list_dbs_btn.clicked.connect(lambda: self.db_query.setText("SELECT name FROM sys.databases"))
        self.list_dbs_btn.setVisible(False)
        quick_query_row.addWidget(self.list_dbs_btn)
        
        self.list_users_btn = QPushButton("List Users")
        self.list_users_btn.clicked.connect(lambda: self.db_query.setText("SELECT name FROM sys.server_principals WHERE type = 'S'"))
        self.list_users_btn.setVisible(False)
        quick_query_row.addWidget(self.list_users_btn)
        
        self.version_btn = QPushButton("Version")
        self.version_btn.clicked.connect(lambda: self.db_query.setText("SELECT @@VERSION"))
        self.version_btn.setVisible(False)
        quick_query_row.addWidget(self.version_btn)
        
        quick_query_row.addStretch()
        layout.addLayout(quick_query_row)
        
        # Authentication section
        auth_label = QLabel("Authentication (for Scripts/Query):")
        auth_label.setStyleSheet("color: #87CEEB; font-weight: bold;")
        layout.addWidget(auth_label)
        
        # Username
        user_row = QHBoxLayout()
        user_label = QLabel("Username:")
        user_label.setFixedWidth(110)
        user_row.addWidget(user_label)
        self.db_username = QLineEdit()
        self.db_username.setPlaceholderText("sa")
        user_row.addWidget(self.db_username)
        layout.addLayout(user_row)
        
        # Password
        pass_row = QHBoxLayout()
        pass_label = QLabel("Password:")
        pass_label.setFixedWidth(110)
        pass_row.addWidget(pass_label)
        self.db_password = QLineEdit()
        self.db_password.setPlaceholderText("Password")
        self.db_password.setEchoMode(QLineEdit.EchoMode.Password)
        pass_row.addWidget(self.db_password)
        layout.addLayout(pass_row)
        
        return db_widget
    
    def toggle_db_type(self, db_type):
        """Toggle database type specific options"""
        is_oracle = (db_type == "Oracle")
        self.oracle_sid.setVisible(is_oracle)
        
        # Update default port
        if is_oracle:
            self.db_port.setText("1521")
        else:
            self.db_port.setText("1433")
    
    def toggle_db_options(self, scan_type):
        """Toggle database scan options"""
        show_query = (scan_type == "Custom Query")
        self.db_query.setVisible(show_query)
        self.list_dbs_btn.setVisible(show_query)
        self.list_users_btn.setVisible(show_query)
        self.version_btn.setVisible(show_query)
    
    def create_ike_controls(self):
        """Create IKE enumeration specific controls"""
        ike_widget = QWidget()
        layout = QVBoxLayout(ike_widget)
        
        # Port
        port_row = QHBoxLayout()
        port_label = QLabel("Port:")
        port_label.setFixedWidth(110)
        port_row.addWidget(port_label)
        self.ike_port = QLineEdit()
        self.ike_port.setText("500")
        self.ike_port.setFixedWidth(100)
        port_row.addWidget(self.ike_port)
        port_row.addStretch()
        layout.addLayout(port_row)
        
        # Scan Type
        scan_type_row = QHBoxLayout()
        scan_type_label = QLabel("Scan Type:")
        scan_type_label.setFixedWidth(110)
        scan_type_row.addWidget(scan_type_label)
        self.ike_scan_type = QComboBox()
        self.ike_scan_type.addItems(["Basic Info", "Detailed Scan", "Transform Enum", "Full Scan"])
        self.ike_scan_type.setFixedWidth(150)
        scan_type_row.addWidget(self.ike_scan_type)
        scan_type_row.addStretch()
        layout.addLayout(scan_type_row)
        
        # Aggressive Mode
        mode_row = QHBoxLayout()
        mode_label = QLabel("Mode:")
        mode_label.setFixedWidth(110)
        mode_row.addWidget(mode_label)
        self.ike_aggressive_mode = QCheckBox("Aggressive Mode (-M)")
        self.ike_aggressive_mode.setChecked(True)
        mode_row.addWidget(self.ike_aggressive_mode)
        mode_row.addStretch()
        layout.addLayout(mode_row)
        
        # Tool info
        info_row = QHBoxLayout()
        info_label = QLabel("Tool:")
        info_label.setFixedWidth(110)
        info_row.addWidget(info_label)
        tool_info = QLabel("Requires ike-scan tool")
        tool_info.setStyleSheet("color: #888; font-size: 10pt;")
        info_row.addWidget(tool_info)
        layout.addLayout(info_row)
        
        # IPSec config info
        config_label = QLabel("IPSec Configuration Files:")
        config_label.setStyleSheet("color: #87CEEB; font-weight: bold;")
        layout.addWidget(config_label)
        
        config_info = QLabel("/etc/ipsec.conf, /etc/ipsec.secrets")
        config_info.setStyleSheet("color: #888; font-size: 9pt; margin-left: 20px;")
        layout.addWidget(config_info)
        
        return ike_widget
    
    def create_av_firewall_controls(self):
        """Create AV/Firewall detection specific controls"""
        av_widget = QWidget()
        layout = QVBoxLayout(av_widget)
        
        # Detection Type
        detection_type_row = QHBoxLayout()
        detection_type_label = QLabel("Detection:")
        detection_type_label.setFixedWidth(110)
        detection_type_row.addWidget(detection_type_label)
        self.av_detection_type = QComboBox()
        self.av_detection_type.addItems(["WAF Detection", "Firewall Detection", "Evasion Test", "AV Payload Gen", "Full Detection"])
        self.av_detection_type.setFixedWidth(150)
        self.av_detection_type.currentTextChanged.connect(self.toggle_av_options)
        detection_type_row.addWidget(self.av_detection_type)
        detection_type_row.addStretch()
        layout.addLayout(detection_type_row)
        
        # Port (for WAF detection)
        port_row = QHBoxLayout()
        port_label = QLabel("Port:")
        port_label.setFixedWidth(110)
        port_row.addWidget(port_label)
        self.av_port = QLineEdit()
        self.av_port.setText("80")
        self.av_port.setFixedWidth(100)
        port_row.addWidget(self.av_port)
        port_row.addStretch()
        layout.addLayout(port_row)
        
        # Payload Type (for AV testing)
        payload_row = QHBoxLayout()
        payload_label = QLabel("Payload:")
        payload_label.setFixedWidth(110)
        payload_row.addWidget(payload_label)
        self.av_payload_type = QComboBox()
        self.av_payload_type.addItems(["msfvenom", "shellter"])
        self.av_payload_type.setFixedWidth(150)
        self.av_payload_type.setVisible(False)
        payload_row.addWidget(self.av_payload_type)
        payload_row.addStretch()
        layout.addLayout(payload_row)
        
        # Tool requirements info
        tools_label = QLabel("Tool Requirements:")
        tools_label.setStyleSheet("color: #87CEEB; font-weight: bold;")
        layout.addWidget(tools_label)
        
        tools_info = QLabel("nmap (firewall detection), msfvenom (payload generation)")
        tools_info.setStyleSheet("color: #888; font-size: 9pt; margin-left: 20px;")
        layout.addWidget(tools_info)
        
        # Detection methods info
        methods_label = QLabel("Detection Methods:")
        methods_label.setStyleSheet("color: #87CEEB; font-weight: bold;")
        layout.addWidget(methods_label)
        
        methods_info = QLabel("WAF: HTTP headers/responses, Firewall: nmap ACK/SYN scans")
        methods_info.setStyleSheet("color: #888; font-size: 9pt; margin-left: 20px;")
        layout.addWidget(methods_info)
        
        return av_widget
    
    def toggle_av_options(self, detection_type):
        """Toggle AV/Firewall detection options"""
        show_payload = (detection_type == "AV Payload Gen")
        self.av_payload_type.setVisible(show_payload)
    
    def run_ike_scan(self):
        """Execute IKE enumeration scan"""
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target IP or domain")
            return
        
        from app.tools.ike_utils import run_ike_enumeration
        from PyQt6.QtCore import QThreadPool
        
        # Get scan parameters
        port = int(self.ike_port.text() or "500")
        scan_type_map = {
            "Basic Info": "basic",
            "Detailed Scan": "detailed",
            "Transform Enum": "transforms",
            "Full Scan": "full"
        }
        scan_type = scan_type_map.get(self.ike_scan_type.currentText(), "basic")
        aggressive_mode = self.ike_aggressive_mode.isChecked()
        
        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        
        self.terminal_output.clear()
        self.progress_widget.setVisible(True)
        self.status_updated.emit(f"Starting IKE enumeration on {target}:{port}...")
        
        # Clear previous results
        self.last_scan_results = {}
        self.export_button.setEnabled(False)
        
        # Create and start worker
        self.current_worker = run_ike_enumeration(
            target=target,
            scan_type=scan_type,
            port=port,
            aggressive_mode=aggressive_mode,
            output_callback=self.append_terminal_output,
            results_callback=self.store_scan_results
        )
        
        # Connect signals
        self.current_worker.signals.finished.connect(self.on_scan_finished)
        self.current_worker.signals.progress_start.connect(self.start_progress)
        self.current_worker.signals.error.connect(self.on_scan_error)
        
        # Start worker
        QThreadPool.globalInstance().start(self.current_worker)

    def create_output_section(self):
        output_frame = QFrame()
        output_layout = QVBoxLayout(output_frame)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.setSpacing(10)



        # QStackedWidget to hold both views
        self.results_stack = QStackedWidget()
        
        # Text view (existing QTextEdit)
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setPlaceholderText("Tool output will appear here...")
        self.results_stack.addWidget(self.terminal_output)
        
        # Table view for DNS results
        from PyQt6.QtWidgets import QTableWidget
        self.dns_table = QTableWidget()
        self.dns_table.setColumnCount(3)
        self.dns_table.setHorizontalHeaderLabels(["Domain/Record", "Type", "Value"])
        self.dns_table.setSortingEnabled(True)
        self.dns_table.setAlternatingRowColors(True)
        self.results_stack.addWidget(self.dns_table)
        
        # Table view for port scan results
        from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem
        self.port_table = QTableWidget()
        self.port_table.setColumnCount(3)
        self.port_table.setHorizontalHeaderLabels(["Port", "Service", "State"])
        self.port_table.setSortingEnabled(True)
        self.port_table.setAlternatingRowColors(True)
        self.results_stack.addWidget(self.port_table)
        
        # Results table for IP addresses found in scans
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["IP Address", "Status", "Method"])
        self.results_table.setSortingEnabled(True)
        self.results_table.setAlternatingRowColors(True)
        self.results_stack.addWidget(self.results_table)
        
        # Set initial view to text
        self.results_stack.setCurrentIndex(0)
        self.current_view_is_text = True

        output_layout.addWidget(self.results_stack)
        return output_frame

    def setup_tool_data(self):
        import json
        config_path = os.path.join(self.main_window.project_root, "resources", "config", "tools.json")
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                self.main_tools_data = config['tools']
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            # Fallback to empty list if config fails
            self.main_tools_data = []

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
        self.is_scanning = False
        self.current_worker = None
        self.structured_dns_results = {}  # Store structured DNS results for tree view

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
        button.setStyleSheet("text-align: left; padding-left: 10px;")
        button.setProperty("class", "tool_button")
        button.clicked.connect(lambda: self.activate_tool_submenu(tool_data["id"]))
        button.enter_signal.connect(self.update_status_bar)
        button.leave_signal.connect(self.clear_status_bar)
        return button

    def activate_tool_submenu(self, tool_id):
        # Save current tool state
        if hasattr(self, 'terminal_output') and self.current_submenu:
            self.save_current_tool_state()
        
        self.current_submenu = tool_id
        self.update_tool_buttons()
        self.highlight_selected_tool(tool_id)
        self.status_updated.emit(f"Selected: {tool_id.replace('_', ' ').title()}")
        
        # Restore tool state for selected tool
        self.restore_tool_state(tool_id)
        
        # Map tool IDs to control names
        tool_map = {
            "dns_enum": "dns",
            "port_scan": "port", 
            "smb_enum": "smb",
            "smtp_enum": "smtp",
            "snmp_enum": "snmp"
        }
        
        control_name = tool_map.get(tool_id)
        if control_name:
            self.switch_tool_controls(control_name)
        else:
            # Fall back to old method for unconfigured tools
            self.switch_tool_controls_legacy(tool_id)
    
    def switch_tool_controls(self, tool_name):
        """Switch to controls for specified tool"""
        if tool_name in self.tool_controls:
            widget = self.tool_controls[tool_name]
            index = self.controls_stack.indexOf(widget)
            if index >= 0:
                self.controls_stack.setCurrentIndex(index)
    
    def switch_tool_controls_legacy(self, tool_id):
        """Legacy method for switching controls"""
        # Map remaining tools to their indices
        legacy_map = {
            "rpc_enum": "rpc",
            "http_enum": "http", 
            "api_enum": "api",
            "ldap_enum": "ldap",
            "db_enum": "db",
            "ike_enum": "ike",
            "av_detect": "av_firewall"
        }
        
        control_name = legacy_map.get(tool_id)
        if control_name and control_name in self.tool_controls:
            widget = self.tool_controls[control_name]
            index = self.controls_stack.indexOf(widget)
            if index >= 0:
                self.controls_stack.setCurrentIndex(index)
    
    def connect_tool_buttons(self, tool_name, control_panel):
        """Connect tool-specific button actions"""
        controls = control_panel.controls
        
        if tool_name == 'port':
            # Connect scan type change handler
            if 'scan_type_combo' in controls:
                controls['scan_type_combo'].currentTextChanged.connect(self.on_port_scan_type_changed)
                # Set initial visibility
                self.on_port_scan_type_changed(controls['scan_type_combo'].currentText())
            
            # Set default values
            if 'ping_timeout' in controls:
                controls['ping_timeout'].setValue(2000)
            
            # Connect button actions
            if 'common_btn' in controls:
                controls['common_btn'].clicked.connect(
                    lambda: self.set_common_ports_for_control_panel(controls['port_input'])
                )
            if 'top1000_btn' in controls:
                controls['top1000_btn'].clicked.connect(
                    lambda: controls['port_input'].setText("1-1000")
                )
            if 'all_btn' in controls:
                controls['all_btn'].clicked.connect(
                    lambda: controls['port_input'].setText("1-65535")
                )
        
        elif tool_name == 'snmp':
            if 'default_btn' in controls:
                controls['default_btn'].clicked.connect(
                    lambda: controls['snmp_communities'].setText("public,private,community")
                )
            if 'extended_btn' in controls:
                controls['extended_btn'].clicked.connect(
                    lambda: controls['snmp_communities'].setText("public,private,community,manager,admin,administrator,root,guest,read,write,test,cisco,default,snmp")
                )
    
    def highlight_selected_tool(self, selected_id):
        for i, button in enumerate(self.main_tool_buttons):
            if self.main_tools_data[i]["id"] == selected_id:
                button.setProperty("class", "tool_button selected")
            else:
                button.setProperty("class", "tool_button")
            button.style().unpolish(button)
            button.style().polish(button)

    def update_tool_buttons(self):
        pass  # Tool buttons removed

    def toggle_all_records(self, state):
        if self.ptr_checkbox.isEnabled():
            self.ptr_checkbox.setChecked(state == 2)
        else:
            # When ALL is selected, check all record types including SRV
            for checkbox in self.record_type_checkboxes.values():
                checkbox.setChecked(state == 2)
            if state == 2:  # ALL selected
                self._set_default_wordlist()
    
    def update_all_checkbox(self):
        all_checked = all(cb.isChecked() for cb in self.record_type_checkboxes.values()) and (not self.ptr_checkbox.isEnabled() or self.ptr_checkbox.isChecked())
        self.all_checkbox.setChecked(all_checked)
        
        # Handle SRV selection logic
        srv_checked = 'SRV' in self.record_type_checkboxes and self.record_type_checkboxes['SRV'].isChecked()
        other_checked = any(cb.isChecked() for rtype, cb in self.record_type_checkboxes.items() if rtype != 'SRV')
        all_checked = self.all_checkbox.isChecked()
        
        # Always enable all checkboxes (no exclusive SRV mode)
        self.all_checkbox.setEnabled(True)
        for cb in self.record_type_checkboxes.values():
            cb.setEnabled(True)
        
        # Set wordlist based on selection
        if srv_checked and not other_checked and not all_checked:
            # SRV only - use srv_wordlist.txt
            srv_wordlist_path = os.path.join(self.main_window.project_root, "resources", "wordlists", "srv_wordlist.txt")
            for i in range(self.wordlist_combo.count()):
                if self.wordlist_combo.itemData(i) == srv_wordlist_path:
                    self.wordlist_combo.setCurrentIndex(i)
                    break
        else:
            # Any other combination - use default wordlist
            self._set_default_wordlist()
    
    def check_target_type(self, text):
        # Only process if DNS controls are active
        if not hasattr(self, 'ptr_checkbox'):
            return
            
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
            if hasattr(self, 'method_row_layout'):
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
            if hasattr(self, 'method_row_layout'):
                for i in range(self.method_row_layout.count()):
                    item = self.method_row_layout.itemAt(i)
                    if item and item.widget():
                        item.widget().setVisible(True)
                # Re-apply method visibility settings
                if hasattr(self, 'method_combo'):
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
            if self.current_submenu == "port_scan":
                self.run_port_scan()
            elif self.current_submenu == "rpc_enum":
                self.run_rpc_scan()
            elif self.current_submenu == "smb_enum":
                self.run_smb_scan()
            elif self.current_submenu == "smtp_enum":
                self.run_smtp_scan()
            elif self.current_submenu == "snmp_enum":
                self.run_snmp_scan()
            elif self.current_submenu == "http_enum":
                self.run_http_scan()
            elif self.current_submenu == "api_enum":
                self.run_api_scan()
            elif self.current_submenu == "ldap_enum":
                self.run_ldap_scan()
            elif self.current_submenu == "db_enum":
                self.run_db_scan()
            elif self.current_submenu == "ike_enum":
                self.run_ike_scan()
            elif self.current_submenu == "av_detect":
                self.run_av_firewall_scan()
            else:
                self.run_host_wordlist_scan()
    
    def cancel_scan(self):
        if self.current_worker:
            self.current_worker.is_running = False
        self.is_scanning = False
        self.run_button.setText("Run")
        self.run_button.setStyleSheet("")
        self.progress_widget.setVisible(False)
        self.status_updated.emit("Scan cancelled")
    
    def run_host_wordlist_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target domain")
            return
        
        dns_input = getattr(self, 'dns_input', None)
        dns_server = dns_input.text().strip() or None if dns_input else None
        
        ptr_checkbox = getattr(self, 'ptr_checkbox', None)
        if ptr_checkbox and ptr_checkbox.isEnabled() and ptr_checkbox.isChecked():
            # PTR query for IP targets - no wordlist/bruteforce needed
            self.is_scanning = True
            self.run_button.setText("Cancel")
            self.run_button.setStyleSheet("background-color: red; color: white;")
            
            self.terminal_output.clear()
            self.progress_widget.setVisible(True)
            
            # Clear previous scan results
            self.last_scan_results = {}
            self.export_button.setEnabled(False)
            
            self.current_worker = dns_utils.query_ptr_records(
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
        
        # Check if ALL is selected
        all_checkbox = getattr(self, 'all_checkbox', None)
        is_all_selected = all_checkbox and all_checkbox.isChecked()
        
        # Process record types in order: A/AAAA, CNAME, MX, TXT, NS, then SRV
        record_order = ['A', 'CNAME', 'MX', 'TXT', 'NS', 'SRV']
        record_type_checkboxes = getattr(self, 'record_type_checkboxes', {})
        
        # Check if SRV is selected (handled separately)
        srv_selected = False
        
        for rtype in record_order:
            if rtype in record_type_checkboxes:
                cb = record_type_checkboxes[rtype]
                if cb.isChecked() or is_all_selected:
                    if rtype == 'A':
                        selected_types.extend(['A', 'AAAA'])
                    elif rtype in ['CNAME']:
                        selected_types.append(rtype)
                    elif rtype == 'SRV':
                        # SRV always runs separately
                        srv_selected = True
                        continue
                    else:
                        direct_query_types.append(rtype)
        
        if not selected_types and not direct_query_types and not srv_selected:
            # If no types selected but PTR is available, that's fine for IP targets
            ptr_checkbox = getattr(self, 'ptr_checkbox', None)
            if not (ptr_checkbox and ptr_checkbox.isEnabled() and ptr_checkbox.isChecked()):
                self.show_error("Please select at least one record type")
                return
            
        method_combo = getattr(self, 'method_combo', None)
        method = method_combo.currentText() if method_combo else "Wordlist"
        
        wordlist_combo = getattr(self, 'wordlist_combo', None)
        wordlist_path = wordlist_combo.currentData() if wordlist_combo and method == "Wordlist" else None
        
        char_checkboxes = getattr(self, 'char_checkboxes', {})
        char_sets = [k for k, v in char_checkboxes.items() if v.isChecked()] if method == "Bruteforce" else None
        
        length_spinbox = getattr(self, 'length_spinbox', None)
        max_length = length_spinbox.value() if length_spinbox and method == "Bruteforce" else 3
        
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
        if selected_types or direct_query_types or srv_selected:
            self.append_terminal_output(f"<p style='color: #00BFFF;'>Enumerating.... Please wait....</p><br>")
        
        # If only SRV is selected, run SRV scan directly
        if srv_selected and not selected_types and not direct_query_types:
            from app.tools.recon import SRVOnlyWorker
            self.current_worker = SRVOnlyWorker(target, dns_server)
            self.current_worker.signals.output.connect(self.append_terminal_output)
            self.current_worker.signals.status.connect(self.update_status_bar_text)
            self.current_worker.signals.finished.connect(self.on_scan_finished)
            self.current_worker.signals.results_ready.connect(self.store_scan_results)
            self.current_worker.signals.progress_start.connect(self.start_progress)
            self.current_worker.signals.progress_update.connect(self.update_progress)
            QThreadPool.globalInstance().start(self.current_worker)
            return
            
        # Check if SRV scan will be needed after main scan
        needs_srv_scan = srv_selected
        
        # Start the actual enumeration for other types
        if selected_types or direct_query_types:
            self.current_worker = dns_utils.enumerate_hostnames(
                target=target,
                wordlist_path=wordlist_path,
                record_types=selected_types + direct_query_types,
                use_bruteforce=(method == "Bruteforce"),
                char_sets=char_sets,
                max_length=max_length,
                dns_server=dns_server,
                output_callback=self.append_terminal_output,
                status_callback=self.update_status_bar_text,
                finished_callback=self._on_dns_scan_finished if needs_srv_scan else self.on_scan_finished,
                results_callback=self.store_scan_results,
                progress_callback=self.update_progress,
                progress_start_callback=self.start_progress
            )
    
    def run_ldap_scan(self):
        """Execute LDAP enumeration scan"""
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target IP or domain")
            return
        
        from app.tools.ldap_utils import run_ldap_enumeration
        from PyQt6.QtCore import QThreadPool
        
        # Get scan parameters
        port = int(self.ldap_port.text() or "389")
        use_ssl = self.ldap_ssl_checkbox.isChecked()
        scan_type_map = {
            "Basic Info": "basic",
            "Anonymous Enum": "anonymous", 
            "Authenticated Enum": "authenticated",
            "Full Scan": "full"
        }
        scan_type = scan_type_map.get(self.ldap_scan_type.currentText(), "basic")
        base_dn = self.ldap_base_dn.text().strip() or None
        username = self.ldap_username.text().strip() or None
        password = self.ldap_password.text().strip() or None
        
        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        
        self.terminal_output.clear()
        self.progress_widget.setVisible(True)
        self.status_updated.emit(f"Starting LDAP enumeration on {target}:{port}...")
        
        # Clear previous results
        self.last_scan_results = {}
        self.export_button.setEnabled(False)
        
        # Create and start worker
        self.current_worker = run_ldap_enumeration(
            target=target,
            scan_type=scan_type,
            port=port,
            use_ssl=use_ssl,
            username=username,
            password=password,
            base_dn=base_dn,
            output_callback=self.append_terminal_output,
            results_callback=self.store_scan_results
        )
        
        # Connect signals
        self.current_worker.signals.finished.connect(self.on_scan_finished)
        self.current_worker.signals.progress_start.connect(self.start_progress)
        self.current_worker.signals.error.connect(self.on_scan_error)
        
        # Start worker
        QThreadPool.globalInstance().start(self.current_worker)
    
    def on_scan_error(self, error_msg):
        """Handle scan errors"""
        self.append_terminal_output(f"<p style='color: #FF6B6B;'>Error: {error_msg}</p>")
        self.on_scan_finished()
    
    def start_progress(self, message):
        """Start progress indication"""
        self.progress_widget.start_progress(message)
    
    def on_scan_finished(self):
        """Handle scan completion"""
        self.is_scanning = False
        self.run_button.setText("Run")
        self.run_button.setStyleSheet("")
        self.progress_widget.setVisible(False)
        self.status_updated.emit("Scan completed")
        
        if self.last_scan_results:
            self.export_button.setEnabled(True)
    
    def store_scan_results(self, results):
        """Store scan results for export"""
        self.last_scan_results = results
        self.last_scan_target = self.target_input.text().strip()
    
    def show_error(self, message):
        """Show error message"""
        self.append_terminal_output(f"<p style='color: #FF6B6B;'>Error: {message}</p>")
    
    def append_terminal_output(self, text):
        """Append text to terminal output"""
        if hasattr(self, 'terminal_output'):
            self.terminal_output.append(text)
    
    def populate_wordlists(self):
        """Populate DNS wordlist dropdown"""
        self.wordlist_combo.addItem("Default subdomains", None)
        wordlist_dir = os.path.join(self.main_window.project_root, "resources", "wordlists")
        if os.path.exists(wordlist_dir):
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt"):
                    self.wordlist_combo.addItem(filename, os.path.join(wordlist_dir, filename))
    
    def run_port_scan(self):
        """Placeholder for port scan"""
        self.show_error("Port scanning not implemented yet")
    
    def run_rpc_scan(self):
        """Placeholder for RPC scan"""
        self.show_error("RPC scanning not implemented yet")
    
    def run_smb_scan(self):
        """Placeholder for SMB scan"""
        self.show_error("SMB scanning not implemented yet")
    
    def run_smtp_scan(self):
        """Placeholder for SMTP scan"""
        self.show_error("SMTP scanning not implemented yet")
    
    def run_snmp_scan(self):
        """Placeholder for SNMP scan"""
        self.show_error("SNMP scanning not implemented yet")
    
    def run_http_scan(self):
        """Placeholder for HTTP scan"""
        self.show_error("HTTP scanning not implemented yet")
    
    def run_api_scan(self):
        """Placeholder for API scan"""
        self.show_error("API scanning not implemented yet")
    
    def export_results(self):
        """Export scan results"""
        if not self.last_scan_results:
            self.show_error("No results to export")
            return
        
        export_format = self.export_combo.currentText()
        self.status_updated.emit(f"Exporting results as {export_format}...")
    
    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        pass
    
    def apply_theme(self):
        """Apply current theme"""
        stylesheet_path = os.path.join(self.main_window.project_root, "resources", "themes", "enumeration_page.qss")
        try:
            with open(stylesheet_path, 'r') as f:
                self.setStyleSheet(f.read())
        except FileNotFoundError:
            pass
    
    def update_status_bar(self, title, description):
        """Update status bar with tool info and show enhanced help"""
        self.status_updated.emit(f"{title}: {description}")
        
        # Show enhanced help panel for selected tool
        if hasattr(self.main_window, 'enhanced_help_panel'):
            tool_map = {
                "DNS Enumeration": "DNS Enumeration",
                "Port Scanning": "Port Scanning", 
                "SMB Enumeration": "SMB Enumeration",
                "SMTP Enumeration": "SMTP Enumeration",
                "SNMP Enumeration": "SNMP Enumeration",
                "HTTP Fingerprinting": "HTTP Enumeration",
                "API Enumeration": "API Enumeration"
            }
            if title in tool_map:
                self.main_window.enhanced_help_panel.show_tool_help(tool_map[title])
    
    def clear_status_bar(self):
        """Clear status bar"""
        self.status_updated.emit("")
    
    def navigate_home(self):
        """Clean up and navigate to home"""
        # Cancel any running scans
        if self.is_scanning and self.current_worker:
            self.current_worker.is_running = False
        
        # Clear heavy UI elements
        self.terminal_output.clear()
        self.last_scan_results = {}
        
        # Navigate
        self.navigate_signal.emit("home")
    
    def run_ptr_scan(self):
        """Placeholder for PTR scan"""
        self.show_error("PTR scanning not fully implemented")
    
    def run_zone_transfer(self):
        """Placeholder for zone transfer"""
        self.show_error("Zone transfer not implemented yet")
    
    def run_basic_records(self):
        """Placeholder for basic records"""
        self.show_error("Basic records scan not implemented yet")
    
    def update_progress(self, completed, found, status_msg=None):
        """Update progress bar"""
        if hasattr(self, 'progress_widget'):
            # Use provided status message or default
            if not status_msg:
                status_msg = "Scanning..."
            self.progress_widget.update_progress(completed, found, status_msg)
    
    def set_common_ports(self):
        """Set common ports in the port input field"""
        from app.tools.port_scanner import get_common_ports
        common_ports = get_common_ports()
        port_text = ','.join(map(str, common_ports))
        
        # Get port input from current control panel or direct attribute
        port_input = None
        if 'port' in self.tool_controls:
            control_panel = self.tool_controls['port']
            if hasattr(control_panel, 'controls') and 'port_input' in control_panel.controls:
                port_input = control_panel.controls['port_input']
        
        if not port_input:
            port_input = getattr(self, 'port_input', None)
        
        if port_input:
            port_input.setText(port_text)
    
    def set_common_ports_for_control_panel(self, port_input):
        """Set common ports for control panel port input"""
        from app.tools.port_scanner import get_common_ports
        common_ports = get_common_ports()
        port_text = ','.join(map(str, common_ports))
        port_input.setText(port_text)
    
    def on_port_scan_type_changed(self, scan_type):
        """Handle port scan type changes to show/hide fields"""
        if 'port' in self.tool_controls:
            control_panel = self.tool_controls['port']
            if hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                
                # Show/hide controls based on scan type
                if scan_type == 'Ping Sweep':
                    # Show ping options
                    if 'ping_timeout' in controls:
                        controls['ping_timeout'].setVisible(True)
                    # Hide nmap options
                    if 'timing_combo' in controls:
                        controls['timing_combo'].setVisible(False)
                    if 'enhanced_stealth_checkbox' in controls:
                        controls['enhanced_stealth_checkbox'].setVisible(False)
                    if 'parallelism_slider' in controls:
                        controls['parallelism_slider'].setVisible(False)
                    # Hide targeted scan options
                    if 'target_scan_combo' in controls:
                        controls['target_scan_combo'].setVisible(False)
                    # Hide port fields
                    controls.get('port_input', {}).setVisible(False)
                    for btn in ['common_btn', 'top1000_btn', 'all_btn']:
                        controls.get(btn, {}).setVisible(False)
                        
                elif scan_type == 'Nmap Sweep':
                    # Hide ping options
                    if 'ping_timeout' in controls:
                        controls['ping_timeout'].setVisible(False)
                    # Show nmap options
                    if 'timing_combo' in controls:
                        controls['timing_combo'].setVisible(True)
                    if 'enhanced_stealth_checkbox' in controls:
                        controls['enhanced_stealth_checkbox'].setVisible(True)
                    if 'parallelism_slider' in controls:
                        controls['parallelism_slider'].setVisible(True)
                    # Hide targeted scan options
                    if 'target_scan_combo' in controls:
                        controls['target_scan_combo'].setVisible(False)
                    # Hide port fields
                    controls.get('port_input', {}).setVisible(False)
                    for btn in ['common_btn', 'top1000_btn', 'all_btn']:
                        controls.get(btn, {}).setVisible(False)
                        
                elif scan_type == 'Targeted Scan':
                    # Hide ping and nmap sweep options
                    if 'ping_timeout' in controls:
                        controls['ping_timeout'].setVisible(False)
                    if 'timing_combo' in controls:
                        controls['timing_combo'].setVisible(False)
                    if 'enhanced_stealth_checkbox' in controls:
                        controls['enhanced_stealth_checkbox'].setVisible(False)
                    if 'parallelism_slider' in controls:
                        controls['parallelism_slider'].setVisible(False)
                    # Show targeted scan options
                    if 'target_scan_combo' in controls:
                        controls['target_scan_combo'].setVisible(True)
                    # Show port fields
                    if 'port_input' in controls:
                        controls['port_input'].setVisible(True)
                    for btn in ['common_btn', 'top1000_btn', 'all_btn']:
                        if btn in controls:
                            controls[btn].setVisible(True)
                
                # Update label visibility
                for child in control_panel.findChildren(QLabel):
                    if child.text() == 'Ports:':
                        child.setVisible(scan_type == 'Targeted Scan')
                    elif child.text() == 'Target Type:':
                        child.setVisible(scan_type == 'Targeted Scan')
                    elif child.text() == 'Timeout:':
                        child.setVisible(scan_type == 'Ping Sweep')
                    elif child.text() == 'Parallelism:':
                        child.setVisible(scan_type == 'Nmap Sweep')
    

    
    def run_av_firewall_scan(self):
        """Execute AV/Firewall detection scan"""
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target IP or domain")
            return
        
        from app.tools.av_firewall_utils import run_av_firewall_detection
        from PyQt6.QtCore import QThreadPool
        
        # Get scan parameters
        detection_type_map = {
            "WAF Detection": "waf",
            "Firewall Detection": "firewall",
            "Evasion Test": "evasion",
            "AV Payload Gen": "payload",
            "Full Detection": "full"
        }
        scan_type = detection_type_map.get(self.av_detection_type.currentText(), "waf")
        port = int(self.av_port.text() or "80")
        payload_type = self.av_payload_type.currentText()
        
        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        
        self.terminal_output.clear()
        self.progress_widget.setVisible(True)
        self.status_updated.emit(f"Starting {scan_type.upper()} detection on {target}...")
        
        # Clear previous results
        self.last_scan_results = {}
        self.export_button.setEnabled(False)
        
        # Create and start worker
        self.current_worker = run_av_firewall_detection(
            target=target,
            scan_type=scan_type,
            port=port,
            payload_type=payload_type,
            output_callback=self.append_terminal_output,
            results_callback=self.store_scan_results
        )
        
        # Connect signals
        self.current_worker.signals.finished.connect(self.on_scan_finished)
        self.current_worker.signals.progress_start.connect(self.start_progress)
        self.current_worker.signals.error.connect(self.on_scan_error)
        
        # Start worker
        QThreadPool.globalInstance().start(self.current_worker)
    
    def run_db_scan(self):
        """Execute database enumeration scan"""
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target IP or domain")
            return
        
        from app.tools.db_utils import run_database_enumeration
        from PyQt6.QtCore import QThreadPool
        
        # Get scan parameters
        db_type = self.db_type_combo.currentText().lower()
        port = int(self.db_port.text() or ("1433" if db_type == "mssql" else "1521"))
        scan_type_map = {
            "Basic Info": "basic",
            "Scripts": "scripts",
            "Custom Query": "query",
            "Full Scan": "full"
        }
        scan_type = scan_type_map.get(self.db_scan_type.currentText(), "basic")
        username = self.db_username.text().strip() or None
        password = self.db_password.text().strip() or None
        custom_query = self.db_query.text().strip() or None
        oracle_sid = self.oracle_sid.text().strip() or "DB11g"
        
        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        
        self.terminal_output.clear()
        self.progress_widget.setVisible(True)
        self.status_updated.emit(f"Starting {db_type.upper()} enumeration on {target}:{port}...")
        
        # Clear previous results
        self.last_scan_results = {}
        self.export_button.setEnabled(False)
        
        # Create and start worker
        self.current_worker = run_database_enumeration(
            target=target,
            db_type=db_type,
            scan_type=scan_type,
            port=port,
            username=username,
            password=password,
            custom_query=custom_query,
            oracle_sid=oracle_sid,
            output_callback=self.append_terminal_output,
            results_callback=self.store_scan_results
        )
        
        # Connect signals
        self.current_worker.signals.finished.connect(self.on_scan_finished)
        self.current_worker.signals.progress_start.connect(self.start_progress)
        self.current_worker.signals.error.connect(self.on_scan_error)
        
        # Start worker
        QThreadPool.globalInstance().start(self.current_worker)         

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
        dns_utils.run_zone_transfer(
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
        records = dns_utils.fetch_basic_records(target)
        for rtype, values in records.items():
            if values:
                self.append_terminal_output(f"<p style='color:#00FF41;'><b>{rtype} Records:</b></p>")
                for value in values:
                    self.append_terminal_output(f"<p style='color:#DCDCDC;'>&nbsp;&nbsp;&nbsp;-&gt; {value}</p>")
        self.status_updated.emit("Basic record scan complete")
        self.on_scan_finished()
    
    def run_port_scan(self):
        """Execute Port Scanning with workflow-based scan types"""
        from app.tools import port_utils
        
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target")
            return

        # Get scan parameters from control panel
        control_panel = self.tool_controls.get('port')
        if not control_panel:
            self.show_error("Port scanning controls not available")
            return
        controls = control_panel.controls
        scan_type = controls['scan_type_combo'].currentText()
        os_detect = controls.get('os_detection_checkbox', {}).isChecked() if hasattr(controls.get('os_detection_checkbox', {}), 'isChecked') else False
        service_detect = controls.get('service_detection_checkbox', {}).isChecked() if hasattr(controls.get('service_detection_checkbox', {}), 'isChecked') else False
        ports_text = controls['port_input'].text().strip()

        # Only Targeted Scan needs ports (except OS detection)
        if scan_type == "Targeted Scan":
            target_scan_type = controls.get('target_scan_combo', {}).currentText() if hasattr(controls.get('target_scan_combo', {}), 'currentText') else "TCP connect scan"
            if target_scan_type != "OS detection" and not ports_text:
                self.show_error("Please specify ports for this scan type")
                return
        


        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        self.terminal_output.clear()
        self.progress_widget.setVisible(True)
        self.status_updated.emit(f"Starting {scan_type} on {target}...")

        self.last_scan_results = {}
        self.export_button.setEnabled(False)

        # Handle Full Scan Workflow
        if "Full Scan Workflow" in scan_type:
            from app.tools.nmap_scanner import run_full_scan
            include_udp = controls.get('include_udp_checkbox', {}).isChecked() if hasattr(controls.get('include_udp_checkbox', {}), 'isChecked') else False
            run_aggressive = controls.get('run_aggressive_checkbox', {}).isChecked() if hasattr(controls.get('run_aggressive_checkbox', {}), 'isChecked') else False
            
            self.append_terminal_output(f"<p style='color: #00BFFF;'>Starting Full Scan Workflow on {target}...</p><br>")
            self.append_terminal_output(f"<p style='color: #FFAA00;'>UDP Scan: {'Enabled' if include_udp else 'Disabled'}</p>")
            self.append_terminal_output(f"<p style='color: #FFAA00;'>Aggressive Scan: {'Enabled' if run_aggressive else 'Disabled'}</p><br>")
            
            try:
                results = run_full_scan(target, run_udp=include_udp, run_aggressive=run_aggressive)
                
                for scan_result in results['scan_sequence']:
                    self.append_terminal_output(f"<p style='color: #87CEEB;'>[{scan_result['scan_type'].upper()}]</p>")
                    if scan_result['success']:
                        self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{scan_result['output']}</pre>")
                    else:
                        self.append_terminal_output(f"<p style='color: #FF4500;'>Error: {scan_result['error']}</p>")
                    self.append_terminal_output("<br>")
                
                if results['all_success']:
                    self.append_terminal_output(f"<p style='color: #00FF41;'>Full scan workflow completed successfully</p>")
                else:
                    self.append_terminal_output(f"<p style='color: #FFAA00;'>Full scan workflow completed with some errors</p>")
                
                self.on_scan_finished()
                return
                
            except Exception as e:
                self.append_terminal_output(f"<p style='color: #FF4500;'>Full scan workflow failed: {str(e)}</p>")
                self.on_scan_finished()
                return
        # Use nmap_scanner for all port scanning operations
        from app.tools.nmap_scanner import (scan_network_sweep, scan_syn, scan_tcp_connect, 
                                           scan_service_detection, scan_os_detection, 
                                           scan_udp, scan_aggressive, scan_targeted)
        
        # Handle UDP scan first before other scan types
        if "UDP" in scan_type:
            result = scan_udp(target, 100)
            
            if result['success']:
                self.append_terminal_output(f"<p style='color: #87CEEB;'>Starting UDP scan on {target}...</p><br>")
                for line in result['output'].split('\n'):
                    if line.strip():
                        if '/udp' in line:
                            self.append_terminal_output(f"<p style='color: #00FF41;'>[+] {line}</p><br>")
                        else:
                            self.append_terminal_output(f"<p style='color: #DCDCDC;'>{line}</p><br>")
            else:
                self.append_terminal_output(f"<p style='color: #FF4500;'>UDP scan failed: {result.get('error', 'Unknown error')}</p>")
            
            self.on_scan_finished()
            return
        
        try:
            if scan_type == "Ping Sweep":
                # Run ping sweep with custom -n and -w values
                import subprocess
                
                ping_n = '1'  # Always use 1 ping
                ping_w = str(controls.get('ping_timeout', {}).value() if hasattr(controls.get('ping_timeout', {}), 'value') else 2000)
                
                # Handle different target formats
                targets = []
                if target.endswith('.0'):
                    # Subnet format: 192.168.1.0 -> 192.168.1.1-254
                    base = target[:-1]
                    targets = [f"{base}{i}" for i in range(1, 255)]
                    self.append_terminal_output(f"<p style='color: #87CEEB;'>Ping sweep subnet {target} ({len(targets)} hosts, 100 threads)...</p><br>")
                    # Start progress widget
                    if hasattr(self, 'progress_widget'):
                        self.progress_widget.start_progress(len(targets), "Ping sweep...")
                elif '-' in target:
                    # Range format: 192.168.1.1-6 -> 192.168.1.1 to 192.168.1.6
                    parts = target.split('-')
                    if len(parts) == 2:
                        start_ip = parts[0].strip()
                        end_part = parts[1].strip()
                        
                        ip_parts = start_ip.split('.')
                        if len(ip_parts) == 4:
                            base = '.'.join(ip_parts[:3]) + '.'
                            start_octet = int(ip_parts[3])
                            end_octet = int(end_part)
                            targets = [f"{base}{i}" for i in range(start_octet, end_octet + 1)]
                            self.append_terminal_output(f"<p style='color: #87CEEB;'>Ping sweep range {target} ({len(targets)} hosts, 100 threads)...</p><br>")
                        else:
                            targets = [target]
                    else:
                        targets = [target]
                else:
                    targets = [target]
                    if hasattr(self, 'progress_widget'):
                        self.progress_widget.start_progress(1, "Ping sweep...")
                
                import concurrent.futures
                
                def ping_host(ip):
                    try:
                        result = subprocess.run(["ping", "-n", ping_n, "-w", ping_w, ip],
                                              capture_output=True, text=True, timeout=5)
                        if "TTL=" in result.stdout:
                            return ip
                    except:
                        pass
                    return None
                
                alive_count = 0
                completed_count = 0
                total_targets = len(targets)
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                    future_to_ip = {executor.submit(ping_host, ip): ip for ip in targets}
                    for future in concurrent.futures.as_completed(future_to_ip):
                        if not self.is_scanning:
                            break
                        result = future.result()
                        completed_count += 1
                        
                        if result:
                            self.append_terminal_output(f"<p style='color: #00FF41;'>Host {result} is up (ping)</p><br>")
                            alive_count += 1
                        
                        # Update progress widget
                        if hasattr(self, 'progress_widget'):
                            status_msg = f"Scanning {result}" if result else "Scanning..."
                            self.progress_widget.update_progress(completed_count, alive_count, status_msg)
                        
                        # Force UI update to show results immediately
                        from PyQt6.QtWidgets import QApplication
                        QApplication.processEvents()
                
                self.append_terminal_output(f"<p style='color: #00FF41;'>Ping sweep completed. Found {alive_count} alive host(s).</p>")
                
                # Store results for export - extract IPs from terminal output
                import re
                terminal_text = self.terminal_output.toPlainText()
                found_ips = re.findall(r'Host (\d+\.\d+\.\d+\.\d+) is up \(ping\)', terminal_text)
                
                if found_ips:
                    ping_results = {ip: {'status': 'up', 'method': 'ping'} for ip in found_ips}
                    self.store_scan_results(ping_results)
                
                self.on_scan_finished()
                return
                
            elif scan_type == "Nmap Sweep":
                # Use threaded worker for nmap sweep
                from app.tools.nmap_scanner import NetworkSweepWorker
                from PyQt6.QtCore import QThreadPool
                
                # Get nmap options
                timing = controls['timing_combo'].currentText() if 'timing_combo' in controls else 'T3'
                stealth_mode = controls['enhanced_stealth_checkbox'].isChecked() if 'enhanced_stealth_checkbox' in controls else False
                parallelism = controls['parallelism_slider'].value() if 'parallelism_slider' in controls else 100
                
                self.current_worker = NetworkSweepWorker(target, stealth_mode, None, timing, parallelism)
                self.current_worker.signals.output.connect(self.append_terminal_output)
                self.current_worker.signals.status.connect(self.update_status_bar_text)
                self.current_worker.signals.progress_start.connect(self.start_progress)
                self.current_worker.signals.progress_update.connect(lambda completed, found: self.update_progress(completed, found, f"Nmap scanning: {target}"))
                self.current_worker.signals.finished.connect(self.on_nmap_scan_finished)
                
                QThreadPool.globalInstance().start(self.current_worker)
                return
            
            elif scan_type == "Targeted Scan":
                # Get target scan type
                target_scan_type = controls.get('target_scan_combo', {}).currentText() if hasattr(controls.get('target_scan_combo', {}), 'currentText') else "TCP connect scan"
                
                # Handle UDP scans separately
                if "UDP" in target_scan_type:
                    # Clear previous results
                    self.last_scan_results = {}
                    
                    # Parse ports for UDP scan
                    if ports_text:
                        udp_ports_list = []
                        for part in ports_text.split(','):
                            part = part.strip()
                            if '-' in part:
                                start, end = map(int, part.split('-'))
                                udp_ports_list.extend(range(start, end + 1))
                            else:
                                udp_ports_list.append(int(part))
                    else:
                        udp_ports_list = None
                    
                    result = scan_udp(target, udp_ports_list)
                    
                    if result['success']:
                        self.append_terminal_output(f"<p style='color: #87CEEB;'>Starting UDP scan on {target}...</p><br>")
                        
                        # Parse UDP results for table view
                        udp_ports = []
                        for line in result['output'].split('\n'):
                            if line.strip():
                                if '/udp' in line:
                                    self.append_terminal_output(f"<p style='color: #00FF41;'>[+] {line}</p><br>")
                                    # Extract port info for table
                                    import re
                                    port_match = re.search(r'(\d+)/udp\s+\S+\s+(\S+)', line)
                                    if port_match:
                                        udp_ports.append({
                                            'port': int(port_match.group(1)),
                                            'service': port_match.group(2),
                                            'state': 'open'
                                        })
                                    else:
                                        # Try simpler pattern
                                        simple_match = re.search(r'(\d+)/udp', line)
                                        if simple_match:
                                            udp_ports.append({
                                                'port': int(simple_match.group(1)),
                                                'service': 'unknown',
                                                'state': 'open'
                                            })
                                else:
                                    self.append_terminal_output(f"<p style='color: #DCDCDC;'>{line}</p><br>")
                        
                        # Store results for table view
                        if udp_ports:
                            udp_results = {target: {'open_ports': udp_ports}}
                            self.store_scan_results(udp_results)
                    else:
                        self.append_terminal_output(f"<p style='color: #FF4500;'>UDP scan failed: {result.get('error', 'Unknown error')}</p>")
                    
                    self.on_scan_finished()
                    return
                
                # Use PortScanWorker for TCP scans
                from app.tools.port_scanner import PortScanWorker
                from PyQt6.QtCore import QThreadPool
                
                # Parse ports
                if ports_text:
                    ports = []
                    for part in ports_text.split(','):
                        part = part.strip()
                        if '-' in part:
                            start, end = map(int, part.split('-'))
                            ports.extend(range(start, end + 1))
                        else:
                            ports.append(int(part))
                else:
                    ports = [80, 443]
                
                self.current_worker = PortScanWorker(target, ports, "tcp", timeout=3)
                self.current_worker.signals.output.connect(self.append_terminal_output)
                self.current_worker.signals.status.connect(self.update_status_bar_text)
                self.current_worker.signals.progress_start.connect(self.start_progress)
                self.current_worker.signals.progress_update.connect(lambda completed, found: self.update_progress(completed, found, f"Port scanning: {target}"))
                self.current_worker.signals.finished.connect(self.on_scan_finished)
                self.current_worker.signals.results_ready.connect(self.store_scan_results)
                
                QThreadPool.globalInstance().start(self.current_worker)
                return
            
            else:
                # Handle other scan types
                if "SYN Stealth" in scan_type:
                    result = scan_syn(target, full=True)
                elif "TCP Connect" in scan_type:
                    result = scan_tcp_connect(target, ports_text or "22,80,443")
                elif "Service Detection" in scan_type:
                    result = scan_service_detection(target, ports_text or "22,80,443")
                elif "OS Detection" in scan_type:
                    result = scan_os_detection(target)
                elif "UDP Scan" in scan_type:
                    result = scan_udp(target, 100)
                    
                    if result['success']:
                        self.append_terminal_output(f"<p style='color: #87CEEB;'>Starting UDP scan on {target}...</p><br>")
                        for line in result['output'].split('\n'):
                            if line.strip():
                                if '/udp' in line:
                                    self.append_terminal_output(f"<p style='color: #00FF41;'>[+] {line}</p><br>")
                                else:
                                    self.append_terminal_output(f"<p style='color: #DCDCDC;'>{line}</p><br>")
                    else:
                        self.append_terminal_output(f"<p style='color: #FF4500;'>UDP scan failed: {result.get('error', 'Unknown error')}</p>")
                    
                    self.on_scan_finished()
                    return
                elif "Aggressive" in scan_type:
                    result = scan_aggressive(target)
                else:
                    result = scan_tcp_connect(target, ports_text or "22,80,443")
                
                if result['success']:
                    self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result['output']}</pre>")
                else:
                    error_msg = result.get('error', 'Unknown error')
                    output_msg = result.get('output', '')
                    self.append_terminal_output(f"<p style='color: #FF4500;'>Error: {error_msg}</p>")
                    if output_msg:
                        self.append_terminal_output(f"<p style='color: #FFAA00;'>Debug: {output_msg}</p>")
                
                self.on_scan_finished()
            
        except Exception as e:
            self.append_terminal_output(f"<p style='color: #FF4500;'>Exception in port scan: {str(e)}</p>")
            self.is_scanning = False
            self.run_button.setText("Run")
            self.run_button.setStyleSheet("")
            self.on_scan_finished()
            return
    
    def on_nmap_scan_finished(self):
        """Handle nmap scan completion and extract results"""
        # Extract nmap results from terminal output
        import re
        terminal_text = self.terminal_output.toPlainText()
        found_ips = re.findall(r'Host (\d+\.\d+\.\d+\.\d+) is up \(nmap\)', terminal_text)
        
        if found_ips:
            nmap_results = {ip: {'status': 'up', 'method': 'nmap'} for ip in found_ips}
            self.store_scan_results(nmap_results)
        
        # Call normal scan finished
        self.on_scan_finished()

    def run_rpc_scan(self):
        """Run RPC enumeration"""
        from app.tools import rpc_utils
        
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        
        auth_combo = getattr(self, 'auth_combo', None)
        username = self.rpc_username.text().strip() if auth_combo and auth_combo.currentText() == "Credentials" else ""
        password = self.rpc_password.text().strip() if auth_combo and auth_combo.currentText() == "Credentials" else ""
        
        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        self.terminal_output.clear()
        self.progress_widget.setVisible(False)
        
        # Clear previous scan results
        self.last_scan_results = {}
        self.export_button.setEnabled(False)
        
        self.current_worker = rpc_utils.run_rpc_enumeration(
            target=target,
            username=username,
            password=password,
            output_callback=self.append_terminal_output,
            status_callback=self.update_status_bar_text,
            finished_callback=self.on_scan_finished,
            results_callback=self.store_scan_results
        )
    
    def run_smb_scan(self):
        """Run SMB enumeration"""
        from app.tools import smb_utils
        
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        
        scan_type_map = {
            "Basic Info": "basic",
            "Share Enumeration": "shares", 
            "Vulnerability Scan": "vulns"
        }
        smb_scan_type = getattr(self, 'smb_scan_type', None)
        scan_type = scan_type_map[smb_scan_type.currentText()] if smb_scan_type else "basic"
        
        smb_auth_combo = getattr(self, 'smb_auth_combo', None)
        username = self.smb_username.text().strip() if smb_auth_combo and smb_auth_combo.currentText() == "Credentials" else ""
        password = self.smb_password.text().strip() if smb_auth_combo and smb_auth_combo.currentText() == "Credentials" else ""
        
        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        self.terminal_output.clear()
        self.progress_widget.setVisible(False)
        
        # Clear previous scan results
        self.last_scan_results = {}
        self.export_button.setEnabled(False)
        
        self.current_worker = smb_utils.run_smb_enumeration(
            target=target,
            username=username,
            password=password,
            scan_type=scan_type,
            output_callback=self.append_terminal_output,
            status_callback=self.update_status_bar_text,
            finished_callback=self.on_scan_finished,
            results_callback=self.store_scan_results
        )
    
    def run_smtp_scan(self):
        """Run SMTP enumeration"""
        from app.tools import smtp_utils
        
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        
        smtp_port = getattr(self, 'smtp_port', None)
        try:
            port = int(smtp_port.text().strip() or "25") if smtp_port else 25
        except (ValueError, AttributeError):
            self.show_error("Invalid port number")
            return
        
        smtp_domain = getattr(self, 'smtp_domain', None)
        smtp_helo = getattr(self, 'smtp_helo', None)
        smtp_wordlist = getattr(self, 'smtp_wordlist', None)
        
        domain = smtp_domain.text().strip() or target if smtp_domain else target
        helo_name = smtp_helo.text().strip() or "test.local" if smtp_helo else "test.local"
        wordlist_path = smtp_wordlist.currentData() if smtp_wordlist else None
        
        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        self.terminal_output.clear()
        self.progress_widget.setVisible(True)
        
        # Clear previous scan results
        self.last_scan_results = {}
        self.export_button.setEnabled(False)
        
        self.current_worker = smtp_utils.run_smtp_enumeration(
            target=target,
            port=port,
            wordlist_path=wordlist_path,
            domain=domain,
            helo_name=helo_name,
            output_callback=self.append_terminal_output,
            status_callback=self.update_status_bar_text,
            finished_callback=self.on_scan_finished,
            results_callback=self.store_scan_results,
            progress_callback=self.update_progress,
            progress_start_callback=self.start_progress
        )
    
    def run_snmp_scan(self):
        """Run SNMP enumeration"""
        from app.tools import snmp_utils
        
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        
        snmp_version = getattr(self, 'snmp_version', None)
        version = snmp_version.currentText() if snmp_version else "2c"
        
        scan_type_map = {
            "Basic Info": "basic",
            "Users": "users",
            "Processes": "processes",
            "Software": "software",
            "Network": "network",
            "Full Enumeration": "full"
        }
        snmp_scan_type = getattr(self, 'snmp_scan_type', None)
        scan_type = scan_type_map[snmp_scan_type.currentText()] if snmp_scan_type else "basic"
        
        snmp_communities = getattr(self, 'snmp_communities', None)
        communities_text = snmp_communities.text().strip() if snmp_communities else ""
        communities = [c.strip() for c in communities_text.split(',') if c.strip()] if communities_text else []
        
        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        self.terminal_output.clear()
        self.progress_widget.setVisible(True)
        
        # Clear previous scan results
        self.last_scan_results = {}
        self.export_button.setEnabled(False)
        
        self.current_worker = snmp_utils.run_snmp_enumeration(
            target=target,
            communities=communities,
            scan_type=scan_type,
            version=version,
            output_callback=self.append_terminal_output,
            status_callback=self.update_status_bar_text,
            finished_callback=self.on_scan_finished,
            results_callback=self.store_scan_results,
            progress_callback=self.update_progress,
            progress_start_callback=self.start_progress
        )
    
    def run_http_scan(self):
        """Run HTTP enumeration"""
        from app.tools import http_utils
        
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        
        scan_type_map = {
            "Basic Fingerprint": "basic",
            "Directory Enum": "directories",
            "Nmap Scripts": "nmap",
            "Nikto Scan": "nikto",
            "Full Scan": "full"
        }
        http_scan_type = getattr(self, 'http_scan_type', None)
        scan_type = scan_type_map[http_scan_type.currentText()] if http_scan_type else "basic"
        
        http_extensions = getattr(self, 'http_extensions', None)
        extensions_text = http_extensions.text().strip() if http_extensions else ""
        extensions = [ext.strip() for ext in extensions_text.split(',') if ext.strip()] if extensions_text else None
        
        http_wordlist = getattr(self, 'http_wordlist', None)
        wordlist_path = http_wordlist.currentData() if http_wordlist else None
        
        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        self.terminal_output.clear()
        self.progress_widget.setVisible(True)
        
        # Clear previous scan results
        self.last_scan_results = {}
        self.export_button.setEnabled(False)
        
        self.current_worker = http_utils.run_http_enumeration(
            target=target,
            scan_type=scan_type,
            wordlist_path=wordlist_path,
            extensions=extensions,
            output_callback=self.append_terminal_output,
            status_callback=self.update_status_bar_text,
            finished_callback=self.on_scan_finished,
            results_callback=self.store_scan_results,
            progress_callback=self.update_progress,
            progress_start_callback=self.start_progress
        )
    
    def run_api_scan(self):
        """Run API enumeration"""
        from app.tools import api_utils
        
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        
        scan_type_map = {
            "Basic Discovery": "basic",
            "Gobuster Enum": "gobuster",
            "HTTP Methods": "methods",
            "Auth Bypass": "auth",
            "Vulnerability Test": "vulns",
            "Full Scan": "full"
        }
        api_scan_type = getattr(self, 'api_scan_type', None)
        scan_type = scan_type_map[api_scan_type.currentText()] if api_scan_type else "basic"
        
        api_wordlist = getattr(self, 'api_wordlist', None)
        wordlist_path = api_wordlist.currentData() if api_wordlist else None
        
        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        self.terminal_output.clear()
        self.progress_widget.setVisible(False)
        
        # Clear previous scan results
        self.last_scan_results = {}
        self.export_button.setEnabled(False)
        
        self.current_worker = api_utils.run_api_enumeration(
            target=target,
            scan_type=scan_type,
            wordlist_path=wordlist_path,
            output_callback=self.append_terminal_output,
            status_callback=self.update_status_bar_text,
            finished_callback=self.on_scan_finished,
            results_callback=self.store_scan_results
        )

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
        self.back_shortcut.activated.connect(self.navigate_home)

    def append_terminal_output(self, text):
        self.terminal_output.insertHtml(text)
        scrollbar = self.terminal_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def update_status_bar_text(self, text):
        self.status_updated.emit(text)
    
    def start_progress(self, total_items, message="Scanning..."):
        """Start progress tracking"""
        if hasattr(self, 'progress_widget'):
            self.progress_widget.start_progress(total_items, message)

    def store_scan_results(self, results):
        if not hasattr(self, 'last_scan_results') or not self.last_scan_results:
            self.last_scan_results = {}
        
        # Store results based on scan type
        if self.current_submenu == "port_scan":
            # Handle port scan results
            self.last_scan_results.update(results)
            self.populate_port_table(results)
        else:
            # Handle DNS results - merge new results with existing results
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
            
            # Update structured results for tree view with all accumulated results
            self.structured_dns_results = self.last_scan_results
            
            # Update DNS table with all accumulated results
            self.populate_dns_table(self.last_scan_results)
        
        self.export_button.setEnabled(True)

    def start_progress(self, total_items):
        self.progress_widget.start_progress(total_items, "Scanning...")

    def update_progress_simple(self, completed_items, results_found):
        self.progress_widget.update_progress(completed_items, results_found)

    def on_scan_finished(self):
        self.progress_widget.finish_progress("Scan Complete")
        self.status_updated.emit("Scan completed successfully")
        self.is_scanning = False
        self.run_button.setText("Run")
        self.run_button.setStyleSheet("")
        self.current_worker = None
    
    def _on_dns_scan_finished(self):
        """Handle DNS scan completion - run SRV scan if SRV is selected"""
        # Check if SRV should be run
        srv_checkbox = getattr(self, 'record_type_checkboxes', {}).get('SRV')
        all_checkbox = getattr(self, 'all_checkbox', None)
        
        should_run_srv = (srv_checkbox and srv_checkbox.isChecked()) or (all_checkbox and all_checkbox.isChecked())
        
        if should_run_srv:
            self.append_terminal_output("<p style='color: #00BFFF;'>Starting SRV enumeration...</p><br>")
            
            target = self.target_input.text().strip()
            dns_server = getattr(self, 'dns_input', None)
            dns_server = dns_server.text().strip() or None if dns_server else None
            
            # Run SRV scan with srv_wordlist.txt
            srv_wordlist_path = os.path.join(self.main_window.project_root, "resources", "wordlists", "srv_wordlist.txt")
            
            self.current_worker = dns_utils.enumerate_hostnames(
                target=target,
                wordlist_path=srv_wordlist_path,
                record_types=['SRV'],
                use_bruteforce=False,
                dns_server=dns_server,
                output_callback=self.append_terminal_output,
                status_callback=self.update_status_bar_text,
                finished_callback=self.on_scan_finished,
                results_callback=self.store_scan_results,
                progress_callback=self.update_progress,
                progress_start_callback=self.start_progress
            )
        else:
            # No SRV scan needed, finish normally
            self.on_scan_finished()

    def show_error(self, message):
        self.terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {message}</p>")
        self.status_updated.emit(f"Error: {message}")

    def show_info(self, message):
        self.terminal_output.setHtml(f"<p style='color: #64C8FF;'>[INFO] {message}</p>")

    def export_results(self):
        export_format = self.export_combo.currentText()
        
        if export_format == "Create Session":
            self.create_session_with_current_scan()
            return
        
        if not self.last_scan_results:
            self.show_error("No scan results to export")
            return
        
        target = self.target_input.text().strip() or "unknown"
        
        if export_format == "Advanced Report":
            self.open_advanced_reporting()
            return
        
        try:
            # Delegate the actual file writing to the exporter module
            success, filepath, message = exporter.export_results(
                self.last_scan_results,
                target,
                export_format.lower()
            )
            
            if success:
                self.append_terminal_output(f"<p style='color: #00FF41;'>[EXPORT] Results exported to {filepath}</p><br>")
                
                # Add to Advanced Reporting history
                self.add_to_reporting_history(filepath, target, export_format)
            else:
                self.append_terminal_output(f"<p style='color: #FF4500;'>[EXPORT ERROR] {message}</p><br>")
                
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
        scan_types = {
            'dns_enum': 'dns_enum',
            'port_scan': 'port_scan', 
            'rpc_enum': 'rpc_enum',
            'smb_enum': 'smb_enum',
            'smtp_enum': 'smtp_enum',
            'snmp_enum': 'snmp_enum',
            'http_enum': 'http_enum',
            'api_enum': 'api_enum'
        }
        scan_type = scan_types.get(self.current_submenu, 'unknown')
        scan_data = {
            'target': self.target_input.text().strip(),
            'scan_type': scan_type,
            'results': self.last_scan_results,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': 'Unknown'
        }
        reporting_widget.load_scan_data(scan_data)
        
        layout.addWidget(reporting_widget)
        dialog.exec()
    
    def add_to_reporting_history(self, filepath, target, export_format):
        """Add exported scan to Advanced Reporting history"""
        try:
            from app.core.scan_database import scan_db
            import time
            
            # Save scan to database for history tracking
            scan_types = {
                'dns_enum': 'dns_enum',
                'port_scan': 'port_scan',
                'rpc_enum': 'rpc_enum',
                'smb_enum': 'smb_enum',
                'smtp_enum': 'smtp_enum',
                'snmp_enum': 'snmp_enum',
                'http_enum': 'http_enum',
                'api_enum': 'api_enum'
            }
            scan_type = scan_types.get(self.current_submenu, 'unknown')
            
            # Save to database
            scan_db.save_scan(
                target=target,
                scan_type=scan_type,
                results=self.last_scan_results,
                duration=0
            )
            
        except Exception as e:
            # Don't fail export if history fails
            print(f"Warning: Could not add to reporting history: {e}")
    
    def save_current_tool_state(self):
        """Save current tool's state (terminal, progress, results, scan status)"""
        if not self.current_submenu:
            return
            
        self.tool_states[self.current_submenu] = {
            'terminal_content': self.terminal_output.toHtml(),
            'is_scanning': self.is_scanning,
            'scan_results': getattr(self, 'last_scan_results', {}),
            'progress_visible': self.progress_widget.isVisible(),
            'progress_value': 0,  # Simplified for now
            'progress_text': '',  # Simplified for now
            'export_enabled': self.export_button.isEnabled(),
            'run_button_text': self.run_button.text(),
            'run_button_style': self.run_button.styleSheet(),
            'results_view_index': self.results_stack.currentIndex()
        }
    
    def restore_tool_state(self, tool_id):
        """Restore tool's state (terminal, progress, results, scan status)"""
        if tool_id in self.tool_states:
            state = self.tool_states[tool_id]
            
            # Restore terminal content
            self.terminal_output.setHtml(state.get('terminal_content', ''))
            
            # Restore scan state
            self.is_scanning = state.get('is_scanning', False)
            self.last_scan_results = state.get('scan_results', {})
            
            # Restore UI state
            self.progress_widget.setVisible(state.get('progress_visible', False))
            # Progress state restoration simplified for now
            self.export_button.setEnabled(state.get('export_enabled', False))
            self.run_button.setText(state.get('run_button_text', 'Run'))
            self.run_button.setStyleSheet(state.get('run_button_style', ''))
            
            # Restore results view
            self.results_stack.setCurrentIndex(state.get('results_view_index', 0))
            
            # Update DNS table if switching to DNS tool with results
            if tool_id == 'dns_enum' and state.get('scan_results'):
                self.populate_dns_table(state.get('scan_results'))
        else:
            # Initialize new tool state
            self.terminal_output.clear()
            self.is_scanning = False
            self.last_scan_results = {}
            self.progress_widget.setVisible(False)
            self.export_button.setEnabled(False)
            self.run_button.setText('Run')
            self.run_button.setStyleSheet('')
            
            # Reset progress bar animation
            if hasattr(self, 'progress_widget'):
                from PyQt6.QtWidgets import QProgressBar
                progress_bars = self.progress_widget.findChildren(QProgressBar)
                for pb in progress_bars:
                    pb.setValue(0)
                    pb.setRange(0, 100)
    
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
    
    def create_session_with_current_scan(self):
        """Create a new session with current scan results"""
        from app.core.session_manager import session_manager
        from app.core.scan_database import scan_db
        from app.core.error_context import handle_errors
        
        if not self.last_scan_results:
            self.show_error("No scan results to create session with")
            return
        
        try:
            with handle_errors("Session Creation", show_dialog=False):
                target = self.target_input.text().strip() or "unknown"
                
                # Create new session
                scan_type_names = {
                    "dns_enum": "DNS Scan",
                    "port_scan": "Port Scan", 
                    "rpc_enum": "RPC Scan",
                    "smb_enum": "SMB Scan",
                    "smtp_enum": "SMTP Scan",
                    "snmp_enum": "SNMP Scan",
                    "http_enum": "HTTP Scan",
                    "api_enum": "API Scan"
                }
                scan_type_name = scan_type_names.get(self.current_submenu, "Scan")
                session = session_manager.create_session(
                    name=f"{scan_type_name} - {target}",
                    description=f"{scan_type_name.lower()} results for {target}",
                    targets=[target]
                )
                
                # Save scan to database
                scan_types = {
                    'dns_enum': 'dns_enum',
                    'port_scan': 'port_scan',
                    'rpc_enum': 'rpc_enum'
                }
                scan_type = scan_types.get(self.current_submenu, 'unknown')
                scan_id = scan_db.save_scan(
                    target=target,
                    scan_type=scan_type,
                    results=self.last_scan_results,
                    duration=0
                )
                
                if scan_id:
                    # Associate scan with session
                    session_manager.add_scan_to_session(session['id'], scan_id)
                    self.append_terminal_output(
                        f"<p style='color: #00FF41;'>[SESSION] Created new session '{session['name']}' with scan results</p><br>"
                    )
                else:
                    self.append_terminal_output(
                        f"<p style='color: #FFAA00;'>[SESSION] Created session but failed to save scan</p><br>"
                    )
        except Exception as e:
            self.append_terminal_output(
                f"<p style='color: #FF4500;'>[SESSION ERROR] Failed to create session: {str(e)}</p><br>"
            )
    
    def on_session_changed(self, session_id):
        """Handle session change event"""
        from app.core.session_manager import session_manager
        from app.core.scan_database import scan_db
        
        # If we have scan results, associate them with the current session
        if self.last_scan_results and session_id:
            try:
                # Save current scan to database
                target = self.target_input.text().strip() or "unknown"
                scan_types = {
                    'dns_enum': 'dns_enum',
                    'port_scan': 'port_scan',
                    'rpc_enum': 'rpc_enum'
                }
                scan_type = scan_types.get(self.current_submenu, 'unknown')
                scan_id = scan_db.save_scan(
                    target=target,
                    scan_type=scan_type,
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
    
    def toggle_results_view(self):
        """Toggle between text and tree view for DNS results"""
        if self.current_view_is_text:
            # Switch to tree view
            self.results_stack.setCurrentIndex(1)
            self.view_toggle_btn.setText("Text View")
            self.current_view_is_text = False
        else:
            # Switch to text view
            self.results_stack.setCurrentIndex(0)
            self.view_toggle_btn.setText("Graph View")
            self.current_view_is_text = True
    
    def populate_dns_table(self, structured_results):
        """Populate DNS table with structured results"""
        from PyQt6.QtWidgets import QTableWidgetItem
        from PyQt6.QtCore import Qt
        
        # Clear existing data
        self.dns_table.setRowCount(0)
        
        if not structured_results:
            return
        
        # Collect all records
        all_records = []
        for domain, record_types in structured_results.items():
            for record_type, values in record_types.items():
                for value in values:
                    all_records.append({
                        'domain': domain,
                        'type': record_type,
                        'value': value
                    })
        
        # Populate table
        self.dns_table.setRowCount(len(all_records))
        for row, record in enumerate(all_records):
            # Domain/Record column
            domain_item = QTableWidgetItem(record['domain'])
            domain_item.setFlags(domain_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.dns_table.setItem(row, 0, domain_item)
            
            # Type column
            type_item = QTableWidgetItem(record['type'])
            type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.dns_table.setItem(row, 1, type_item)
            
            # Value column
            value_item = QTableWidgetItem(record['value'])
            value_item.setFlags(value_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.dns_table.setItem(row, 2, value_item)
        
        # Resize columns to content
        self.dns_table.resizeColumnsToContents()
    def set_results_view(self, is_text_view):
        """Set results view to text or table"""
        self.current_view_is_text = is_text_view
        
        # Update button states
        self.text_view_btn.setChecked(is_text_view)
        self.graph_view_btn.setChecked(not is_text_view)
        
        # Switch view
        if is_text_view:
            self.results_stack.setCurrentIndex(0)  # Text view
        else:
            # Show appropriate table based on scan type
            if self.current_submenu == "port_scan":
                # Get current scan type from controls
                control_panel = self.tool_controls.get('port', {})
                controls = getattr(control_panel, 'controls', {})
                scan_type = controls.get('scan_type_combo', {}).currentText() if hasattr(controls.get('scan_type_combo', {}), 'currentText') else ""
                
                if scan_type == "Targeted Scan":
                    self.results_stack.setCurrentIndex(2)  # Port table for targeted scans
                else:
                    # Update IP results table for Ping/Nmap sweeps
                    self.update_results_table()
                    self.results_stack.setCurrentIndex(3)  # IP results table
            else:
                # DNS and other scans use table view
                self.results_stack.setCurrentIndex(1)  # DNS table view
    
    def parse_nmap_output(self, nmap_output, target):
        """Parse nmap output to extract port information"""
        import re
        
        open_ports = []
        lines = nmap_output.split('\n')
        
        for line in lines:
            # Match port lines like "80/tcp open http"
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s*(.*)', line.strip())
            if port_match:
                port = port_match.group(1)
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4).strip() if port_match.group(4) else 'unknown'
                
                if state == 'open':
                    open_ports.append({
                        'port': int(port),
                        'protocol': protocol,
                        'service': service,
                        'state': state,
                        'banner': ''
                    })
        
        if open_ports:
            return {target: {'open_ports': open_ports}}
        return None
    
    def populate_port_table(self, port_results):
        """Populate port table with scan results"""
        from PyQt6.QtWidgets import QTableWidgetItem
        from PyQt6.QtCore import Qt
        
        # Clear existing data
        self.port_table.setRowCount(0)
        
        if not port_results:
            return
        
        # Extract port data from results
        ports_data = []
        for target, data in port_results.items():
            if isinstance(data, dict) and 'open_ports' in data:
                for port_info in data['open_ports']:
                    if isinstance(port_info, dict):
                        ports_data.append({
                            'port': str(port_info.get('port', 'Unknown')),
                            'service': port_info.get('service', 'Unknown'),
                            'state': port_info.get('state', 'open')
                        })
                    else:
                        # Handle simple port number format
                        ports_data.append({
                            'port': str(port_info),
                            'service': 'Unknown',
                            'state': 'open'
                        })
        
        # Populate table
        self.port_table.setRowCount(len(ports_data))
        for row, port_data in enumerate(ports_data):
            # Port column
            port_item = QTableWidgetItem(port_data['port'])
            port_item.setFlags(port_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.port_table.setItem(row, 0, port_item)
            
            # Service column
            service_item = QTableWidgetItem(port_data['service'])
            service_item.setFlags(service_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.port_table.setItem(row, 1, service_item)
            
            # State column
            state_item = QTableWidgetItem(port_data['state'])
            state_item.setFlags(state_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.port_table.setItem(row, 2, state_item)
        
        # Resize columns to content
        self.port_table.resizeColumnsToContents()
    
    def update_results_table(self):
        """Update results table with found IP addresses"""
        from PyQt6.QtWidgets import QTableWidgetItem
        from PyQt6.QtCore import Qt
        import re
        
        # Clear existing data
        self.results_table.setRowCount(0)
        
        # Extract IP addresses from terminal output
        terminal_text = self.terminal_output.toPlainText()
        ip_addresses = []
        
        # Look for "Host X.X.X.X is up" patterns
        up_pattern = r'Host (\d+\.\d+\.\d+\.\d+) is up \((\w+)\)'
        matches = re.findall(up_pattern, terminal_text)
        
        for ip, method in matches:
            ip_addresses.append({
                'ip': ip,
                'status': 'Up',
                'method': method.capitalize()
            })
        
        # Populate table
        self.results_table.setRowCount(len(ip_addresses))
        for row, ip_data in enumerate(ip_addresses):
            # IP Address column
            ip_item = QTableWidgetItem(ip_data['ip'])
            ip_item.setFlags(ip_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.results_table.setItem(row, 0, ip_item)
            
            # Status column
            status_item = QTableWidgetItem(ip_data['status'])
            status_item.setFlags(status_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.results_table.setItem(row, 1, status_item)
            
            # Method column
            method_item = QTableWidgetItem(ip_data['method'])
            method_item.setFlags(method_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.results_table.setItem(row, 2, method_item)
        
        # Resize columns to content
        self.results_table.resizeColumnsToContents()