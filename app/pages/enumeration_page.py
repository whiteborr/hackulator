# --- FULL UPDATED enumeration_page.py ---
import os
import logging
import time
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, 
                             QComboBox, QCheckBox, QVBoxLayout, QHBoxLayout, 
                             QFrame, QSizePolicy, QScrollArea, QStatusBar)
from PyQt6.QtCore import pyqtSignal, QSize, Qt, QThreadPool
from PyQt6.QtGui import QPixmap, QIcon, QShortcut, QKeySequence

from app.tools import dns_utils
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

    def _create_record_checkboxes(self, parent_layout):
        """Helper to create record type checkboxes"""
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
        parent_layout.addWidget(self.all_checkbox)
        parent_layout.addSpacing(10)

        self.record_type_checkboxes = {}
        for rtype in ['A', 'CNAME', 'MX', 'TXT', 'NS']:
            cb = QCheckBox(rtype)
            cb.setStyleSheet(checkbox_style)
            cb.stateChanged.connect(self.update_all_checkbox)
            self.record_type_checkboxes[rtype] = cb
            parent_layout.addWidget(cb)
            parent_layout.addSpacing(10)

        self.ptr_checkbox = QCheckBox("PTR")
        self.ptr_checkbox.setStyleSheet(checkbox_style)
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
        
        # Create stacked widget for different tool controls
        self.controls_stack = QStackedWidget()
        
        # DNS controls
        self.dns_controls = self.create_dns_controls()
        self.controls_stack.addWidget(self.dns_controls)
        
        # Port scan controls  
        self.port_controls = self.create_port_controls()
        self.controls_stack.addWidget(self.port_controls)
        
        # RPC controls
        self.rpc_controls = self.create_rpc_controls()
        self.controls_stack.addWidget(self.rpc_controls)
        
        # SMB controls
        self.smb_controls = self.create_smb_controls()
        self.controls_stack.addWidget(self.smb_controls)
        
        # SMTP controls
        self.smtp_controls = self.create_smtp_controls()
        self.controls_stack.addWidget(self.smtp_controls)
        
        # SNMP controls
        self.snmp_controls = self.create_snmp_controls()
        self.controls_stack.addWidget(self.snmp_controls)
        
        # HTTP controls
        self.http_controls = self.create_http_controls()
        self.controls_stack.addWidget(self.http_controls)
        
        # API controls
        self.api_controls = self.create_api_controls()
        self.controls_stack.addWidget(self.api_controls)
        
        # LDAP controls
        self.ldap_controls = self.create_ldap_controls()
        self.controls_stack.addWidget(self.ldap_controls)
        
        # Database controls
        self.db_controls = self.create_db_controls()
        self.controls_stack.addWidget(self.db_controls)
        
        # IKE controls
        self.ike_controls = self.create_ike_controls()
        self.controls_stack.addWidget(self.ike_controls)
        
        # AV/Firewall controls
        self.av_firewall_controls = self.create_av_firewall_controls()
        self.controls_stack.addWidget(self.av_firewall_controls)
        
        controls_layout.addWidget(self.controls_stack)
        
        # === Actions Row ===
        action_row = QHBoxLayout()
        action_row.addStretch()
        self.run_button = QPushButton("Run")
        self.run_button.setFixedWidth(80)
        self.run_button.clicked.connect(self.toggle_scan)
        action_row.addWidget(self.run_button)

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

        # Record Type Checkboxes
        record_row = QHBoxLayout()
        types_label = QLabel("Types:")
        types_label.setFixedWidth(110)
        types_label.setFixedHeight(30)
        record_row.addWidget(types_label)
        
        self._create_record_checkboxes(record_row)
        record_row.addStretch()
        layout.addLayout(record_row)

        # DNS Server
        dns_row = QHBoxLayout()
        dns_label = QLabel("DNS:")
        dns_label.setFixedWidth(110)
        dns_row.addWidget(dns_label)
        self.dns_input = QLineEdit()
        self.dns_input.setPlaceholderText("DNS Server (optional)")
        self.dns_input.setFixedWidth(400)
        dns_row.addWidget(self.dns_input)
        dns_row.addStretch()
        layout.addLayout(dns_row)

        # Method & Wordlist/Bruteforce
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
        
        self.toggle_method_options("Wordlist")
        return dns_widget
    
    def create_port_controls(self):
        """Create port scanning specific controls"""
        port_widget = QWidget()
        layout = QVBoxLayout(port_widget)
        
        # Scan Type
        scan_type_row = QHBoxLayout()
        scan_type_label = QLabel("Scan Type:")
        scan_type_label.setFixedWidth(110)
        scan_type_row.addWidget(scan_type_label)
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["TCP Connect", "Network Sweep"])
        self.scan_type_combo.setFixedWidth(150)
        scan_type_row.addWidget(self.scan_type_combo)
        scan_type_row.addStretch()
        layout.addLayout(scan_type_row)
        
        # Port Range
        port_row = QHBoxLayout()
        port_label = QLabel("Ports:")
        port_label.setFixedWidth(110)
        port_row.addWidget(port_label)
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("80,443,1-1000 or leave empty for common ports")
        port_row.addWidget(self.port_input)
        layout.addLayout(port_row)
        
        # Quick port selections
        quick_ports_row = QHBoxLayout()
        quick_ports_label = QLabel("Quick:")
        quick_ports_label.setFixedWidth(110)
        quick_ports_row.addWidget(quick_ports_label)
        
        self.common_ports_btn = QPushButton("Common")
        self.common_ports_btn.clicked.connect(lambda: self.port_input.setText("21,22,23,25,53,80,110,135,139,143,443,993,995,3389"))
        quick_ports_row.addWidget(self.common_ports_btn)
        
        self.top100_btn = QPushButton("Top 100")
        self.top100_btn.clicked.connect(lambda: self.port_input.setText("1-100"))
        quick_ports_row.addWidget(self.top100_btn)
        
        self.top1000_btn = QPushButton("Top 1000")
        self.top1000_btn.clicked.connect(lambda: self.port_input.setText("1-1000"))
        quick_ports_row.addWidget(self.top1000_btn)
        
        quick_ports_row.addStretch()
        layout.addLayout(quick_ports_row)
        
        return port_widget
    
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
        self.is_scanning = False
        self.current_worker = None

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
        
        # Switch controls based on tool
        if tool_id == "dns_enum":
            self.controls_stack.setCurrentIndex(0)  # DNS controls
        elif tool_id == "port_scan":
            self.controls_stack.setCurrentIndex(1)  # Port controls
        elif tool_id == "rpc_enum":
            self.controls_stack.setCurrentIndex(2)  # RPC controls
        elif tool_id == "smb_enum":
            self.controls_stack.setCurrentIndex(3)  # SMB controls
        elif tool_id == "smtp_enum":
            self.controls_stack.setCurrentIndex(4)  # SMTP controls
        elif tool_id == "snmp_enum":
            self.controls_stack.setCurrentIndex(5)  # SNMP controls
        elif tool_id == "http_enum":
            self.controls_stack.setCurrentIndex(6)  # HTTP controls
        elif tool_id == "api_enum":
            self.controls_stack.setCurrentIndex(7)  # API controls
        elif tool_id == "ldap_enum":
            self.controls_stack.setCurrentIndex(8)  # LDAP controls
        elif tool_id == "db_enum":
            self.controls_stack.setCurrentIndex(9)  # Database controls
        elif tool_id == "ike_enum":
            self.controls_stack.setCurrentIndex(10)  # IKE controls
        elif tool_id == "av_detect":
            self.controls_stack.setCurrentIndex(11)  # AV/Firewall controls
        else:
            self.controls_stack.setCurrentIndex(0)  # Default to DNS
    
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
        pass
    
    def update_status_bar(self, title, description):
        """Update status bar with tool info"""
        self.status_updated.emit(f"{title}: {description}")
    
    def clear_status_bar(self):
        """Clear status bar"""
        self.status_updated.emit("")
    
    def run_ptr_scan(self):
        """Placeholder for PTR scan"""
        self.show_error("PTR scanning not fully implemented")
    
    def run_zone_transfer(self):
        """Placeholder for zone transfer"""
        self.show_error("Zone transfer not implemented yet")
    
    def run_basic_records(self):
        """Placeholder for basic records"""
        self.show_error("Basic records scan not implemented yet")
    
    def update_progress(self, value):
        """Update progress bar"""
        if hasattr(self, 'progress_widget'):
            self.progress_widget.update_progress(value)
    
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
        
        # Handle direct queries for MX, NS, TXT first
        if direct_query_types:
            dns_utils.query_direct_records(
                target=target,
                record_types=direct_query_types,
                dns_server=dns_server,
                output_callback=self.append_terminal_output,
                results_callback=self.store_scan_results
            )
        
        # Handle wordlist/bruteforce for A and CNAME
        if selected_types:
            self.current_worker = dns_utils.enumerate_hostnames(
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
        """Run port scanning based on selected options"""
        from app.tools import port_utils
        
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        
        scan_type = self.scan_type_combo.currentText()
        
        self.is_scanning = True
        self.run_button.setText("Cancel")
        self.run_button.setStyleSheet("background-color: red; color: white;")
        self.terminal_output.clear()
        self.progress_widget.setVisible(True)
        
        # Clear previous scan results
        self.last_scan_results = {}
        self.export_button.setEnabled(False)
        
        if scan_type == "Network Sweep":
            self.current_worker = port_utils.run_network_sweep(
                network_range=target,
                output_callback=self.append_terminal_output,
                status_callback=self.update_status_bar_text,
                finished_callback=self.on_scan_finished,
                results_callback=self.store_scan_results,
                progress_callback=self.update_progress,
                progress_start_callback=self.start_progress
            )
        else:  # TCP Connect
            try:
                ports = port_utils.parse_port_range(self.port_input.text().strip())
                self.current_worker = port_utils.run_port_scan(
                    target=target,
                    ports=ports,
                    output_callback=self.append_terminal_output,
                    status_callback=self.update_status_bar_text,
                    finished_callback=self.on_scan_finished,
                    results_callback=self.store_scan_results,
                    progress_callback=self.update_progress,
                    progress_start_callback=self.start_progress
                )
            except ValueError as e:
                self.show_error(f"Invalid port range: {str(e)}")
                self.is_scanning = False
                self.run_button.setText("Run")
                self.run_button.setStyleSheet("")
                return
    
    def run_rpc_scan(self):
        """Run RPC enumeration"""
        from app.tools import rpc_utils
        
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        
        username = self.rpc_username.text().strip() if self.auth_combo.currentText() == "Credentials" else ""
        password = self.rpc_password.text().strip() if self.auth_combo.currentText() == "Credentials" else ""
        
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
        scan_type = scan_type_map[self.smb_scan_type.currentText()]
        
        username = self.smb_username.text().strip() if self.smb_auth_combo.currentText() == "Credentials" else ""
        password = self.smb_password.text().strip() if self.smb_auth_combo.currentText() == "Credentials" else ""
        
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
        
        try:
            port = int(self.smtp_port.text().strip() or "25")
        except ValueError:
            self.show_error("Invalid port number")
            return
        
        domain = self.smtp_domain.text().strip() or target
        helo_name = self.smtp_helo.text().strip() or "test.local"
        wordlist_path = self.smtp_wordlist.currentData()
        
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
        
        version = self.snmp_version.currentText()
        
        scan_type_map = {
            "Basic Info": "basic",
            "Users": "users",
            "Processes": "processes",
            "Software": "software",
            "Network": "network",
            "Full Enumeration": "full"
        }
        scan_type = scan_type_map[self.snmp_scan_type.currentText()]
        
        communities_text = self.snmp_communities.text().strip()
        communities = [c.strip() for c in communities_text.split(',') if c.strip()] if communities_text else snmp_utils.get_default_communities()
        
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
        scan_type = scan_type_map[self.http_scan_type.currentText()]
        
        extensions_text = self.http_extensions.text().strip()
        extensions = [ext.strip() for ext in extensions_text.split(',') if ext.strip()] if extensions_text else None
        
        wordlist_path = self.http_wordlist.currentData()
        
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
        scan_type = scan_type_map[self.api_scan_type.currentText()]
        
        wordlist_path = self.api_wordlist.currentData()
        
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
            success, filename, message = exporter.export_results(
                self.last_scan_results,
                target,
                export_format.lower()
            )
            
            if success:
                self.append_terminal_output(f"<p style='color: #00FF41;'>[EXPORT] Results exported to {filename}</p><br>")
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
