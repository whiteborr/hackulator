# app/pages/enumeration_page_refactored.py
import logging
import os
import time
import json
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, 
                            QComboBox, QCheckBox, QVBoxLayout, QHBoxLayout, 
                            QGridLayout, QFrame, QSizePolicy, QScrollArea, QStatusBar)
from PyQt6.QtCore import pyqtSignal, QSize, Qt, QThreadPool
from PyQt6.QtGui import QPixmap, QIcon, QFont, QTextCursor, QShortcut, QKeySequence

from app.core import custom_scripts
from app.core.validators import InputValidator, ValidationError
from app.core.exporter import exporter
from app.core.base_worker import CommandWorker
from app.core.cache_manager import cache_manager
from app.core.memory_manager import memory_manager
from app.core.pdf_generator import pdf_generator
from app.core.executive_summary import executive_summary
from app.core.vulnerability_correlator import vulnerability_correlator
from app.core.result_comparator import result_comparator
from app.core.proxy_manager import proxy_manager
from app.core.rate_limiter import rate_limiter
from app.core.template_manager import template_manager
from app.core.scheduler import scan_scheduler
from app.core.multi_target_manager import multi_target_manager
from app.core.theme_manager import theme_manager
from app.core.shortcut_manager import ShortcutManager
from app.core.scan_database import scan_db
from app.core.context_menu_manager import ContextMenuManager
from app.widgets.progress_widget import ProgressWidget
from app.widgets.cache_status_widget import CacheStatusWidget
from app.widgets.memory_widget import MemoryWidget
from app.widgets.scan_control_widget import ScanControlWidget
from app.widgets.pdf_preview_widget import PDFPreviewWidget
from app.widgets.summary_widget import SummaryWidget
from app.widgets.correlation_widget import CorrelationWidget
from app.widgets.comparison_widget import ComparisonWidget
from app.widgets.proxy_widget import ProxyWidget
from app.widgets.rate_limit_widget import RateLimitWidget
from app.widgets.template_widget import TemplateWidget
from app.widgets.scheduler_widget import SchedulerWidget
from app.widgets.multi_target_widget import MultiTargetWidget
from app.widgets.theme_widget import ThemeWidget
from app.widgets.advanced_theme_widget import AdvancedThemeWidget
from app.widgets.help_widget import HelpWidget
from app.widgets.drag_drop_combo import DragDropComboBox
from app.widgets.advanced_dir_widget import AdvancedDirectoryWidget
from app.widgets.cert_transparency_widget import CertTransparencyWidget
from app.widgets.osint_widget import OSINTWidget
from app.widgets.vuln_scanner_widget import VulnScannerWidget
from app.widgets.scan_history_widget import ScanHistoryWidget
from app.widgets.session_widget import SessionWidget
from app.widgets.wordlist_widget import WordlistWidget
from app.widgets.filter_widget import FilterWidget
from app.widgets.notification_widget import NotificationWidget
from app.widgets.plugin_widget import PluginWidget
from app.widgets.api_integration_widget import APIIntegrationWidget
from app.widgets.threat_intel_widget import ThreatIntelWidget
from app.widgets.ml_pattern_widget import MLPatternWidget
from app.widgets.distributed_scan_widget import DistributedScanWidget

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
        self.is_submenu_active = False
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
        self.content_area.addWidget(self.tool_panel, 0)  # Fixed width

        # Create main work area (right)
        self.work_area = self.create_work_area()
        self.content_area.addWidget(self.work_area, 1)  # Expandable

        # Create status bar
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background-color: rgba(20, 30, 40, 150);
                color: #64C8FF;
                border-top: 1px solid rgba(100, 200, 255, 100);
                font-size: 12pt;
            }
        """)
        self.main_layout.addWidget(self.status_bar)

        # Initialize data and setup
        self.setup_tool_data()
        self.setup_shortcuts()
        self.apply_theme()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        
        # Start memory monitoring
        memory_manager.start_monitoring(self.on_memory_event)
        
        # Initialize context menu manager
        self.context_menu_manager = ContextMenuManager(self)
        self.context_menu_manager.copy_text.connect(self.copy_to_clipboard)
        self.context_menu_manager.clear_output.connect(self.clear_terminal)
        self.context_menu_manager.export_results.connect(self.export_results)
        self.context_menu_manager.save_to_file.connect(self.save_output_to_file)

    def create_header(self):
        """Create the header with title and back button"""
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

        # Back button
        self.back_button = QPushButton("← Back to Home")
        self.back_button.setProperty("class", "backButton")
        self.back_button.clicked.connect(lambda: self.navigate_signal.emit("home"))
        self.back_button.setFixedWidth(150)

        # Title
        self.title_label = QLabel("Enumeration Tools")
        self.title_label.setObjectName("TitleLabel")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        header_layout.addWidget(self.back_button)
        header_layout.addWidget(self.title_label, 1)
        header_layout.addStretch()

        return header_frame

    def create_tool_panel(self):
        """Create the left tool selection panel"""
        tool_frame = QFrame()
        tool_frame.setFixedWidth(300)
        tool_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)

        # Create scroll area for tools
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QScrollBar:vertical {
                background-color: rgba(50, 50, 50, 100);
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: rgba(100, 200, 255, 150);
                border-radius: 6px;
                min-height: 20px;
            }
        """)

        # Tool list widget
        tool_widget = QWidget()
        self.tool_layout = QVBoxLayout(tool_widget)
        self.tool_layout.setContentsMargins(10, 10, 10, 10)
        self.tool_layout.setSpacing(8)

        scroll_area.setWidget(tool_widget)

        # Add scroll area to frame
        frame_layout = QVBoxLayout(tool_frame)
        frame_layout.setContentsMargins(5, 5, 5, 5)
        frame_layout.addWidget(scroll_area)

        return tool_frame

    def create_work_area(self):
        """Create the main work area with controls and output"""
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
        work_layout.addWidget(self.output_section, 1)  # Expandable

        # Progress section
        self.progress_widget = ProgressWidget(self)
        self.progress_widget.setVisible(False)
        work_layout.addWidget(self.progress_widget)
        
        # Cache status section
        self.cache_widget = CacheStatusWidget(self)
        work_layout.addWidget(self.cache_widget)
        
        # Memory usage section
        self.memory_widget = MemoryWidget(self)
        work_layout.addWidget(self.memory_widget)
        
        # Scan control section
        self.scan_control = ScanControlWidget(self)
        work_layout.addWidget(self.scan_control)
        
        # PDF preview section (initially hidden)
        self.pdf_preview = PDFPreviewWidget(self)
        self.pdf_preview.setVisible(False)
        work_layout.addWidget(self.pdf_preview)
        
        # Summary section (initially hidden)
        self.summary_widget = SummaryWidget(self)
        self.summary_widget.setVisible(False)
        work_layout.addWidget(self.summary_widget)
        
        # Correlation section (initially hidden)
        self.correlation_widget = CorrelationWidget(self)
        self.correlation_widget.setVisible(False)
        work_layout.addWidget(self.correlation_widget)
        
        # Comparison section (initially hidden)
        self.comparison_widget = ComparisonWidget(self)
        self.comparison_widget.setVisible(False)
        work_layout.addWidget(self.comparison_widget)
        
        # Proxy section (initially hidden)
        self.proxy_widget = ProxyWidget(self)
        self.proxy_widget.setVisible(False)
        work_layout.addWidget(self.proxy_widget)
        
        # Rate limiting section (initially hidden)
        self.rate_limit_widget = RateLimitWidget(self)
        self.rate_limit_widget.setVisible(False)
        work_layout.addWidget(self.rate_limit_widget)
        
        # Template section (initially hidden)
        self.template_widget = TemplateWidget(self)
        self.template_widget.setVisible(False)
        self.template_widget.template_loaded.connect(self.apply_template)
        work_layout.addWidget(self.template_widget)
        
        # Scheduler section (initially hidden)
        self.scheduler_widget = SchedulerWidget(self)
        self.scheduler_widget.setVisible(False)
        self.scheduler_widget.scan_scheduled.connect(self.on_scan_scheduled)
        work_layout.addWidget(self.scheduler_widget)
        
        # Multi-target section (initially hidden)
        self.multi_target_widget = MultiTargetWidget(self)
        self.multi_target_widget.setVisible(False)
        self.multi_target_widget.scan_completed.connect(self.on_multi_scan_completed)
        work_layout.addWidget(self.multi_target_widget)
        
        # Theme section (initially hidden)
        self.theme_widget = ThemeWidget(self)
        self.theme_widget.setVisible(False)
        work_layout.addWidget(self.theme_widget)
        
        # Advanced theme section (initially hidden)
        self.advanced_theme_widget = AdvancedThemeWidget(self)
        self.advanced_theme_widget.setVisible(False)
        self.advanced_theme_widget.theme_selected.connect(self.apply_advanced_theme)
        work_layout.addWidget(self.advanced_theme_widget)
        
        # Help section (initially hidden)
        self.help_widget = HelpWidget(self)
        self.help_widget.setVisible(False)
        work_layout.addWidget(self.help_widget)
        
        # Advanced directory enumeration section (initially hidden)
        self.advanced_dir_widget = AdvancedDirectoryWidget(self)
        self.advanced_dir_widget.setVisible(False)
        self.advanced_dir_widget.scan_completed.connect(self.on_advanced_dir_completed)
        work_layout.addWidget(self.advanced_dir_widget)
        
        # Certificate transparency section (initially hidden)
        self.cert_transparency_widget = CertTransparencyWidget(self)
        self.cert_transparency_widget.setVisible(False)
        self.cert_transparency_widget.search_completed.connect(self.on_cert_transparency_completed)
        work_layout.addWidget(self.cert_transparency_widget)
        
        # OSINT section (initially hidden)
        self.osint_widget = OSINTWidget(self)
        self.osint_widget.setVisible(False)
        self.osint_widget.collection_completed.connect(self.on_osint_completed)
        work_layout.addWidget(self.osint_widget)
        
        # Vulnerability scanner section (initially hidden)
        self.vuln_scanner_widget = VulnScannerWidget(self)
        self.vuln_scanner_widget.setVisible(False)
        self.vuln_scanner_widget.scan_completed.connect(self.on_vuln_scan_completed)
        work_layout.addWidget(self.vuln_scanner_widget)
        
        # Scan history section (initially hidden)
        self.scan_history_widget = ScanHistoryWidget(self)
        self.scan_history_widget.setVisible(False)
        self.scan_history_widget.scan_loaded.connect(self.on_scan_loaded)
        work_layout.addWidget(self.scan_history_widget)
        
        # Session management section (initially hidden)
        self.session_widget = SessionWidget(self)
        self.session_widget.setVisible(False)
        self.session_widget.session_changed.connect(self.on_session_changed)
        work_layout.addWidget(self.session_widget)
        
        # Wordlist management section (initially hidden)
        self.wordlist_widget = WordlistWidget(self)
        self.wordlist_widget.setVisible(False)
        self.wordlist_widget.wordlist_selected.connect(self.on_wordlist_selected)
        work_layout.addWidget(self.wordlist_widget)
        
        # Result filtering section (initially hidden)
        self.filter_widget = FilterWidget(self)
        self.filter_widget.setVisible(False)
        self.filter_widget.results_filtered.connect(self.on_results_filtered)
        work_layout.addWidget(self.filter_widget)
        
        # Notification management section (initially hidden)
        self.notification_widget = NotificationWidget(self)
        self.notification_widget.setVisible(False)
        work_layout.addWidget(self.notification_widget)
        
        # Plugin management section (initially hidden)
        self.plugin_widget = PluginWidget(self)
        self.plugin_widget.setVisible(False)
        self.plugin_widget.plugin_executed.connect(self.on_plugin_executed)
        work_layout.addWidget(self.plugin_widget)
        
        # API integration section (initially hidden)
        self.api_integration_widget = APIIntegrationWidget(self)
        self.api_integration_widget.setVisible(False)
        self.api_integration_widget.api_executed.connect(self.on_api_executed)
        work_layout.addWidget(self.api_integration_widget)
        
        # Threat intelligence section (initially hidden)
        self.threat_intel_widget = ThreatIntelWidget(self)
        self.threat_intel_widget.setVisible(False)
        self.threat_intel_widget.threat_checked.connect(self.on_threat_checked)
        work_layout.addWidget(self.threat_intel_widget)
        
        # ML pattern detection section (initially hidden)
        self.ml_pattern_widget = MLPatternWidget(self)
        self.ml_pattern_widget.setVisible(False)
        self.ml_pattern_widget.pattern_analyzed.connect(self.on_pattern_analyzed)
        work_layout.addWidget(self.ml_pattern_widget)
        
        # Distributed scanning section (initially hidden)
        self.distributed_scan_widget = DistributedScanWidget(self)
        self.distributed_scan_widget.setVisible(False)
        self.distributed_scan_widget.scan_completed.connect(self.on_distributed_scan_completed)
        work_layout.addWidget(self.distributed_scan_widget)

        return work_frame

    def create_controls_section(self):
        """Create the controls section with input fields and buttons"""
        controls_frame = QFrame()
        controls_frame.setFixedHeight(120)
        controls_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(20, 30, 40, 100);
                border-radius: 8px;
                border: 1px solid rgba(100, 200, 255, 30);
            }
        """)

        controls_layout = QVBoxLayout(controls_frame)
        controls_layout.setContentsMargins(10, 10, 10, 10)
        controls_layout.setSpacing(8)

        # First row: Target input and wordlist
        first_row = QHBoxLayout()
        
        # Target input
        target_label = QLabel("Target:")
        target_label.setStyleSheet("color: #64C8FF; font-weight: bold;")
        target_label.setFixedWidth(60)
        
        self.target_input = QLineEdit()
        self.target_input.setObjectName("TargetInput")
        self.target_input.setPlaceholderText("Enter target (IP, domain, or range)...")
        self.target_input.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.target_input.customContextMenuRequested.connect(self.show_input_context_menu)
        
        # Wordlist combo
        wordlist_label = QLabel("Wordlist:")
        wordlist_label.setStyleSheet("color: #64C8FF; font-weight: bold;")
        wordlist_label.setFixedWidth(70)
        
        self.wordlist_combo = DragDropComboBox()
        self.wordlist_combo.setProperty("class", "wordlistCombo")
        self.wordlist_combo.setFixedWidth(200)
        self.wordlist_combo.file_dropped.connect(self.on_wordlist_dropped)
        self.populate_wordlists()

        first_row.addWidget(target_label)
        first_row.addWidget(self.target_input, 1)
        first_row.addWidget(wordlist_label)
        first_row.addWidget(self.wordlist_combo)

        # Second row: Record types and export controls
        second_row = QHBoxLayout()
        
        # Record type checkboxes
        record_label = QLabel("Types:")
        record_label.setStyleSheet("color: #64C8FF; font-weight: bold;")
        record_label.setFixedWidth(60)
        
        self.record_type_checkboxes = {}
        for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
            checkbox = QCheckBox(record_type)
            checkbox.setStyleSheet("color: #DCDCDC; font-size: 11pt;")
            if record_type == 'A':
                checkbox.setChecked(True)
            self.record_type_checkboxes[record_type] = checkbox
            second_row.addWidget(checkbox)

        second_row.addStretch()

        # Export controls
        self.export_combo = QComboBox()
        self.export_combo.setProperty("class", "exportCombo")
        self.export_combo.addItems(["JSON", "CSV", "XML", "PDF", "Summary", "Correlate", "Compare", "Proxy", "Rate Limit", "Templates", "Schedule", "Multi-Target", "Theme", "Advanced Themes", "Help", "Advanced Dir", "Cert Transparency", "OSINT", "Vuln Scan", "History", "Sessions", "Wordlists", "Filter", "Notifications", "Plugins", "API Integration", "Threat Intel", "ML Patterns", "Distributed Scan"])
        self.export_combo.setFixedWidth(110)

        self.export_button = QPushButton("Export")
        self.export_button.setProperty("class", "exportButton")
        self.export_button.clicked.connect(self.handle_export_action)
        self.export_button.setEnabled(False)
        self.export_button.setFixedWidth(80)

        second_row.addWidget(self.export_combo)
        second_row.addWidget(self.export_button)

        controls_layout.addLayout(first_row)
        controls_layout.addLayout(second_row)

        return controls_frame

    def create_output_section(self):
        """Create the output section with terminal and tool buttons"""
        output_frame = QFrame()
        output_layout = QHBoxLayout(output_frame)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.setSpacing(10)

        # Tool buttons panel (left)
        self.tool_buttons_panel = QFrame()
        self.tool_buttons_panel.setFixedWidth(120)
        self.tool_buttons_panel.setStyleSheet("""
            QFrame {
                background-color: rgba(20, 30, 40, 100);
                border-radius: 8px;
                border: 1px solid rgba(100, 200, 255, 30);
            }
        """)

        self.tool_buttons_layout = QVBoxLayout(self.tool_buttons_panel)
        self.tool_buttons_layout.setContentsMargins(5, 5, 5, 5)
        self.tool_buttons_layout.setSpacing(5)

        # Terminal output (right)
        self.terminal_output = QTextEdit()
        self.terminal_output.setObjectName("InfoPanel")
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setPlaceholderText("Tool output will appear here...")
        self.terminal_output.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.terminal_output.customContextMenuRequested.connect(self.show_terminal_context_menu)

        output_layout.addWidget(self.tool_buttons_panel)
        output_layout.addWidget(self.terminal_output, 1)

        return output_frame

    def setup_tool_data(self):
        """Setup tool data and create main tool buttons"""
        self.main_tools_data = [
            {"id": "dns_enum", "title": "DNS Enumeration", "desc": "Discover domains, subdomains, and IPs.", "icon": "resources/icons/1A.png"},
            {"id": "port_scan", "title": "Port Scanning", "desc": "Identify open ports and services running.", "icon": "resources/icons/1B.png"},
            {"id": "smb_enum", "title": "SMB Enumeration", "desc": "List shares and users via Windows SMB.", "icon": "resources/icons/1C.png"},
            {"id": "smtp_enum", "title": "SMTP Enumeration", "desc": "Probe mail servers for valid emails.", "icon": "resources/icons/1D.png"},
            {"id": "snmp_enum", "title": "SNMP Enumeration", "desc": "Extract network device info using SNMP.", "icon": "resources/icons/1E.png"},
            {"id": "http_fingerprint", "title": "HTTP/S Fingerprinting", "desc": "Identify web server type and technologies.", "icon": "resources/icons/1F.png"},
            {"id": "advanced_dir", "title": "Advanced Directory Enum", "desc": "Recursive directory discovery with intelligent filtering.", "icon": "resources/icons/1F.png"},
            {"id": "cert_transparency", "title": "Certificate Transparency", "desc": "Discover subdomains through CT logs and certificate data.", "icon": "resources/icons/1G.png"},
            {"id": "osint", "title": "OSINT Data Gathering", "desc": "Collect intelligence from multiple open source sources.", "icon": "resources/icons/1H.png"},
            {"id": "vuln_scan", "title": "Vulnerability Scanner", "desc": "Identify common security vulnerabilities and misconfigurations.", "icon": "resources/icons/1H.png"},
            {"id": "api_enum", "title": "API Enumeration", "desc": "Discover and misuse APIs for data.", "icon": "resources/icons/1G.png"},
            {"id": "db_enum", "title": "Database Enumeration", "desc": "Find databases, tables, and credentials.", "icon": "resources/icons/1H.png"},
        ]

        # Create main tool buttons
        self.main_tool_buttons = []
        for tool in self.main_tools_data:
            button = self.create_main_tool_button(tool)
            self.tool_layout.addWidget(button)
            self.main_tool_buttons.append(button)

        # Add stretch to push buttons to top
        self.tool_layout.addStretch()

        # Setup tool-specific data
        self.setup_tool_specific_data()

    def create_main_tool_button(self, tool_data):
        """Create a main tool selection button"""
        button = HoverButton(tool_data["title"], tool_data["desc"], self)
        button.setMinimumHeight(50)
        button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        # Load icon
        icon_path = str(self.main_window.project_root / tool_data["icon"])
        icon = QIcon(icon_path)
        if not icon.isNull():
            button.setIcon(icon)
            button.setIconSize(QSize(24, 24))

        button.setText(tool_data["title"])
        button.setStyleSheet("""
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-size: 11pt;
                font-weight: bold;
                text-align: left;
                padding: 8px 12px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
                color: #FFFFFF;
            }
            QPushButton:pressed {
                background-color: rgba(70, 100, 130, 220);
            }
        """)

        # Connect to submenu activation
        button.clicked.connect(lambda: self.activate_tool_submenu(tool_data["id"]))
        button.enter_signal.connect(self.update_status_bar)
        button.leave_signal.connect(self.clear_status_bar)

        return button

    def setup_tool_specific_data(self):
        """Setup data for tool-specific buttons"""
        self.dns_tools_data = [
            {"id": "dns_hosts", "text": "HOSTS", "method": self.run_host_wordlist_scan},
            {"id": "dns_ptr", "text": "PTR", "method": self.run_ptr_scan},
            {"id": "dns_dnsrecon", "text": "DNSRecon", "method": self.run_dnsrecon},
            {"id": "dns_dnsenum", "text": "DNSEnum", "method": self.run_dnsenum},
            {"id": "dns_xfer", "text": "XFER", "method": self.run_zone_transfer},
            {"id": "dns_nslookup", "text": "NSLOOKUP", "method": self.run_nslookup},
        ]

        self.port_tools_data = [
            {"id": "port_tcp", "text": "TCP SCAN", "method": self.run_port_scan},
            {"id": "port_sweep", "text": "SWEEP", "method": self.run_port_sweep},
            {"id": "port_top", "text": "TOP PORTS", "method": self.run_top_ports},
            {"id": "port_service", "text": "SERVICE", "method": self.run_service_scan},
        ]

        # Store for easy access
        self.tool_data_map = {
            "dns_enum": self.dns_tools_data,
            "port_scan": self.port_tools_data,
        }

        # Initialize storage for results
        self.last_scan_results = {}
        self.last_scan_target = ""

    def activate_tool_submenu(self, tool_id):
        """Activate a specific tool submenu"""
        self.current_submenu = tool_id
        self.update_tool_buttons()
        self.update_controls_visibility()
        self.status_updated.emit(f"Selected: {tool_id.replace('_', ' ').title()}")

    def update_tool_buttons(self):
        """Update the tool buttons panel based on current submenu"""
        # Clear existing buttons
        for i in reversed(range(self.tool_buttons_layout.count())):
            child = self.tool_buttons_layout.itemAt(i).widget()
            if child:
                child.setParent(None)

        # Add new buttons based on current submenu
        if self.current_submenu in self.tool_data_map:
            tools_data = self.tool_data_map[self.current_submenu]
            for tool_data in tools_data:
                button = QPushButton(tool_data["text"])
                button.setProperty("class", "dnsToolButton")
                button.setMinimumHeight(35)
                button.clicked.connect(tool_data["method"])
                self.tool_buttons_layout.addWidget(button)

        # Add stretch
        self.tool_buttons_layout.addStretch()

    def update_controls_visibility(self):
        """Update control visibility based on current tool"""
        # Show/hide controls based on tool type
        show_wordlist = self.current_submenu in ["dns_enum", "smtp_enum"]
        show_record_types = self.current_submenu == "dns_enum"

        self.wordlist_combo.setVisible(show_wordlist)
        for checkbox in self.record_type_checkboxes.values():
            checkbox.setVisible(show_record_types)

    def populate_wordlists(self):
        """Populate wordlist combo box"""
        wordlist_dir = self.main_window.project_root / "resources" / "wordlists"
        if wordlist_dir.exists():
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt"):
                    self.wordlist_combo.addItem(filename, str(wordlist_dir / filename))

    def update_status_bar(self, title, description):
        """Update status bar with tool information"""
        self.status_bar.showMessage(f"{title}: {description}")

    def clear_status_bar(self):
        """Clear status bar"""
        self.status_bar.clearMessage()
    
    def on_memory_event(self, message):
        """Handle memory optimization events"""
        self.status_updated.emit(message)
    
    def apply_template(self, template):
        """Apply loaded template settings"""
        try:
            # Apply rate limiting settings
            rate_settings = template.get('settings', {}).get('rate_limit', {})
            if rate_settings.get('enabled', False):
                rate_limiter.set_rate_limit(
                    rate_settings.get('rps', 10),
                    rate_settings.get('threads', 50),
                    True
                )
                self.status_updated.emit(f"Applied rate limiting: {rate_settings.get('rps', 10)} req/s")
            
            # Apply proxy settings if needed
            proxy_settings = template.get('settings', {}).get('proxy', {})
            if proxy_settings.get('enabled', False):
                self.status_updated.emit("Template loaded - configure proxy manually if needed")
            
            # Update UI elements based on template
            tools = template.get('tools', [])
            if 'dns_enum' in tools:
                params = template.get('parameters', {}).get('dns_enum', {})
                record_types = params.get('record_types', ['A'])
                # Update record type checkboxes
                for rtype, checkbox in self.record_type_checkboxes.items():
                    checkbox.setChecked(rtype in record_types)
            
            self.status_updated.emit(f"Template applied: {template.get('description', 'Unknown template')}")
            
        except Exception as e:
            self.status_updated.emit(f"Error applying template: {str(e)}")
    
    def on_scan_scheduled(self, scan_id):
        """Handle scan scheduling event"""
        self.status_updated.emit(f"Scan scheduled: {scan_id}")
        
        # Start scheduler if not running
        if not scan_scheduler.running:
            scan_scheduler.start_scheduler()
            self.status_updated.emit("Scan scheduler started")
    
    def execute_single_target_scan(self, target: str, scan_type: str = 'dns_enum'):
        """Execute scan for single target (used by multi-target scanner)"""
        try:
            if scan_type == 'dns_enum':
                # Get current settings
                wordlist_path = self.wordlist_combo.currentData()
                selected_types = [rtype for rtype, cb in self.record_type_checkboxes.items() if cb.isChecked()]
                
                # Execute DNS enumeration
                from app.core.sync_scanner import enumerate_hostnames_sync
                return enumerate_hostnames_sync(target, wordlist_path, selected_types)
            else:
                return {'error': f'Scan type {scan_type} not implemented for multi-target'}
        except Exception as e:
            return {'error': str(e)}
    
    def on_multi_scan_completed(self, scan_id: str, results: dict):
        """Handle multi-target scan completion"""
        self.last_scan_results = results
        self.status_updated.emit(f"Multi-target scan completed: {len(results)} targets")
        
        # Enable export for multi-target results
        self.export_button.setEnabled(True)
        
        # Apply initial theme
        theme_manager.apply_theme()
        
        # Setup keyboard shortcuts
        self.setup_shortcuts()
    
    def setup_shortcuts(self):
        """Setup keyboard shortcuts for this page"""
        try:
            # Get main window for shortcut setup
            main_window = self.window()
            if main_window:
                self.shortcut_manager = ShortcutManager(main_window)
                
                # Connect shortcut signals
                self.shortcut_manager.new_scan.connect(self.start_new_scan)
                self.shortcut_manager.export_results.connect(self.quick_export)
                self.shortcut_manager.toggle_theme.connect(theme_manager.toggle_theme)
                self.shortcut_manager.show_help.connect(self.show_help)
                self.shortcut_manager.pause_scan.connect(self.toggle_pause_scan)
                self.shortcut_manager.stop_scan.connect(self.stop_current_scan)
                self.shortcut_manager.multi_target.connect(self.show_multi_target)
        except Exception:
            pass  # Fail silently if shortcuts can't be setup
    
    def start_new_scan(self):
        """Start new scan via shortcut"""
        if hasattr(self, 'dns_button'):
            self.dns_button.click()
    
    def quick_export(self):
        """Quick export via shortcut"""
        if self.export_button.isEnabled():
            self.export_button.click()
    
    def show_help(self):
        """Show help via shortcut"""
        self.help_widget.setVisible(True)
        self.status_updated.emit("Help opened (F1)")
    
    def toggle_pause_scan(self):
        """Toggle pause/resume scan"""
        # Would integrate with scan controller if available
        self.status_updated.emit("Pause/Resume scan (Ctrl+P)")
    
    def stop_current_scan(self):
        """Stop current scan"""
        # Would integrate with scan controller if available
        self.status_updated.emit("Stop scan (Ctrl+S/Escape)")
    
    def show_multi_target(self):
        """Show multi-target scanner"""
        self.multi_target_widget.setVisible(True)
        self.status_updated.emit("Multi-target scanner opened (Ctrl+M)")
    
    def on_wordlist_dropped(self, file_path):
        """Handle wordlist file drop"""
        self.status_updated.emit(f"📁 Wordlist loaded: {file_path}")
        # Wordlist is already added to combo by DragDropComboBox
    
    def on_advanced_dir_completed(self, results):
        """Handle advanced directory enumeration completion"""
        if 'error' not in results:
            self.last_scan_results = results
            self.export_button.setEnabled(True)
            
            stats = results.get('scan_stats', {})
            dirs_found = stats.get('directories_found', 0)
            files_found = stats.get('files_found', 0)
            
            self.status_updated.emit(f"Advanced directory scan completed: {dirs_found} directories, {files_found} files found")
        else:
            self.status_updated.emit(f"Advanced directory scan failed: {results['error']}")
    
    def on_cert_transparency_completed(self, results):
        """Handle certificate transparency search completion"""
        if 'error' not in results:
            self.last_scan_results = results
            self.export_button.setEnabled(True)
            
            subdomain_count = len(results.get('subdomains', []))
            cert_count = len(results.get('certificates', []))
            
            self.status_updated.emit(f"Certificate transparency search completed: {subdomain_count} subdomains from {cert_count} certificates")
        else:
            self.status_updated.emit(f"Certificate transparency search failed: {results['error']}")
    
    def on_osint_completed(self, results):
        """Handle OSINT data collection completion"""
        if 'error' not in results:
            self.last_scan_results = results
            self.export_button.setEnabled(True)
            
            findings_count = len(results.get('findings', []))
            sources_count = results.get('summary', {}).get('successful_sources', 0)
            
            self.status_updated.emit(f"OSINT collection completed: {findings_count} findings from {sources_count} sources")
        else:
            self.status_updated.emit(f"OSINT collection failed: {results['error']}")
    
    def on_vuln_scan_completed(self, results):
        """Handle vulnerability scan completion"""
        if 'error' not in results:
            self.last_scan_results = results
            self.export_button.setEnabled(True)
            
            vuln_count = len(results.get('vulnerabilities', []))
            high_count = results.get('summary', {}).get('severity_breakdown', {}).get('high', 0)
            
            self.status_updated.emit(f"Vulnerability scan completed: {vuln_count} vulnerabilities found ({high_count} high severity)")
            
            # Send vulnerability notification if vulnerabilities found
            if vuln_count > 0:
                try:
                    from app.core.notification_manager import notification_manager
                    target = getattr(self, 'last_scan_target', self.target_input.text().strip())
                    notification_manager.show_vulnerability_alert(target, vuln_count, high_count)
                except Exception:
                    pass
        else:
            self.status_updated.emit(f"Vulnerability scan failed: {results['error']}")
            
            # Send error notification
            try:
                from app.core.notification_manager import notification_manager
                notification_manager.show_error_notification("Vulnerability Scan Failed", results['error'])
            except Exception:
                pass
    
    def on_scan_loaded(self, scan):
        """Handle scan loaded from history"""
        self.last_scan_results = scan.get('results', {})
        self.export_button.setEnabled(True)
        
        target = scan.get('target', '')
        scan_type = scan.get('scan_type', '')
        scan_id = scan.get('id', 0)
        
        self.status_updated.emit(f"Loaded historical scan: {target} ({scan_type}) - ID {scan_id}")
        
        # Update target input if available
        if target and hasattr(self, 'target_input'):
            self.target_input.setText(target)
    
    def on_session_changed(self, session_id):
        """Handle session change"""
        from app.core.session_manager import session_manager
        session = session_manager.get_session(session_id)
        
        if session:
            self.status_updated.emit(f"Active session: {session['name']} ({len(session.get('scan_ids', []))} scans)")
            
            # Load session targets if available
            targets = session.get('targets', [])
            if targets and hasattr(self, 'target_input'):
                self.target_input.setText(targets[0])  # Load first target
    
    def on_wordlist_selected(self, wordlist_id):
        """Handle wordlist selection"""
        from app.core.wordlist_manager import wordlist_manager
        wordlists = wordlist_manager.get_wordlists()
        wordlist = next((wl for wl in wordlists if wl['id'] == wordlist_id), None)
        
        if wordlist:
            self.status_updated.emit(f"Selected wordlist: {wordlist['name']} ({wordlist['word_count']} words)")
            
            # Update wordlist combo if available
            if hasattr(self, 'wordlist_combo'):
                # Add to combo if not already present
                for i in range(self.wordlist_combo.count()):
                    if self.wordlist_combo.itemData(i) == wordlist['filepath']:
                        self.wordlist_combo.setCurrentIndex(i)
                        return
                
                # Add new item
                self.wordlist_combo.addItem(wordlist['name'], wordlist['filepath'])
                self.wordlist_combo.setCurrentIndex(self.wordlist_combo.count() - 1)
    
    def on_results_filtered(self, filtered_results):
        """Handle filtered results"""
        self.status_updated.emit(f"Results filtered: {len(filtered_results)} items match criteria")
    
    def _convert_results_to_list(self, results):
        """Convert scan results to list format for filtering"""
        if isinstance(results, list):
            return results
        elif isinstance(results, dict):
            # Convert dict to list of items
            result_list = []
            for key, value in results.items():
                if isinstance(value, dict):
                    item = value.copy()
                    item['key'] = key
                    result_list.append(item)
                else:
                    result_list.append({'key': key, 'value': value})
            return result_list
        else:
            return []

    def apply_theme(self):
        """Apply theme styling"""
        theme = self.main_window.theme_manager
        background_path = theme.get("backgrounds.enumeration")
        if background_path:
            self.setStyleSheet(f"""
                EnumerationPage {{
                    background-image: url({background_path});
                    background-repeat: no-repeat;
                    background-position: center;
                    background-attachment: fixed;
                }}
            """)

    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        self.scan_shortcut = QShortcut(QKeySequence("F5"), self)
        self.scan_shortcut.activated.connect(self.run_current_tool)
        
        self.export_shortcut = QShortcut(QKeySequence("Ctrl+E"), self)
        self.export_shortcut.activated.connect(self.export_results)
        
        self.clear_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.clear_shortcut.activated.connect(self.clear_terminal)
        
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))

    def run_current_tool(self):
        """Run the currently selected tool's default action"""
        if self.current_submenu == "dns_enum":
            self.run_host_wordlist_scan()
        elif self.current_submenu == "port_scan":
            self.run_port_scan()

    def clear_terminal(self):
        """Clear terminal output"""
        self.terminal_output.clear()
        self.status_updated.emit("Terminal output cleared")

    # Tool execution methods (simplified versions)
    def run_host_wordlist_scan(self):
        """Run DNS hostname enumeration"""
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target domain")
            return

        wordlist_path = self.wordlist_combo.currentData()
        selected_types = [rtype for rtype, cb in self.record_type_checkboxes.items() if cb.isChecked()]
        
        # Check cache first
        cache_params = {'wordlist': wordlist_path, 'types': selected_types}
        cached_results = cache_manager.get('dns_enum', target, cache_params)
        if cached_results:
            self.status_updated.emit(f"Loading cached results for {target}...")
            self.cache_widget.update_status("Hit")
            self.display_cached_results(cached_results)
            return
        
        self.cache_widget.update_status("Miss")
        
        # Optimize memory before starting scan
        memory_manager.optimize_memory()
        
        # Start scan control
        self.scan_control.start_scan()

        self.terminal_output.clear()
        self.progress_widget.setVisible(True)
        self.status_updated.emit(f"Starting DNS enumeration on {target}...")

        # Use your existing custom_scripts.enumerate_hostnames method
        custom_scripts.enumerate_hostnames(
            target=target,
            wordlist_path=wordlist_path,
            record_types=selected_types,
            output_callback=self.append_terminal_output,
            status_callback=self.update_status_bar_text,
            finished_callback=self.on_scan_finished,
            results_callback=self.store_scan_results,
            progress_callback=self.update_progress,
            progress_start_callback=self.start_progress,
            scan_controller=self.scan_control.scan_controller
        )

    def run_port_scan(self):
        """Run port scan"""
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target IP")
            return
        
        # Check cache first
        cached_results = cache_manager.get('port_scan', target)
        if cached_results:
            self.status_updated.emit(f"Loading cached port scan for {target}...")
            self.cache_widget.update_status("Hit")
            self.display_cached_results(cached_results)
            return
        
        self.cache_widget.update_status("Miss")

        self.terminal_output.clear()
        self.status_updated.emit(f"Starting port scan on {target}...")

        cmd = ["python", "tools/port_scanner.py", target, "-p", "1-1000"]
        worker = CommandWorker(cmd, f"Port scan on {target}", str(self.main_window.project_root))
        worker.signals.output.connect(self.append_terminal_output)
        worker.signals.error.connect(self.append_terminal_output)
        worker.signals.finished.connect(lambda: self.on_port_scan_finished(target))
        QThreadPool.globalInstance().start(worker)

    # Placeholder methods for other tools
    def run_ptr_scan(self): self.show_info("PTR scan functionality")
    def run_dnsrecon(self): self.show_info("DNSRecon functionality")
    def run_dnsenum(self): self.show_info("DNSEnum functionality")
    def run_zone_transfer(self): self.show_info("Zone transfer functionality")
    def run_nslookup(self): self.show_info("NSLookup functionality")
    def run_port_sweep(self): self.show_info("Port sweep functionality")
    def run_top_ports(self): self.show_info("Top ports scan functionality")
    def run_service_scan(self): self.show_info("Service scan functionality")

    # Utility methods
    def show_error(self, message):
        """Show error message"""
        self.terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {message}</p>")
        self.status_updated.emit(f"Error: {message}")

    def show_info(self, message):
        """Show info message"""
        self.terminal_output.setHtml(f"<p style='color: #64C8FF;'>[INFO] {message}</p>")
        self.status_bar.showMessage(message)

    def append_terminal_output(self, text):
        """Append text to terminal output"""
        self.terminal_output.insertHtml(text)
        scrollbar = self.terminal_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def update_status_bar_text(self, text):
        """Update status bar with text"""
        self.status_bar.showMessage(text)

    def store_scan_results(self, results):
        """Store scan results for export and cache"""
        self.last_scan_results = results
        self.export_button.setEnabled(True)  # Always enable for proxy access
        
        # Cache the results
        if results and hasattr(self, 'last_scan_target'):
            target = getattr(self, 'last_scan_target', self.target_input.text().strip())
            wordlist_path = self.wordlist_combo.currentData()
            selected_types = [rtype for rtype, cb in self.record_type_checkboxes.items() if cb.isChecked()]
            cache_params = {'wordlist': wordlist_path, 'types': selected_types}
            cache_manager.set('dns_enum', target, results, cache_params)
            
            # Save to scan database
            try:
                scan_id = scan_db.save_scan(target, self.current_submenu, results)
                
                # Add to current session if active
                from app.core.session_manager import session_manager
                current_session = session_manager.get_current_session()
                if current_session and scan_id:
                    session_manager.add_scan_to_session(current_session['id'], scan_id)
                    
            except Exception:
                pass  # Fail silently if database save fails
        
        # Auto-run correlation if significant results
        if results and isinstance(results, dict) and len(results) > 5:
            self.status_updated.emit("Auto-analyzing correlations...")
            scan_data = {self.current_submenu: results}
            correlations = vulnerability_correlator.correlate_findings(scan_data)
            
            if correlations.get('correlation_score', 0) > 30:
                self.correlation_widget.setVisible(True)
                self.correlation_widget.display_correlations(correlations)
        
        # Auto-run ML pattern analysis for significant results
        if results and len(results) > 3:
            from app.core.ml_pattern_detection import ml_pattern_detection
            ml_analysis = ml_pattern_detection.analyze_scan_results(results, self.current_submenu)
            
            patterns_found = len(ml_analysis.get('patterns', []))
            if patterns_found > 0:
                self.status_updated.emit(f"🤖 Auto-detected {patterns_found} patterns in results")
        
        # Auto-run comparison if results exist
        if results:
            target = getattr(self, 'last_scan_target', self.target_input.text().strip())
            comparison = result_comparator.compare_results(results, target, self.current_submenu)
            
            if comparison.get('changes_detected', False):
                self.comparison_widget.setVisible(True)
                self.comparison_widget.display_comparison(comparison)
                self.status_updated.emit(f"Changes detected: +{len(comparison.get('new_findings', []))} new findings")

    def start_progress(self, total_items):
        """Start progress tracking"""
        self.progress_widget.start_progress(total_items, "Scanning...")

    def update_progress(self, completed_items, results_found):
        """Update progress"""
        self.progress_widget.update_progress(completed_items, results_found)

    def on_scan_finished(self):
        """Handle scan completion"""
        self.progress_widget.finish_progress("Scan Complete")
        self.status_updated.emit("Scan completed successfully")
        
        # Send notification
        try:
            from app.core.notification_manager import notification_manager
            target = getattr(self, 'last_scan_target', self.target_input.text().strip())
            results_count = len(self.last_scan_results) if isinstance(self.last_scan_results, (list, dict)) else 0
            notification_manager.show_scan_completion(target, self.current_submenu, results_count)
        except Exception:
            pass
        
        # Reset scan control
        self.scan_control.scan_controller.reset()
        # Clean up memory after scan
        memory_manager.optimize_memory()
    
    def on_port_scan_finished(self, target):
        """Handle port scan completion and cache results"""
        self.status_updated.emit("Port scan completed successfully")
        # Cache basic port scan result (simplified)
        cache_manager.set('port_scan', target, {'status': 'completed', 'timestamp': time.time()})

    def display_cached_results(self, results):
        """Display cached scan results"""
        self.last_scan_results = results
        self.export_button.setEnabled(True)
        
        # Format and display results
        output = "<p style='color: #64C8FF;'>[CACHED] Previous scan results:</p>"
        if isinstance(results, dict):
            for key, value in results.items():
                output += f"<p style='color: #00FF41;'>[+] {key}: {value}</p>"
        elif isinstance(results, list):
            for item in results:
                output += f"<p style='color: #00FF41;'>[+] {item}</p>"
        
        self.terminal_output.setHtml(output)
        self.status_updated.emit("Cached results loaded")
    
    def handle_export_action(self):
        """Handle export button click - either export or show proxy config"""
        format_type = self.export_combo.currentText().lower()
        
        if format_type == "proxy":
            # Show proxy configuration
            self.proxy_widget.setVisible(True)
            self.status_updated.emit("Proxy configuration panel opened")
        elif format_type == "rate limit":
            # Show rate limiting configuration
            self.rate_limit_widget.setVisible(True)
            self.status_updated.emit("Rate limiting configuration panel opened")
        elif format_type == "templates":
            # Show template management
            self.template_widget.setVisible(True)
            self.status_updated.emit("Template management panel opened")
        elif format_type == "schedule":
            # Show scan scheduler
            self.scheduler_widget.setVisible(True)
            self.status_updated.emit("Scan scheduler panel opened")
        elif format_type == "multi-target":
            # Show multi-target scanner
            self.multi_target_widget.setVisible(True)
            self.status_updated.emit("Multi-target scanner panel opened")
        elif format_type == "theme":
            # Show theme selector
            self.theme_widget.setVisible(True)
            self.status_updated.emit("Theme selector panel opened")
        elif format_type == "advanced themes":
            # Show advanced theme selector
            self.advanced_theme_widget.setVisible(True)
            # Load themes from main window's advanced theme manager
            if hasattr(self.main_window, 'advanced_theme_manager'):
                self.advanced_theme_widget.load_themes(self.main_window.advanced_theme_manager)
            self.status_updated.emit("Advanced theme selector panel opened")
        elif format_type == "help":
            # Show help
            self.help_widget.setVisible(True)
            self.status_updated.emit("Help panel opened")
        elif format_type == "advanced dir":
            # Show advanced directory enumeration
            self.advanced_dir_widget.setVisible(True)
            self.status_updated.emit("Advanced directory enumeration panel opened")
        elif format_type == "cert transparency":
            # Show certificate transparency search
            self.cert_transparency_widget.setVisible(True)
            self.status_updated.emit("Certificate transparency search panel opened")
        elif format_type == "osint":
            # Show OSINT data gathering
            self.osint_widget.setVisible(True)
            self.status_updated.emit("OSINT data gathering panel opened")
        elif format_type == "vuln scan":
            # Show vulnerability scanner
            self.vuln_scanner_widget.setVisible(True)
            self.status_updated.emit("Vulnerability scanner panel opened")
        elif format_type == "history":
            # Show scan history
            self.scan_history_widget.setVisible(True)
            self.status_updated.emit("Scan history database opened")
        elif format_type == "sessions":
            # Show session management
            self.session_widget.setVisible(True)
            self.status_updated.emit("Session management panel opened")
        elif format_type == "wordlists":
            # Show wordlist management
            self.wordlist_widget.setVisible(True)
            self.status_updated.emit("Wordlist management panel opened")
        elif format_type == "filter":
            # Show result filtering
            self.filter_widget.setVisible(True)
            # Load current results if available
            if self.last_scan_results:
                self.filter_widget.load_results(self._convert_results_to_list(self.last_scan_results))
            self.status_updated.emit("Result filtering panel opened")
        elif format_type == "notifications":
            # Show notifications
            self.notification_widget.setVisible(True)
            self.status_updated.emit("Notifications panel opened")
        elif format_type == "plugins":
            # Show plugin manager
            self.plugin_widget.setVisible(True)
            self.status_updated.emit("Plugin manager opened")
        elif format_type == "api integration":
            # Show API integration
            self.api_integration_widget.setVisible(True)
            self.status_updated.emit("API integration panel opened")
        elif format_type == "threat intel":
            # Show threat intelligence
            self.threat_intel_widget.setVisible(True)
            self.status_updated.emit("Threat intelligence panel opened")
        elif format_type == "ml patterns":
            # Show ML pattern detection
            self.ml_pattern_widget.setVisible(True)
            # Load current results if available
            if self.last_scan_results:
                self.ml_pattern_widget.load_results(self.last_scan_results, self.current_submenu)
            self.status_updated.emit("ML pattern detection panel opened")
        elif format_type == "distributed scan":
            # Show distributed scanning
            self.distributed_scan_widget.setVisible(True)
            self.status_updated.emit("Distributed scanning panel opened")
        else:
            self.export_results()
    
    def export_results(self):
        """Export scan results"""
        if not self.last_scan_results:
            self.show_error("No scan results to export")
            return

        format_type = self.export_combo.currentText().lower()
        self.status_updated.emit(f"Exporting results as {format_type.upper()}...")
        
        if format_type == "pdf":
            # Show PDF preview widget
            self.pdf_preview.setVisible(True)
            self.pdf_preview.update_status("Generating PDF report...")
            
            # Generate PDF report
            target = getattr(self, 'last_scan_target', self.target_input.text().strip())
            output_path = f"exports/{target}_scan_report.pdf"
            os.makedirs("exports", exist_ok=True)
            
            success, filepath, message = pdf_generator.generate_report(
                self.last_scan_results,
                target,
                self.current_submenu,
                output_path
            )
            
            if success:
                self.pdf_preview.update_status(f"PDF generated: {filepath}")
            else:
                self.pdf_preview.update_status(f"PDF generation failed: {message}")
        elif format_type == "summary":
            # Generate executive summary
            target = getattr(self, 'last_scan_target', self.target_input.text().strip())
            output_path = f"exports/{target}_executive_summary.json"
            os.makedirs("exports", exist_ok=True)
            
            success, filepath, message = executive_summary.generate_json_summary(
                self.last_scan_results,
                self.current_submenu,
                target,
                output_path
            )
            
            if success:
                # Show summary widget and load data
                self.summary_widget.setVisible(True)
                with open(filepath, 'r') as f:
                    summary_data = json.load(f)
                self.summary_widget.display_summary(summary_data)
        elif format_type == "correlate":
            # Perform vulnerability correlation
            self.status_updated.emit("Analyzing vulnerability correlations...")
            
            # Create scan results dict for correlation
            scan_data = {
                self.current_submenu: self.last_scan_results
            }
            
            correlations = vulnerability_correlator.correlate_findings(scan_data)
            
            # Show correlation widget
            self.correlation_widget.setVisible(True)
            self.correlation_widget.display_correlations(correlations)
            
            # Save correlation results
            target = getattr(self, 'last_scan_target', self.target_input.text().strip())
            output_path = f"exports/{target}_correlations.json"
            os.makedirs("exports", exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(correlations, f, indent=2)
            
            success, filepath, message = True, output_path, "Correlation analysis completed"
        elif format_type == "compare":
            # Perform result comparison
            self.status_updated.emit("Comparing with previous scans...")
            
            target = getattr(self, 'last_scan_target', self.target_input.text().strip())
            comparison = result_comparator.compare_results(
                self.last_scan_results,
                target,
                self.current_submenu
            )
            
            # Show comparison widget
            self.comparison_widget.setVisible(True)
            self.comparison_widget.display_comparison(comparison)
            
            # Save comparison results
            output_path = f"exports/{target}_comparison.json"
            os.makedirs("exports", exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(comparison, f, indent=2)
            
            success, filepath, message = True, output_path, "Comparison analysis completed"
        else:
            # Use existing exporter
            success, filepath, message = exporter.export_results(
                self.last_scan_results,
                self.last_scan_target,
                format_type
            )

        if success:
            self.show_info(f"Results exported to: {filepath}")
            self.status_updated.emit(f"Export completed: {filepath}")
        else:
            self.show_error(f"Export failed: {message}")
    
    def apply_advanced_theme(self, theme_name):
        """Apply advanced theme selection"""
        if hasattr(self.main_window, 'advanced_theme_manager'):
            success = self.main_window.advanced_theme_manager.apply_theme(theme_name)
            if success:
                theme_display_name = self.main_window.advanced_theme_manager.available_themes[theme_name]['name']
                self.status_updated.emit(f"Applied theme: {theme_display_name}")
            else:
                self.status_updated.emit(f"Failed to apply theme: {theme_name}")
    
    def show_terminal_context_menu(self, position):
        """Show context menu for terminal output"""
        cursor = self.terminal_output.textCursor()
        selected_text = cursor.selectedText()
        has_results = bool(self.last_scan_results)
        
        menu = self.context_menu_manager.create_terminal_menu(self.terminal_output, selected_text)
        menu.exec(self.terminal_output.mapToGlobal(position))
    
    def show_input_context_menu(self, position):
        """Show context menu for input fields"""
        menu = self.context_menu_manager.create_input_menu(self.target_input)
        menu.exec(self.target_input.mapToGlobal(position))
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        from PyQt6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        self.status_updated.emit("Text copied to clipboard")
    
    def save_output_to_file(self, content):
        """Save output content to file"""
        from PyQt6.QtWidgets import QFileDialog
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Output", "output.txt", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.status_updated.emit(f"Output saved to: {filename}")
            except Exception as e:
                self.status_updated.emit(f"Failed to save file: {str(e)}")
    
    def on_plugin_executed(self, plugin_name, result):
        """Handle plugin execution completion."""
        if 'error' not in result:
            self.last_scan_results = result
            self.export_button.setEnabled(True)
            self.status_updated.emit(f"Plugin {plugin_name} executed successfully")
        else:
            self.status_updated.emit(f"Plugin {plugin_name} failed: {result['error']}")
    
    def on_api_executed(self, source, result):
        """Handle API integration completion."""
        if 'error' not in result:
            self.last_scan_results = result
            self.export_button.setEnabled(True)
            self.status_updated.emit(f"API query to {source} completed successfully")
        else:
            self.status_updated.emit(f"API query to {source} failed: {result['error']}")
    
    def on_threat_checked(self, check_type, result):
        """Handle threat intelligence check completion."""
        threats_found = len(result.get('threats', []))
        target = result.get('ip', result.get('domain', 'Unknown'))
        
        if threats_found > 0:
            self.last_scan_results = result
            self.export_button.setEnabled(True)
            self.status_updated.emit(f"⚠️ {threats_found} threats found for {target}")
        else:
            self.status_updated.emit(f"✅ No threats found for {target}")
    
    def on_pattern_analyzed(self, scan_type, analysis):
        """Handle ML pattern analysis completion."""
        patterns_found = len(analysis.get('patterns', []))
        anomalies_found = len(analysis.get('anomalies', []))
        
        if patterns_found > 0 or anomalies_found > 0:
            self.last_scan_results = analysis
            self.export_button.setEnabled(True)
            self.status_updated.emit(f"🤖 ML analysis: {patterns_found} patterns, {anomalies_found} anomalies")
        else:
            self.status_updated.emit(f"🤖 ML analysis completed - no significant patterns detected")
    
    def on_distributed_scan_completed(self, scan_id, results):
        """Handle distributed scan completion."""
        summary = results.get('summary', {})
        total_nodes = summary.get('total_nodes', 0)
        total_results = summary.get('total_results', 0)
        
        if total_results > 0:
            self.last_scan_results = results
            self.export_button.setEnabled(True)
            self.status_updated.emit(f"🌐 Distributed scan completed: {total_results} results from {total_nodes} nodes")
        else:
            self.status_updated.emit(f"🌐 Distributed scan completed - no results from {total_nodes} nodes")