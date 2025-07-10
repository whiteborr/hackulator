# app/widgets/hacking_mode_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QComboBox, QPushButton, QLineEdit, QSpinBox,
                            QGroupBox, QTextEdit, QTabWidget, QCheckBox,
                            QTableWidget, QTableWidgetItem, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSignal
from app.core.hacking_mode import hacking_mode
from app.core.license_manager import license_manager

class HackingModeWidget(QWidget):
    """Hacking mode interface widget"""
    
    exploit_executed = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.connect_signals()
        self.check_license()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Hacking Mode - Exploit Framework")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #FF6B6B;")
        layout.addWidget(header)
        
        # Warning
        warning = QLabel("⚠️ FOR AUTHORIZED TESTING ONLY - PROFESSIONAL LICENSE REQUIRED")
        warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px; background: rgba(255,107,107,0.1);")
        layout.addWidget(warning)
        
        # License warning
        self.license_warning = QLabel("❌ Hacking Mode requires Professional license")
        self.license_warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px;")
        layout.addWidget(self.license_warning)
        
        # Tab widget
        self.tabs = QTabWidget()
        
        # Exploit tab
        self.exploit_tab = self.create_exploit_tab()
        self.tabs.addTab(self.exploit_tab, "Exploits")
        
        # Payload tab
        self.payload_tab = self.create_payload_tab()
        self.tabs.addTab(self.payload_tab, "Payloads")
        
        # Sessions tab
        self.sessions_tab = self.create_sessions_tab()
        self.tabs.addTab(self.sessions_tab, "Sessions")
        
        layout.addWidget(self.tabs)
        
        # Status
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(150)
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)
        
    def create_exploit_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target configuration
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout(target_group)
        
        target_input_layout = QHBoxLayout()
        target_input_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.100")
        target_input_layout.addWidget(self.target_input)
        target_layout.addLayout(target_input_layout)
        
        lhost_layout = QHBoxLayout()
        lhost_layout.addWidget(QLabel("LHOST:"))
        self.lhost_input = QLineEdit()
        self.lhost_input.setPlaceholderText("10.0.0.1")
        lhost_layout.addWidget(self.lhost_input)
        
        lhost_layout.addWidget(QLabel("LPORT:"))
        self.lport_input = QSpinBox()
        self.lport_input.setRange(1, 65535)
        self.lport_input.setValue(4444)
        lhost_layout.addWidget(self.lport_input)
        target_layout.addLayout(lhost_layout)
        
        layout.addWidget(target_group)
        
        # Exploit selection
        exploit_group = QGroupBox("Exploit Selection")
        exploit_layout = QVBoxLayout(exploit_group)
        
        self.exploit_combo = QComboBox()
        self.exploit_combo.addItems([
            "ms17_010 (EternalBlue)",
            "eternal_blue (SMB)",
            "web_shell (PHP/ASP/JSP)",
            "privilege_escalation",
            "lateral_movement"
        ])
        exploit_layout.addWidget(self.exploit_combo)
        
        # Exploit options
        options_layout = QHBoxLayout()
        self.auto_exploit = QCheckBox("Auto-exploit")
        self.stealth_mode = QCheckBox("Stealth mode")
        options_layout.addWidget(self.auto_exploit)
        options_layout.addWidget(self.stealth_mode)
        exploit_layout.addLayout(options_layout)
        
        self.execute_exploit_btn = QPushButton("Execute Exploit")
        self.execute_exploit_btn.setStyleSheet("background-color: #FF6B6B; font-weight: bold;")
        exploit_layout.addWidget(self.execute_exploit_btn)
        
        layout.addWidget(exploit_group)
        
        return widget
        
    def create_payload_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Payload configuration
        payload_group = QGroupBox("Payload Generation")
        payload_layout = QVBoxLayout(payload_group)
        
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Type:"))
        self.payload_type = QComboBox()
        self.payload_type.addItems([
            "reverse_shell",
            "bind_shell", 
            "meterpreter",
            "powershell"
        ])
        type_layout.addWidget(self.payload_type)
        payload_layout.addLayout(type_layout)
        
        shell_layout = QHBoxLayout()
        shell_layout.addWidget(QLabel("Shell:"))
        self.shell_type = QComboBox()
        self.shell_type.addItems(["bash", "python", "powershell", "cmd"])
        shell_layout.addWidget(self.shell_type)
        payload_layout.addLayout(shell_layout)
        
        self.generate_payload_btn = QPushButton("Generate Payload")
        payload_layout.addWidget(self.generate_payload_btn)
        
        layout.addWidget(payload_group)
        
        # Generated payload
        self.payload_output = QTextEdit()
        self.payload_output.setPlaceholderText("Generated payload will appear here...")
        layout.addWidget(self.payload_output)
        
        return widget
        
    def create_sessions_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Session management
        session_group = QGroupBox("Active Sessions")
        session_layout = QVBoxLayout(session_group)
        
        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(4)
        self.sessions_table.setHorizontalHeaderLabels(["ID", "Type", "Target", "Status"])
        session_layout.addWidget(self.sessions_table)
        
        session_buttons = QHBoxLayout()
        self.refresh_sessions_btn = QPushButton("Refresh")
        self.interact_session_btn = QPushButton("Interact")
        self.kill_session_btn = QPushButton("Kill Session")
        
        session_buttons.addWidget(self.refresh_sessions_btn)
        session_buttons.addWidget(self.interact_session_btn)
        session_buttons.addWidget(self.kill_session_btn)
        session_layout.addLayout(session_buttons)
        
        layout.addWidget(session_group)
        
        return widget
        
    def connect_signals(self):
        self.execute_exploit_btn.clicked.connect(self.execute_exploit)
        self.generate_payload_btn.clicked.connect(self.generate_payload)
        self.refresh_sessions_btn.clicked.connect(self.refresh_sessions)
        hacking_mode.exploit_event.connect(self.handle_exploit_event)
        
    def check_license(self):
        if license_manager.is_feature_enabled('hacking_mode'):
            self.license_warning.hide()
            self.setEnabled(True)
        else:
            self.license_warning.show()
            self.setEnabled(False)
            
    def execute_exploit(self):
        if not license_manager.is_feature_enabled('hacking_mode'):
            self.status_text.append("❌ Hacking Mode requires Professional license")
            return
            
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Target is required")
            return
            
        exploit_text = self.exploit_combo.currentText()
        exploit_type = exploit_text.split()[0]  # Extract exploit name
        
        options = {
            'lhost': self.lhost_input.text().strip() or '127.0.0.1',
            'lport': self.lport_input.value(),
            'stealth': self.stealth_mode.isChecked(),
            'auto': self.auto_exploit.isChecked()
        }
        
        self.status_text.append(f"🚀 Executing {exploit_type} against {target}...")
        
        # Show confirmation dialog
        reply = QMessageBox.question(
            self, 'Confirm Exploit Execution',
            f"Execute {exploit_type} against {target}?\n\n"
            f"LHOST: {options['lhost']}\n"
            f"LPORT: {options['lport']}\n\n"
            "This action should only be performed on authorized targets.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            result = hacking_mode.execute_exploit(exploit_type, target, options)
            
            if result['success']:
                self.status_text.append(f"✅ Exploit executed successfully")
                self.status_text.append(f"📋 Output: {result.get('output', 'No output')[:200]}...")
            else:
                self.status_text.append(f"❌ Exploit failed: {result.get('error', 'Unknown error')}")
                
    def generate_payload(self):
        if not license_manager.is_feature_enabled('hacking_mode'):
            self.status_text.append("❌ Hacking Mode requires Professional license")
            return
            
        payload_type = self.payload_type.currentText()
        shell_type = self.shell_type.currentText()
        
        options = {
            'lhost': self.lhost_input.text().strip() or '127.0.0.1',
            'lport': self.lport_input.value(),
            'type': shell_type
        }
        
        self.status_text.append(f"🔧 Generating {payload_type} payload...")
        
        result = hacking_mode.generate_payload(payload_type, options)
        
        if result['success']:
            self.payload_output.setPlainText(result['payload'])
            self.status_text.append(f"✅ Payload generated: {payload_type}")
        else:
            self.status_text.append(f"❌ Payload generation failed: {result.get('error', 'Unknown error')}")
            
    def refresh_sessions(self):
        status = hacking_mode.get_session_status()
        sessions = status.get('sessions', [])
        
        self.sessions_table.setRowCount(len(sessions))
        
        for row, session in enumerate(sessions):
            self.sessions_table.setItem(row, 0, QTableWidgetItem(session.get('id', '')))
            self.sessions_table.setItem(row, 1, QTableWidgetItem(session.get('type', '')))
            self.sessions_table.setItem(row, 2, QTableWidgetItem(session.get('target', '')))
            self.sessions_table.setItem(row, 3, QTableWidgetItem(session.get('status', '')))
            
        self.status_text.append(f"🔄 Refreshed sessions: {len(sessions)} active")
        
    def handle_exploit_event(self, event_type, message, data):
        self.status_text.append(f"🎯 {message}")
        if event_type == 'session_established':
            self.refresh_sessions()