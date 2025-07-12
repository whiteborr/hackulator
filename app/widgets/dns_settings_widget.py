# app/widgets/dns_settings_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QComboBox, QPushButton, QGroupBox, QTextEdit,
                            QMessageBox, QFrame, QLineEdit, QTableWidget,
                            QTableWidgetItem)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from app.core.dns_settings import dns_settings
from app.core.local_dns_server import local_dns_server
from app.core.license_manager import license_manager

class DNSSettingsWidget(QWidget):
    """DNS Settings configuration widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.connect_signals()
        self.load_current_settings()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        
        # Title
        title = QLabel("DNS Settings")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #00FF41; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # DNS Server Selection Group
        dns_group = QGroupBox("Global DNS Server")
        dns_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #64C8FF;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                color: #DCDCDC;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        dns_layout = QVBoxLayout(dns_group)
        
        # DNS selection
        dns_select_layout = QHBoxLayout()
        dns_select_layout.addWidget(QLabel("DNS Server:"))
        
        self.dns_combo = QComboBox()
        self.dns_combo.setEditable(True)
        self.dns_combo.addItems(dns_settings.get_available_dns_servers())
        self.dns_combo.lineEdit().setPlaceholderText("Enter IP address or FQDN")
        self.dns_combo.setStyleSheet("""
            QComboBox {
                background-color: rgba(50, 50, 50, 150);
                color: #DCDCDC;
                border: 1px solid #64C8FF;
                border-radius: 4px;
                padding: 5px;
                min-width: 200px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #64C8FF;
            }
        """)
        dns_select_layout.addWidget(self.dns_combo)
        dns_select_layout.addStretch()
        
        dns_layout.addLayout(dns_select_layout)
        
        # Apply button
        apply_layout = QHBoxLayout()
        self.apply_btn = QPushButton("Apply DNS Settings")
        self.apply_btn.setStyleSheet("""
            QPushButton {
                background-color: #00FF41;
                color: #000000;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00CC33;
            }
        """)
        apply_layout.addWidget(self.apply_btn)
        apply_layout.addStretch()
        
        dns_layout.addLayout(apply_layout)
        layout.addWidget(dns_group)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setStyleSheet("color: #64C8FF;")
        layout.addWidget(separator)
        
        # Local DNS Server Group
        local_dns_group = QGroupBox("Local DNS Server (Professional/Enterprise)")
        local_dns_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #FFD700;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                color: #DCDCDC;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        local_dns_layout = QVBoxLayout(local_dns_group)
        
        # Server controls
        server_controls = QHBoxLayout()
        
        self.start_server_btn = QPushButton("Start Local DNS Server")
        self.start_server_btn.setStyleSheet("""
            QPushButton {
                background-color: #00FF41;
                color: #000000;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00CC33;
            }
            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
            }
        """)
        
        self.stop_server_btn = QPushButton("Stop Local DNS Server")
        self.stop_server_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF4444;
                color: #FFFFFF;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #CC3333;
            }
            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
            }
        """)
        
        server_controls.addWidget(self.start_server_btn)
        server_controls.addWidget(self.stop_server_btn)
        server_controls.addStretch()
        
        local_dns_layout.addLayout(server_controls)
        
        # Server status
        self.server_status = QLabel("Server Status: Stopped")
        self.server_status.setStyleSheet("color: #FFAA00; font-weight: bold;")
        local_dns_layout.addWidget(self.server_status)
        
        # DNS Records Management Section
        records_section = QGroupBox("DNS Records")
        records_section.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #FFD700;
                border-radius: 4px;
                margin-top: 5px;
                padding-top: 5px;
                color: #DCDCDC;
            }
        """)
        records_layout = QVBoxLayout(records_section)
        
        # Add record form
        add_form = QHBoxLayout()
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        self.domain_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(50, 50, 50, 150);
                color: #DCDCDC;
                border: 1px solid #64C8FF;
                border-radius: 4px;
                padding: 4px;
            }
        """)
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["A", "AAAA", "CNAME"])
        self.type_combo.setStyleSheet("""
            QComboBox {
                background-color: rgba(50, 50, 50, 150);
                color: #DCDCDC;
                border: 1px solid #64C8FF;
                border-radius: 4px;
                padding: 4px;
            }
        """)
        
        self.value_input = QLineEdit()
        self.value_input.setPlaceholderText("192.168.1.1")
        self.value_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(50, 50, 50, 150);
                color: #DCDCDC;
                border: 1px solid #64C8FF;
                border-radius: 4px;
                padding: 4px;
            }
        """)
        
        self.add_record_btn = QPushButton("Add")
        self.add_record_btn.setStyleSheet("""
            QPushButton {
                background-color: #64C8FF;
                color: #000000;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #4A9FCC;
            }
            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
            }
        """)
        
        # Set stretch factors to control field widths
        add_form.addWidget(self.domain_input, 3)  # Domain field wider
        add_form.addWidget(self.type_combo, 1)    # Type field normal
        add_form.addWidget(self.value_input, 2)   # Value field narrower
        add_form.addWidget(self.add_record_btn, 1) # Button normal
        
        records_layout.addLayout(add_form)
        
        # Records table
        self.records_table = QTableWidget()
        self.records_table.setColumnCount(3)
        self.records_table.setHorizontalHeaderLabels(["Domain", "Type", "Value"])
        self.records_table.horizontalHeader().setStretchLastSection(True)
        self.records_table.setMaximumHeight(150)
        self.records_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(30, 30, 30, 150);
                color: #DCDCDC;
                border: 1px solid #64C8FF;
                border-radius: 4px;
                gridline-color: #64C8FF;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 100);
                color: #000000;
                border: none;
                padding: 4px;
                font-weight: bold;
            }
        """)
        records_layout.addWidget(self.records_table)
        
        # Table controls
        table_controls = QHBoxLayout()
        
        self.refresh_btn = QPushButton("Refresh")
        self.delete_btn = QPushButton("Delete")
        self.clear_btn = QPushButton("Clear All")
        
        for btn in [self.refresh_btn, self.delete_btn, self.clear_btn]:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(100, 100, 100, 150);
                    color: #DCDCDC;
                    border: 1px solid #64C8FF;
                    border-radius: 4px;
                    padding: 4px 8px;
                }
                QPushButton:hover {
                    background-color: rgba(100, 200, 255, 100);
                    color: #000000;
                }
                QPushButton:disabled {
                    background-color: #666666;
                    color: #999999;
                }
            """)
        
        table_controls.addWidget(self.refresh_btn)
        table_controls.addWidget(self.delete_btn)
        table_controls.addWidget(self.clear_btn)
        table_controls.addStretch()
        
        records_layout.addLayout(table_controls)
        local_dns_layout.addWidget(records_section)
        
        layout.addWidget(local_dns_group)
        
        # Status info
        info_text = QTextEdit()
        info_text.setMaximumHeight(100)
        info_text.setReadOnly(True)
        info_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(30, 30, 30, 150);
                color: #DCDCDC;
                border: 1px solid #64C8FF;
                border-radius: 4px;
                padding: 5px;
            }
        """)
        info_text.setPlainText(
            "DNS Settings affect all scanning tools globally.\n"
            "• Default DNS: Use system DNS settings\n"
            "• LocalDNS: Use local DNS server for custom domains\n"
            "• Public DNS: Use specified public DNS servers"
        )
        layout.addWidget(info_text)
        
        layout.addStretch()
        

        
        # Check license and enable/disable features
        self.update_license_features()
    
    def connect_signals(self):
        """Connect widget signals"""
        self.apply_btn.clicked.connect(self.apply_dns_settings)
        self.start_server_btn.clicked.connect(self.start_local_dns)
        self.stop_server_btn.clicked.connect(self.stop_local_dns)
        self.add_record_btn.clicked.connect(self.add_record)
        self.refresh_btn.clicked.connect(self.refresh_records)
        self.delete_btn.clicked.connect(self.delete_record)
        self.clear_btn.clicked.connect(self.clear_records)
        
        # Connect to local DNS server signals
        local_dns_server.status_changed.connect(self.update_server_status)
    
    def load_current_settings(self):
        """Load current DNS settings"""
        current_dns = dns_settings.get_current_dns()
        
        # Set combo box to current DNS setting
        index = self.dns_combo.findText(current_dns)
        if index >= 0:
            self.dns_combo.setCurrentIndex(index)
        else:
            # If it's a custom DNS server, set it as text
            self.dns_combo.setCurrentText(current_dns)
        
        # Update server status
        if local_dns_server.running:
            self.server_status.setText(f"Server Status: Running on port {local_dns_server.port}")
            self.server_status.setStyleSheet("color: #00FF41; font-weight: bold;")
            self.start_server_btn.setEnabled(False)
            self.stop_server_btn.setEnabled(True)
        else:
            self.server_status.setText("Server Status: Stopped")
            self.server_status.setStyleSheet("color: #FFAA00; font-weight: bold;")
            self.start_server_btn.setEnabled(True)
            self.stop_server_btn.setEnabled(False)
        
        self.refresh_records()
    
    def update_license_features(self):
        """Update features based on license"""
        is_licensed = license_manager.is_feature_enabled('local_dns_server')
        
        self.start_server_btn.setEnabled(is_licensed and not local_dns_server.running)
        self.stop_server_btn.setEnabled(is_licensed and local_dns_server.running)
        
        # Enable/disable DNS records controls
        for widget in [self.add_record_btn, self.refresh_btn, self.delete_btn, self.clear_btn]:
            widget.setEnabled(is_licensed)
        
        if not is_licensed:
            self.server_status.setText("Server Status: Requires Professional/Enterprise License")
            self.server_status.setStyleSheet("color: #FF4444; font-weight: bold;")
    
    def apply_dns_settings(self):
        """Apply DNS settings globally"""
        selected_dns = self.dns_combo.currentText()
        dns_settings.set_dns_server(selected_dns)
        
        QMessageBox.information(self, "DNS Settings", 
                              f"DNS server changed to: {selected_dns}\n\n"
                              "This setting will be used by all scanning tools.")
    
    def start_local_dns(self):
        """Start local DNS server"""
        if not license_manager.is_feature_enabled('local_dns_server'):
            QMessageBox.warning(self, "Professional Feature", 
                              "Local DNS Server requires Professional or Enterprise license.")
            return
        
        if local_dns_server.start_server():
            self.server_status.setText(f"Server Status: Running on port {local_dns_server.port}")
            self.server_status.setStyleSheet("color: #00FF41; font-weight: bold;")
            self.start_server_btn.setEnabled(False)
            self.stop_server_btn.setEnabled(True)
        else:
            QMessageBox.warning(self, "Server Error", "Failed to start Local DNS server.")
    
    def stop_local_dns(self):
        """Stop local DNS server"""
        local_dns_server.stop_server()
        self.server_status.setText("Server Status: Stopped")
        self.server_status.setStyleSheet("color: #FFAA00; font-weight: bold;")
        self.start_server_btn.setEnabled(True)
        self.stop_server_btn.setEnabled(False)
    
    def add_record(self):
        """Add DNS record"""
        domain = self.domain_input.text().strip()
        record_type = self.type_combo.currentText()
        value = self.value_input.text().strip()
        
        if not domain or not value:
            QMessageBox.warning(self, "Error", "Please fill in domain and value")
            return
        
        if local_dns_server.add_record(domain, record_type, value):
            self.domain_input.clear()
            self.value_input.clear()
            self.refresh_records()
    
    def delete_record(self):
        """Delete selected DNS record"""
        current_row = self.records_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Error", "Please select a record to delete")
            return
        
        domain = self.records_table.item(current_row, 0).text()
        record_type = self.records_table.item(current_row, 1).text()
        value = self.records_table.item(current_row, 2).text()
        
        if local_dns_server.remove_record(domain, record_type, value):
            self.refresh_records()
    
    def clear_records(self):
        """Clear all DNS records"""
        reply = QMessageBox.question(self, "Confirm", "Clear all DNS records?")
        if reply == QMessageBox.StandardButton.Yes:
            local_dns_server.clear_records()
            self.refresh_records()
    
    def refresh_records(self):
        """Refresh records table"""
        records = local_dns_server.get_records()
        total_records = sum(len(values) for types in records.values() for values in types.values())
        
        self.records_table.setRowCount(total_records)
        row = 0
        for domain, types in records.items():
            for record_type, values in types.items():
                for value in values:
                    self.records_table.setItem(row, 0, QTableWidgetItem(domain))
                    self.records_table.setItem(row, 1, QTableWidgetItem(record_type))
                    self.records_table.setItem(row, 2, QTableWidgetItem(value))
                    row += 1
    
    def update_server_status(self, message, is_running):
        """Update server status from signals"""
        if is_running:
            self.server_status.setText(f"Server Status: {message}")
            self.server_status.setStyleSheet("color: #00FF41; font-weight: bold;")
            self.start_server_btn.setEnabled(False)
            self.stop_server_btn.setEnabled(True)
        else:
            self.server_status.setText(f"Server Status: {message}")
            self.server_status.setStyleSheet("color: #FFAA00; font-weight: bold;")
            self.start_server_btn.setEnabled(True)
            self.stop_server_btn.setEnabled(False)