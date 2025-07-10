# app/widgets/web_scanner_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QGroupBox,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QCheckBox, QProgressBar, QComboBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor
from app.core.web_scanner import web_scanner
from app.core.license_manager import license_manager

class WebScanWorker(QThread):
    """Worker thread for web scanning"""
    scan_completed = pyqtSignal(dict)
    
    def __init__(self, url, scan_types):
        super().__init__()
        self.url = url
        self.scan_types = scan_types
        
    def run(self):
        result = web_scanner.comprehensive_scan(self.url)
        self.scan_completed.emit(result)

class WebScannerWidget(QWidget):
    """Web application security scanner widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_worker = None
        self.setup_ui()
        self.connect_signals()
        self.check_license()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Web Application Security Scanner")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(header)
        
        # License warning
        self.license_warning = QLabel("⚠️ Web Scanner requires Professional license")
        self.license_warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px;")
        layout.addWidget(self.license_warning)
        
        # Target Configuration
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout(target_group)
        
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/app")
        url_layout.addWidget(self.url_input)
        target_layout.addLayout(url_layout)
        
        # Scan Options
        options_layout = QHBoxLayout()
        self.sql_injection = QCheckBox("SQL Injection")
        self.sql_injection.setChecked(True)
        self.xss_scan = QCheckBox("Cross-Site Scripting")
        self.xss_scan.setChecked(True)
        self.dir_traversal = QCheckBox("Directory Traversal")
        self.dir_traversal.setChecked(True)
        self.cmd_injection = QCheckBox("Command Injection")
        self.cmd_injection.setChecked(True)
        
        options_layout.addWidget(self.sql_injection)
        options_layout.addWidget(self.xss_scan)
        options_layout.addWidget(self.dir_traversal)
        options_layout.addWidget(self.cmd_injection)
        target_layout.addLayout(options_layout)
        
        layout.addWidget(target_group)
        
        # Control Buttons
        button_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Start Web Scan")
        self.scan_btn.setStyleSheet("background-color: #64C8FF; font-weight: bold;")
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.setEnabled(False)
        
        button_layout.addWidget(self.scan_btn)
        button_layout.addWidget(self.stop_btn)
        layout.addLayout(button_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results Table
        results_group = QGroupBox("Vulnerability Results")
        results_layout = QVBoxLayout(results_group)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["Type", "Severity", "URL", "Payload", "Evidence"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(self.results_table)
        
        layout.addWidget(results_group)
        
        # Summary
        summary_group = QGroupBox("Scan Summary")
        summary_layout = QVBoxLayout(summary_group)
        
        self.summary_text = QTextEdit()
        self.summary_text.setMaximumHeight(100)
        self.summary_text.setReadOnly(True)
        summary_layout.addWidget(self.summary_text)
        
        layout.addWidget(summary_group)
        
    def connect_signals(self):
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        web_scanner.scan_event.connect(self.handle_scan_event)
        
    def check_license(self):
        if license_manager.is_feature_enabled('web_scanner'):
            self.license_warning.hide()
            self.setEnabled(True)
        else:
            self.license_warning.show()
            self.setEnabled(False)
            
    def start_scan(self):
        if not license_manager.is_feature_enabled('web_scanner'):
            self.summary_text.append("❌ Web Scanner requires Professional license")
            return
            
        url = self.url_input.text().strip()
        if not url:
            self.summary_text.append("❌ Please enter a target URL")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        # Get selected scan types
        scan_types = []
        if self.sql_injection.isChecked():
            scan_types.append('sql_injection')
        if self.xss_scan.isChecked():
            scan_types.append('xss')
        if self.dir_traversal.isChecked():
            scan_types.append('directory_traversal')
        if self.cmd_injection.isChecked():
            scan_types.append('command_injection')
            
        if not scan_types:
            self.summary_text.append("❌ Please select at least one scan type")
            return
            
        # Start scan
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        self.results_table.setRowCount(0)
        self.summary_text.clear()
        self.summary_text.append(f"🚀 Starting web application scan of {url}")
        
        # Start worker thread
        self.scan_worker = WebScanWorker(url, scan_types)
        self.scan_worker.scan_completed.connect(self.handle_scan_completed)
        self.scan_worker.start()
        
    def stop_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.terminate()
            self.scan_worker.wait()
            
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.summary_text.append("🛑 Scan stopped by user")
        
    def handle_scan_event(self, event_type, message, data):
        if event_type == 'scan_progress':
            self.summary_text.append(f"📡 {message}")
        elif event_type == 'scan_started':
            self.summary_text.append(f"🎯 {message}")
        elif event_type == 'scan_completed':
            self.summary_text.append(f"✅ {message}")
            
    def handle_scan_completed(self, result):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        if 'error' in result:
            self.summary_text.append(f"❌ Scan failed: {result['error']}")
            return
            
        # Update results table
        vulnerabilities = result.get('vulnerabilities', [])
        self.results_table.setRowCount(len(vulnerabilities))
        
        for row, vuln in enumerate(vulnerabilities):
            # Type
            type_item = QTableWidgetItem(vuln['type'])
            self.results_table.setItem(row, 0, type_item)
            
            # Severity
            severity_item = QTableWidgetItem(vuln['severity'])
            if vuln['severity'] == 'Critical':
                severity_item.setForeground(QColor("#FF0000"))
            elif vuln['severity'] == 'High':
                severity_item.setForeground(QColor("#FF6B6B"))
            elif vuln['severity'] == 'Medium':
                severity_item.setForeground(QColor("#FFA500"))
            self.results_table.setItem(row, 1, severity_item)
            
            # URL
            url_item = QTableWidgetItem(vuln['url'][:50] + "..." if len(vuln['url']) > 50 else vuln['url'])
            self.results_table.setItem(row, 2, url_item)
            
            # Payload
            payload_item = QTableWidgetItem(vuln['payload'][:30] + "..." if len(vuln['payload']) > 30 else vuln['payload'])
            self.results_table.setItem(row, 3, payload_item)
            
            # Evidence
            evidence_item = QTableWidgetItem(vuln['evidence'][:40] + "..." if len(vuln['evidence']) > 40 else vuln['evidence'])
            self.results_table.setItem(row, 4, evidence_item)
            
        # Update summary
        total = result.get('total_vulnerabilities', 0)
        critical = result.get('critical', 0)
        high = result.get('high', 0)
        medium = result.get('medium', 0)
        
        self.summary_text.append(f"\n📊 Scan Results Summary:")
        self.summary_text.append(f"Total Vulnerabilities: {total}")
        self.summary_text.append(f"Critical: {critical} | High: {high} | Medium: {medium}")
        
        if total > 0:
            self.summary_text.append(f"⚠️ {total} vulnerabilities found - Review and remediate immediately!")
        else:
            self.summary_text.append(f"✅ No vulnerabilities detected in this scan")