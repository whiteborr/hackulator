# app/pages/running_scans_page.py
import time
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTableWidget, QTableWidgetItem, 
                            QHeaderView, QProgressBar, QTextEdit, QSplitter)
from PyQt6.QtCore import QTimer, pyqtSignal, Qt
from PyQt6.QtGui import QFont

from app.core.thread_manager import thread_manager
from app.core.unified_theme_manager import get_theme_manager
from app.core.scan_registry import scan_registry

class RunningScansPage(QWidget):
    """Page showing all currently running enumeration scans"""
    
    navigate_signal = pyqtSignal(str)
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.setup_ui()
        self.setup_timer()
        
        # Connect to scan registry signals
        scan_registry.scan_started.connect(self.on_scan_started)
        scan_registry.scan_updated.connect(self.on_scan_updated)
        scan_registry.scan_finished.connect(self.on_scan_finished)
        
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("Running Scans Monitor")
        title.setStyleSheet("""
            QLabel {
                font-size: 24pt;
                font-weight: bold;
                color: #64C8FF;
                margin-bottom: 10px;
            }
        """)
        layout.addWidget(title)
        
        # Description
        desc = QLabel("Monitor and control all active enumeration scans")
        desc.setStyleSheet("""
            QLabel {
                font-size: 12pt;
                color: #DCDCDC;
                margin-bottom: 20px;
            }
        """)
        layout.addWidget(desc)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        self.back_btn = QPushButton("← Back to Home")
        self.back_btn.clicked.connect(lambda: self.navigate_signal.emit("home"))
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_scans)
        
        self.stop_all_btn = QPushButton("Stop All Scans")
        self.stop_all_btn.clicked.connect(self.stop_all_scans)
        
        self.clear_btn = QPushButton("Clear Completed")
        self.clear_btn.clicked.connect(self.clear_completed_scans)
        
        control_layout.addWidget(self.back_btn)
        control_layout.addWidget(self.refresh_btn)
        control_layout.addWidget(self.stop_all_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addStretch()
        
        layout.addLayout(control_layout)
        
        # Create splitter for table and details
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Scans table
        self.scans_table = QTableWidget()
        self.setup_table()
        splitter.addWidget(self.scans_table)
        
        # Details panel
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        details_label = QLabel("Scan Details")
        details_label.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        details_layout.addWidget(details_label)
        
        self.details_text = QTextEdit()
        self.details_text.setMaximumHeight(200)
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        
        splitter.addWidget(details_widget)
        splitter.setSizes([400, 200])
        
        layout.addWidget(splitter)
        
        # Apply styling
        self.apply_styling()
        
    def setup_table(self):
        """Setup the scans table"""
        headers = ["Scan Type", "Target", "Status", "Progress", "Duration", "Details", "Actions"]
        self.scans_table.setColumnCount(len(headers))
        self.scans_table.setHorizontalHeaderLabels(headers)
        
        # Configure table
        header = self.scans_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Scan Type
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)           # Target
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Status
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)             # Progress
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Duration
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)           # Details
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)             # Actions
        
        # Set column widths
        self.scans_table.setColumnWidth(3, 120)  # Progress
        self.scans_table.setColumnWidth(6, 150)  # Actions
        
        # Connect selection change
        self.scans_table.itemSelectionChanged.connect(self.on_selection_changed)
        
    def setup_timer(self):
        """Setup refresh timer"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_display)
        self.timer.start(1000)  # Update every second
        
    def apply_styling(self):
        """Apply consistent styling"""
        self.setStyleSheet("""
            QWidget {
                background-color: #0A0A0A;
                color: #DCDCDC;
            }
            
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 11pt;
            }
            
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
            
            QPushButton:pressed {
                background-color: rgba(100, 200, 255, 100);
            }
            
            QPushButton:disabled {
                background-color: rgba(100, 100, 100, 100);
                color: #666666;
            }
            
            QTableWidget {
                background-color: rgba(20, 30, 40, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                gridline-color: rgba(100, 200, 255, 50);
                selection-background-color: rgba(100, 200, 255, 100);
            }
            
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid rgba(100, 200, 255, 30);
            }
            
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            
            QTextEdit {
                background-color: rgba(20, 30, 40, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 6px;
                padding: 10px;
                font-family: 'Consolas', 'Monaco', monospace;
            }
            
            QProgressBar {
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                text-align: center;
                background-color: rgba(50, 50, 50, 150);
            }
            
            QProgressBar::chunk {
                background-color: rgba(100, 200, 255, 200);
                border-radius: 3px;
            }
        """)
        
    def refresh_scans(self):
        """Refresh the scan list from scan registry"""
        all_scans = scan_registry.get_all_scans()
        active_scans = scan_registry.get_active_scans()
        
        self.update_display()
        self.status_updated.emit(f"Refreshed - {len(active_scans)} active scans, {len(all_scans)} total")
        
    def get_scan_type_from_thread_id(self, thread_id):
        """Extract scan type from thread ID"""
        if "dns" in thread_id.lower():
            return "DNS Enumeration"
        elif "port" in thread_id.lower():
            return "Port Scan"
        elif "smb" in thread_id.lower():
            return "SMB Enumeration"
        elif "smtp" in thread_id.lower():
            return "SMTP Enumeration"
        elif "snmp" in thread_id.lower():
            return "SNMP Enumeration"
        elif "http" in thread_id.lower():
            return "HTTP Fingerprinting"
        elif "api" in thread_id.lower():
            return "API Enumeration"
        elif "rpc" in thread_id.lower():
            return "RPC Enumeration"
        else:
            return thread_id.split('_')[0].upper() + " Scan"
    
    def update_display(self):
        """Update the table display"""
        all_scans = scan_registry.get_all_scans()
        self.scans_table.setRowCount(len(all_scans))
        
        for row, (scan_id, scan_item) in enumerate(all_scans.items()):
            # Scan Type
            self.scans_table.setItem(row, 0, QTableWidgetItem(scan_item.scan_type))
            
            # Target
            self.scans_table.setItem(row, 1, QTableWidgetItem(scan_item.target))
            
            # Status
            status_item = QTableWidgetItem(scan_item.status)
            if scan_item.status == "Running":
                status_item.setForeground(Qt.GlobalColor.green)
            elif scan_item.status == "Paused":
                status_item.setForeground(Qt.GlobalColor.yellow)
            elif scan_item.status == "Cancelled":
                status_item.setForeground(Qt.GlobalColor.red)
            else:
                status_item.setForeground(Qt.GlobalColor.gray)
            self.scans_table.setItem(row, 2, status_item)
            
            # Progress
            progress_widget = self.scans_table.cellWidget(row, 3)
            if not progress_widget:
                progress_widget = QProgressBar()
                self.scans_table.setCellWidget(row, 3, progress_widget)
            
            if scan_item.total_items > 0:
                progress = int((scan_item.completed_items / scan_item.total_items) * 100)
                progress_widget.setValue(progress)
                progress_widget.setFormat(f"{progress}% ({scan_item.completed_items}/{scan_item.total_items})")
            else:
                progress_widget.setRange(0, 0)  # Indeterminate progress
                progress_widget.setFormat("Running...")
            
            # Duration
            duration = time.time() - scan_item.start_time
            duration_str = self.format_duration(duration)
            self.scans_table.setItem(row, 4, QTableWidgetItem(duration_str))
            
            # Details
            self.scans_table.setItem(row, 5, QTableWidgetItem(scan_item.details))
            
            # Actions
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(2, 2, 2, 2)
            
            if scan_item.status == "Running":
                pause_btn = QPushButton("Pause")
                pause_btn.clicked.connect(lambda checked, sid=scan_id: self.pause_scan(sid))
                actions_layout.addWidget(pause_btn)
            elif scan_item.status == "Paused":
                resume_btn = QPushButton("Resume")
                resume_btn.clicked.connect(lambda checked, sid=scan_id: self.resume_scan(sid))
                actions_layout.addWidget(resume_btn)
            
            stop_btn = QPushButton("Stop")
            stop_btn.clicked.connect(lambda checked, sid=scan_id: self.stop_scan(sid))
            actions_layout.addWidget(stop_btn)
            
            self.scans_table.setCellWidget(row, 6, actions_widget)
    
    def format_duration(self, seconds):
        """Format duration in human readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    
    def pause_scan(self, scan_id):
        """Pause a specific scan"""
        if scan_registry.pause_scan(scan_id):
            self.status_updated.emit(f"Paused scan: {scan_id}")
        else:
            self.status_updated.emit(f"Failed to pause scan: {scan_id}")
    
    def resume_scan(self, scan_id):
        """Resume a paused scan"""
        if scan_registry.resume_scan(scan_id):
            self.status_updated.emit(f"Resumed scan: {scan_id}")
        else:
            self.status_updated.emit(f"Failed to resume scan: {scan_id}")
    
    def stop_scan(self, scan_id):
        """Stop a specific scan"""
        if scan_registry.stop_scan(scan_id):
            self.status_updated.emit(f"Stopped scan: {scan_id}")
        else:
            self.status_updated.emit(f"Failed to stop scan: {scan_id}")
    
    def stop_all_scans(self):
        """Stop all running scans"""
        stopped_count = scan_registry.stop_all_scans()
        self.status_updated.emit(f"Stopped {stopped_count} scans")
    
    def on_selection_changed(self):
        """Handle table selection change"""
        current_row = self.scans_table.currentRow()
        all_scans = scan_registry.get_all_scans()
        
        if current_row >= 0 and current_row < len(all_scans):
            scan_items = list(all_scans.values())
            if current_row < len(scan_items):
                scan_item = scan_items[current_row]
                
                # Show detailed information
                details = f"""
Scan ID: {scan_item.scan_id}
Type: {scan_item.scan_type}
Target: {scan_item.target}
Status: {scan_item.status}
Started: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_item.start_time))}
Duration: {self.format_duration(time.time() - scan_item.start_time)}

Progress: {scan_item.completed_items}/{scan_item.total_items} items
Details: {scan_item.details}

Thread Information:
- Thread ID: {scan_item.thread_id or 'N/A'}
- Current Status: {scan_item.status}
                """.strip()
                
                self.details_text.setPlainText(details)
    
    def on_scan_started(self, scan_id, scan_type, target):
        """Handle scan started signal"""
        self.update_display()
        self.status_updated.emit(f"Started: {scan_type} on {target}")
    
    def on_scan_updated(self, scan_id, completed_items):
        """Handle scan progress update"""
        self.update_display()
    
    def on_scan_finished(self, scan_id, status):
        """Handle scan finished signal"""
        self.update_display()
        self.status_updated.emit(f"Scan finished: {scan_id} - {status}")
    
    def clear_completed_scans(self):
        """Remove completed scans from the registry"""
        cleared_count = scan_registry.cleanup_finished_scans(max_age_seconds=60)
        self.update_display()
        self.status_updated.emit(f"Cleared {cleared_count} completed scans")