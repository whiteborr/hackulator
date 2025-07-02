# app/widgets/scan_control_widget.py
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QPushButton, QLabel
from PyQt6.QtCore import Qt
from app.core.scan_controller import ScanController

class ScanControlWidget(QWidget):
    """Widget with pause/resume/stop controls"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_controller = ScanController()
        self.setup_ui()
        self.scan_controller.status_changed.connect(self.update_buttons)
        
    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt;")
        
        # Control buttons
        self.pause_btn = QPushButton("⏸️ Pause")
        self.pause_btn.setFixedSize(70, 25)
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.pause_btn.setEnabled(False)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.setFixedSize(60, 25)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        
        # Style buttons
        button_style = """
            QPushButton {
                background-color: rgba(100, 100, 100, 150);
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 9pt;
            }
            QPushButton:hover {
                background-color: rgba(120, 120, 120, 200);
            }
            QPushButton:disabled {
                background-color: rgba(60, 60, 60, 100);
                color: #888;
            }
        """
        self.pause_btn.setStyleSheet(button_style)
        self.stop_btn.setStyleSheet(button_style)
        
        layout.addWidget(self.status_label)
        layout.addStretch()
        layout.addWidget(self.pause_btn)
        layout.addWidget(self.stop_btn)
        
    def start_scan(self):
        """Start a new scan"""
        self.scan_controller.start()
        
    def toggle_pause(self):
        """Toggle pause/resume"""
        if self.scan_controller.is_paused:
            self.scan_controller.resume()
        else:
            self.scan_controller.pause()
            
    def stop_scan(self):
        """Stop current scan"""
        self.scan_controller.stop()
        
    def update_buttons(self, status):
        """Update button states based on scan status"""
        if status == "running":
            self.status_label.setText("Running")
            self.pause_btn.setText("⏸️ Pause")
            self.pause_btn.setEnabled(True)
            self.stop_btn.setEnabled(True)
        elif status == "paused":
            self.status_label.setText("Paused")
            self.pause_btn.setText("▶️ Resume")
            self.pause_btn.setEnabled(True)
            self.stop_btn.setEnabled(True)
        else:  # stopped
            self.status_label.setText("Ready")
            self.pause_btn.setText("⏸️ Pause")
            self.pause_btn.setEnabled(False)
            self.stop_btn.setEnabled(False)