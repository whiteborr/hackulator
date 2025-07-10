# app/widgets/stealth_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QComboBox, QPushButton, QSpinBox, QCheckBox,
                            QGroupBox, QSlider, QLineEdit, QTextEdit)
from PyQt6.QtCore import Qt, pyqtSignal
from app.core.stealth_engine import stealth_engine
from app.core.license_manager import license_manager

class StealthWidget(QWidget):
    """Stealth mode configuration widget"""
    
    stealth_configured = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.connect_signals()
        self.check_license()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Stealth Mode Configuration")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(header)
        
        # License warning
        self.license_warning = QLabel("⚠️ Stealth Mode requires Professional license")
        self.license_warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px;")
        layout.addWidget(self.license_warning)
        
        # Evasion Level
        evasion_group = QGroupBox("Evasion Level")
        evasion_layout = QVBoxLayout(evasion_group)
        
        self.evasion_combo = QComboBox()
        self.evasion_combo.addItems(["normal", "polite", "sneaky", "paranoid"])
        evasion_layout.addWidget(self.evasion_combo)
        
        # Descriptions
        descriptions = {
            "normal": "Standard timing (0.1-1s delay)",
            "polite": "Polite timing (1-3s delay)", 
            "sneaky": "Sneaky timing (2-8s delay)",
            "paranoid": "Paranoid timing (5-15s delay)"
        }
        
        self.description_label = QLabel(descriptions["normal"])
        evasion_layout.addWidget(self.description_label)
        
        layout.addWidget(evasion_group)
        
        # Decoy Configuration
        decoy_group = QGroupBox("Decoy IPs")
        decoy_layout = QVBoxLayout(decoy_group)
        
        self.enable_decoys = QCheckBox("Enable IP Decoys")
        decoy_layout.addWidget(self.enable_decoys)
        
        decoy_count_layout = QHBoxLayout()
        decoy_count_layout.addWidget(QLabel("Decoy Count:"))
        self.decoy_count = QSpinBox()
        self.decoy_count.setRange(1, 10)
        self.decoy_count.setValue(5)
        decoy_count_layout.addWidget(self.decoy_count)
        decoy_layout.addLayout(decoy_count_layout)
        
        self.decoy_input = QLineEdit()
        self.decoy_input.setPlaceholderText("Custom decoy IPs (comma-separated)")
        decoy_layout.addWidget(self.decoy_input)
        
        layout.addWidget(decoy_group)
        
        # Timing Controls
        timing_group = QGroupBox("Advanced Timing")
        timing_layout = QVBoxLayout(timing_group)
        
        # Scan delay
        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("Scan Delay (ms):"))
        self.scan_delay = QSpinBox()
        self.scan_delay.setRange(0, 10000)
        self.scan_delay.setValue(1000)
        delay_layout.addWidget(self.scan_delay)
        timing_layout.addLayout(delay_layout)
        
        # Max retries
        retry_layout = QHBoxLayout()
        retry_layout.addWidget(QLabel("Max Retries:"))
        self.max_retries = QSpinBox()
        self.max_retries.setRange(1, 10)
        self.max_retries.setValue(2)
        retry_layout.addWidget(self.max_retries)
        timing_layout.addLayout(retry_layout)
        
        layout.addWidget(timing_group)
        
        # Fragmentation
        frag_group = QGroupBox("Packet Fragmentation")
        frag_layout = QVBoxLayout(frag_group)
        
        self.enable_frag = QCheckBox("Enable Packet Fragmentation")
        frag_layout.addWidget(self.enable_frag)
        
        mtu_layout = QHBoxLayout()
        mtu_layout.addWidget(QLabel("MTU Size:"))
        self.mtu_size = QSpinBox()
        self.mtu_size.setRange(8, 1500)
        self.mtu_size.setValue(24)
        mtu_layout.addWidget(self.mtu_size)
        frag_layout.addLayout(mtu_layout)
        
        layout.addWidget(frag_group)
        
        # Control Buttons
        button_layout = QHBoxLayout()
        self.enable_btn = QPushButton("Enable Stealth Mode")
        self.disable_btn = QPushButton("Disable Stealth Mode")
        self.test_btn = QPushButton("Test Configuration")
        
        button_layout.addWidget(self.enable_btn)
        button_layout.addWidget(self.disable_btn)
        button_layout.addWidget(self.test_btn)
        layout.addLayout(button_layout)
        
        # Status
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(100)
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)
        
    def connect_signals(self):
        self.evasion_combo.currentTextChanged.connect(self.update_description)
        self.enable_btn.clicked.connect(self.enable_stealth)
        self.disable_btn.clicked.connect(self.disable_stealth)
        self.test_btn.clicked.connect(self.test_configuration)
        stealth_engine.stealth_event.connect(self.handle_stealth_event)
        
    def check_license(self):
        if license_manager.is_feature_enabled('stealth_mode'):
            self.license_warning.hide()
            self.setEnabled(True)
        else:
            self.license_warning.show()
            self.setEnabled(False)
            
    def update_description(self, level):
        descriptions = {
            "normal": "Standard timing (0.1-1s delay) - Fast but detectable",
            "polite": "Polite timing (1-3s delay) - Balanced approach", 
            "sneaky": "Sneaky timing (2-8s delay) - Slower but stealthier",
            "paranoid": "Paranoid timing (5-15s delay) - Maximum stealth"
        }
        self.description_label.setText(descriptions.get(level, ""))
        
    def enable_stealth(self):
        if not license_manager.is_feature_enabled('stealth_mode'):
            self.status_text.append("❌ Stealth Mode requires Professional license")
            return
            
        config = self.get_configuration()
        stealth_engine.enable_stealth_mode(config['evasion_level'])
        
        if config['enable_decoys']:
            if config['custom_decoys']:
                stealth_engine.decoy_ips = config['custom_decoys'].split(',')
            else:
                stealth_engine.generate_decoy_ips("192.168.1.1", config['decoy_count'])
                
        self.status_text.append("✅ Stealth Mode enabled")
        self.stealth_configured.emit(config)
        
    def disable_stealth(self):
        stealth_engine.stealth_enabled = False
        stealth_engine.decoy_ips = []
        self.status_text.append("🔓 Stealth Mode disabled")
        
    def test_configuration(self):
        config = self.get_configuration()
        self.status_text.append(f"🧪 Testing configuration: {config['evasion_level']} level")
        
        # Simulate timing test
        delay = stealth_engine.get_timing_delay(config['evasion_level'])
        self.status_text.append(f"⏱️ Timing delay: {delay:.2f}s")
        
        if config['enable_decoys']:
            self.status_text.append(f"🎭 Decoys: {config['decoy_count']} IPs")
            
    def get_configuration(self):
        return {
            'evasion_level': self.evasion_combo.currentText(),
            'enable_decoys': self.enable_decoys.isChecked(),
            'decoy_count': self.decoy_count.value(),
            'custom_decoys': self.decoy_input.text().strip(),
            'scan_delay': self.scan_delay.value(),
            'max_retries': self.max_retries.value(),
            'enable_fragmentation': self.enable_frag.isChecked(),
            'mtu_size': self.mtu_size.value()
        }
        
    def handle_stealth_event(self, event_type, message):
        self.status_text.append(f"📡 {message}")