# app/widgets/advanced_reporting_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QComboBox, QPushButton, QTextEdit, QGroupBox,
                            QCheckBox, QSpinBox, QProgressBar, QTabWidget,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QSplitter, QFrame)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QPixmap, QPainter, QColor
from datetime import datetime
import json
import os
import time

from app.core.advanced_reporting import advanced_reporting
from app.core.logger import logger

class ReportGenerationWorker(QThread):
    """Worker thread for report generation"""
    finished = pyqtSignal(bool, str, str)  # success, filepath, message
    progress = pyqtSignal(int)
    
    def __init__(self, scan_data, report_type, output_format, custom_template=None):
        super().__init__()
        self.scan_data = scan_data
        self.report_type = report_type
        self.output_format = output_format
        self.custom_template = custom_template
    
    def run(self):
        try:
            self.progress.emit(25)
            success, filepath, message = advanced_reporting.generate_comprehensive_report(
                self.scan_data, self.report_type, self.output_format, self.custom_template
            )
            self.progress.emit(100)
            self.finished.emit(success, filepath, message)
        except Exception as e:
            self.finished.emit(False, "", f"Report generation failed: {str(e)}")

class AdvancedReportingWidget(QWidget):
    """Advanced reporting interface widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_scan_data = {}
        self.report_history = []
        self.last_generated_report = None
        self.setup_ui()
        self.setup_connections()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Advanced Reporting Engine")
        title.setStyleSheet("")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Create tabs
        self.tab_widget = QTabWidget()
        
        # Report Generation Tab
        self.setup_generation_tab()
        
        # Report Templates Tab
        self.setup_templates_tab()
        
        # Report History Tab
        self.setup_history_tab()
        
        layout.addWidget(self.tab_widget)
    
    def setup_generation_tab(self):
        """Setup report generation tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Configuration section
        config_group = QGroupBox("Report Configuration")
        config_layout = QVBoxLayout(config_group)
        
        # Report type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Report Type:"))
        self.report_type_combo = QComboBox()
        self.report_type_combo.addItems([
            "Executive Summary",
            "Technical Detailed", 
            "Compliance Assessment",
            "Vulnerability Assessment",
            "Comparison Report"
        ])
        type_layout.addWidget(self.report_type_combo)
        type_layout.addStretch()
        config_layout.addLayout(type_layout)
        
        # Output format selection
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Output Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(["PDF", "HTML", "JSON"])
        format_layout.addWidget(self.format_combo)
        format_layout.addStretch()
        config_layout.addLayout(format_layout)
        
        # Advanced options
        options_layout = QHBoxLayout()
        self.include_charts = QCheckBox("Include Charts")
        self.include_recommendations = QCheckBox("Include Recommendations")
        self.include_compliance = QCheckBox("Include Compliance Check")
        self.include_charts.setChecked(True)
        self.include_recommendations.setChecked(True)
        options_layout.addWidget(self.include_charts)
        options_layout.addWidget(self.include_recommendations)
        options_layout.addWidget(self.include_compliance)
        options_layout.addStretch()
        config_layout.addLayout(options_layout)
        
        layout.addWidget(config_group)
        
        # Data source section
        data_group = QGroupBox("Data Source")
        data_layout = QVBoxLayout(data_group)
        
        # Current scan data display
        self.data_summary = QTextEdit()
        self.data_summary.setMaximumHeight(100)
        self.data_summary.setPlaceholderText("No scan data loaded. Run a scan first.")
        data_layout.addWidget(QLabel("Current Scan Data:"))
        data_layout.addWidget(self.data_summary)
        
        # Load data buttons
        button_layout = QHBoxLayout()
        self.load_current_btn = QPushButton("Use Current Scan")
        self.load_file_btn = QPushButton("Load from File")
        button_layout.addWidget(self.load_current_btn)
        button_layout.addWidget(self.load_file_btn)
        button_layout.addStretch()
        data_layout.addLayout(button_layout)
        
        layout.addWidget(data_group)
        
        # Generation section
        gen_group = QGroupBox("Generate Report")
        gen_layout = QVBoxLayout(gen_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        gen_layout.addWidget(self.progress_bar)
        
        # Generate/Open button (dual purpose)
        self.generate_btn = QPushButton("Generate Advanced Report")
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
        gen_layout.addWidget(self.generate_btn)
        
        # Track button state
        self.button_is_open_mode = False
        
        # Output display
        self.output_text = QTextEdit()
        self.output_text.setMaximumHeight(150)
        self.output_text.setPlaceholderText("Report generation output will appear here...")
        gen_layout.addWidget(QLabel("Output:"))
        gen_layout.addWidget(self.output_text)
        
        layout.addWidget(gen_group)
        
        self.tab_widget.addTab(tab, "Generate Report")
    
    def setup_templates_tab(self):
        """Setup report templates tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Template selection
        template_group = QGroupBox("Report Templates")
        template_layout = QVBoxLayout(template_group)
        
        # Template list
        self.template_combo = QComboBox()
        self.template_combo.addItems([
            "Standard Executive Report",
            "Technical Assessment Report", 
            "Compliance Audit Report",
            "Vulnerability Summary Report",
            "Custom Template"
        ])
        template_layout.addWidget(QLabel("Select Template:"))
        template_layout.addWidget(self.template_combo)
        
        # Template preview
        self.template_preview = QTextEdit()
        self.template_preview.setPlaceholderText("Template preview will appear here...")
        template_layout.addWidget(QLabel("Template Preview:"))
        template_layout.addWidget(self.template_preview)
        
        # Template actions
        template_actions = QHBoxLayout()
        self.preview_template_btn = QPushButton("Preview Template")
        self.customize_template_btn = QPushButton("Customize Template")
        self.save_template_btn = QPushButton("Save as New Template")
        template_actions.addWidget(self.preview_template_btn)
        template_actions.addWidget(self.customize_template_btn)
        template_actions.addWidget(self.save_template_btn)
        template_actions.addStretch()
        template_layout.addLayout(template_actions)
        
        layout.addWidget(template_group)
        
        self.tab_widget.addTab(tab, "Templates")
    
    def setup_history_tab(self):
        """Setup report history tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # History table
        history_group = QGroupBox("Report History")
        history_layout = QVBoxLayout(history_group)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Date", "Target", "Type", "Format", "Status", "File Path"
        ])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        history_layout.addWidget(self.history_table)
        
        # History actions
        history_actions = QHBoxLayout()
        self.refresh_history_btn = QPushButton("Refresh")
        self.open_report_btn = QPushButton("Open Report")
        self.delete_report_btn = QPushButton("Delete Report")
        history_actions.addWidget(self.refresh_history_btn)
        history_actions.addWidget(self.open_report_btn)
        history_actions.addWidget(self.delete_report_btn)
        history_actions.addStretch()
        history_layout.addLayout(history_actions)
        
        layout.addWidget(history_group)
        
        self.tab_widget.addTab(tab, "History")
    
    def setup_connections(self):
        """Setup signal connections"""
        self.generate_btn.clicked.connect(self.handle_main_button_click)
        self.load_current_btn.clicked.connect(self.load_current_scan)
        self.load_file_btn.clicked.connect(self.load_from_file)
        self.preview_template_btn.clicked.connect(self.preview_template)
        self.refresh_history_btn.clicked.connect(self.refresh_history)
        self.delete_report_btn.clicked.connect(self.delete_selected_report)
        
        # Auto-update data summary when combo changes
        self.report_type_combo.currentTextChanged.connect(self.update_template_preview)
    
    def load_scan_data(self, scan_data):
        """Load scan data from external source"""
        self.current_scan_data = scan_data
        self.update_data_summary()
    
    def update_data_summary(self):
        """Update the data summary display"""
        if not self.current_scan_data:
            self.data_summary.setText("No scan data loaded.")
            return
        
        summary = f"Target: {self.current_scan_data.get('target', 'Unknown')}\n"
        summary += f"Scan Type: {self.current_scan_data.get('scan_type', 'Unknown')}\n"
        summary += f"Results: {len(self.current_scan_data.get('results', {}))}\n"
        summary += f"Timestamp: {self.current_scan_data.get('timestamp', 'Unknown')}"
        
        self.data_summary.setText(summary)
    
    def load_current_scan(self):
        """Load current scan data (placeholder)"""
        # This would be connected to the main application's current scan data
        self.output_text.append("Loading current scan data...")
        # Placeholder data for demonstration
        self.current_scan_data = {
            'target': 'example.com',
            'scan_type': 'dns_enum',
            'results': {'example.com': {'A': ['1.2.3.4']}},
            'timestamp': datetime.now().isoformat()
        }
        self.update_data_summary()
        self.output_text.append("Current scan data loaded successfully.")
        self.reset_button_to_generate_mode()
    
    def load_from_file(self):
        """Load scan data from file"""
        from PyQt6.QtWidgets import QFileDialog, QMessageBox
        import json
        import time
        
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Scan Results File",
            "exports",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r') as f:
                file_data = json.load(f)
            
            # Extract scan data (handle different file formats)
            if 'results' in file_data:
                scan_data = file_data
            elif 'metadata' in file_data and 'results' in file_data:
                scan_data = {
                    'target': file_data['metadata']['scan_info'].get('target', 'Unknown'),
                    'scan_type': 'imported',
                    'results': file_data['results'],
                    'timestamp': file_data['metadata']['scan_info'].get('timestamp', time.strftime('%Y-%m-%d %H:%M:%S')),
                    'duration': 'Unknown'
                }
            else:
                # Assume it's raw results
                scan_data = {
                    'target': 'Imported Data',
                    'scan_type': 'imported',
                    'results': file_data,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'duration': 'Unknown'
                }
            
            self.load_scan_data(scan_data)
            self.output_text.append(f"Successfully loaded scan data from: {file_path}")
            self.reset_button_to_generate_mode()
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error Loading File",
                f"Failed to load scan results file:\n{str(e)}"
            )
            self.output_text.append(f"Error loading file: {str(e)}")
    
    def generate_report(self):
        """Generate the advanced report"""
        if not self.current_scan_data:
            self.output_text.append("ERROR: No scan data loaded. Please load scan data first.")
            return
        
        # Get configuration
        report_type = self.report_type_combo.currentText().lower().replace(' ', '_')
        output_format = self.format_combo.currentText().lower()
        
        # Create custom template based on options
        custom_template = {
            'include_charts': self.include_charts.isChecked(),
            'include_recommendations': self.include_recommendations.isChecked(),
            'include_compliance': self.include_compliance.isChecked()
        }
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.generate_btn.setEnabled(False)
        
        # Start generation worker
        self.worker = ReportGenerationWorker(
            self.current_scan_data, report_type, output_format, custom_template
        )
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_report_generated)
        self.worker.start()
        
        # Keep button in generate mode during generation
        
        self.output_text.append(f"Generating {report_type} report in {output_format} format...")
    
    def on_report_generated(self, success, filepath, message):
        """Handle report generation completion"""
        self.progress_bar.setVisible(False)
        self.generate_btn.setEnabled(True)
        
        # Debug output
        self.output_text.append(f"DEBUG: success={success}, filepath='{filepath}', message='{message}'")
        
        if success and filepath:
            self.output_text.append(f"SUCCESS: {message}")
            self.output_text.append(f"Report saved to: {filepath}")
            
            # Add to history
            self.add_to_history(filepath)
            
            # Switch button to open mode
            self.last_generated_report = filepath
            self.set_button_to_open_mode()
            
            self.output_text.append("Report generated successfully!")
        else:
            self.output_text.append(f"ERROR: {message}")
    
    def add_to_history(self, filepath):
        """Add report to history"""
        history_entry = {
            'date': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'target': self.current_scan_data.get('target', 'Unknown'),
            'type': self.report_type_combo.currentText(),
            'format': self.format_combo.currentText(),
            'status': 'Generated',
            'filepath': filepath
        }
        self.report_history.append(history_entry)
        self.refresh_history()
    
    def preview_template(self):
        """Preview selected template"""
        template_name = self.template_combo.currentText()
        preview_text = f"Template: {template_name}\n\n"
        
        if "Executive" in template_name:
            preview_text += "Executive Summary Template:\n"
            preview_text += "- Executive Overview\n"
            preview_text += "- Risk Assessment Summary\n"
            preview_text += "- Key Recommendations\n"
            preview_text += "- Business Impact Analysis"
        elif "Technical" in template_name:
            preview_text += "Technical Assessment Template:\n"
            preview_text += "- Detailed Findings\n"
            preview_text += "- Technical Analysis\n"
            preview_text += "- Vulnerability Details\n"
            preview_text += "- Remediation Steps"
        else:
            preview_text += "Standard template with comprehensive sections."
        
        self.template_preview.setText(preview_text)
    
    def update_template_preview(self):
        """Update template preview when report type changes"""
        self.preview_template()
    
    def refresh_history(self):
        """Refresh the history table"""
        self.history_table.setRowCount(len(self.report_history))
        
        for row, entry in enumerate(self.report_history):
            self.history_table.setItem(row, 0, QTableWidgetItem(entry['date']))
            self.history_table.setItem(row, 1, QTableWidgetItem(entry['target']))
            self.history_table.setItem(row, 2, QTableWidgetItem(entry['type']))
            self.history_table.setItem(row, 3, QTableWidgetItem(entry['format']))
            self.history_table.setItem(row, 4, QTableWidgetItem(entry['status']))
            self.history_table.setItem(row, 5, QTableWidgetItem(entry['filepath']))
    
    def open_selected_report(self):
        """Open the selected report"""
        current_row = self.history_table.currentRow()
        if current_row >= 0 and current_row < len(self.report_history):
            filepath = self.report_history[current_row]['filepath']
            try:
                os.startfile(filepath)  # Windows
            except:
                self.output_text.append(f"Could not open file: {filepath}")
    
    def delete_selected_report(self):
        """Delete the selected report"""
        from PyQt6.QtWidgets import QMessageBox
        
        current_row = self.history_table.currentRow()
        if current_row < 0 or current_row >= len(self.report_history):
            self.output_text.append("No report selected for deletion.")
            return
        
        report = self.report_history[current_row]
        filepath = report['filepath']
        
        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "Delete Report",
            f"Are you sure you want to delete this report?\n\n{os.path.basename(filepath)}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Delete the file
                if os.path.exists(filepath):
                    os.remove(filepath)
                
                # Remove from history
                self.report_history.pop(current_row)
                
                # Refresh the table
                self.refresh_history()
                
                self.output_text.append(f"Successfully deleted report: {os.path.basename(filepath)}")
                
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Delete Error",
                    f"Failed to delete report:\n{str(e)}"
                )
                self.output_text.append(f"Error deleting report: {str(e)}")
    
    def handle_main_button_click(self):
        """Handle main button click - either generate or open"""
        if self.button_is_open_mode:
            self.open_generated_report()
        else:
            self.generate_report()
    
    def set_button_to_open_mode(self):
        """Set button to open mode"""
        self.button_is_open_mode = True
        self.generate_btn.setText("Open Generated Report")
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
    
    def reset_button_to_generate_mode(self):
        """Reset button to generate mode"""
        self.button_is_open_mode = False
        self.generate_btn.setText("Generate Advanced Report")
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
            QPushButton:disabled {
                background-color: #95a5a6;
            }
        """)
    
    def open_generated_report(self):
        """Open the last generated report"""
        if not self.last_generated_report or not os.path.exists(self.last_generated_report):
            self.output_text.append("No report file found to open.")
            return
        
        try:
            import subprocess
            import platform
            
            if platform.system() == 'Windows':
                os.startfile(self.last_generated_report)
            elif platform.system() == 'Darwin':  # macOS
                subprocess.run(['open', self.last_generated_report])
            else:  # Linux
                subprocess.run(['xdg-open', self.last_generated_report])
            
            self.output_text.append(f"Opened report: {os.path.basename(self.last_generated_report)}")
        except Exception as e:
            self.output_text.append(f"Could not open report: {str(e)}")