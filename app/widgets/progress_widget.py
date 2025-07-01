# app/widgets/progress_widget.py
from PyQt6.QtWidgets import QWidget, QProgressBar, QLabel, QVBoxLayout, QHBoxLayout
from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from datetime import datetime, timedelta

class ProgressWidget(QWidget):
    """Enhanced progress widget with ETA and statistics"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.start_time = None
        self.total_items = 0
        self.completed_items = 0
        self.results_found = 0
        
        self.setup_ui()
        
        # Timer for updating ETA
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(1000)  # Update every second
    
    def setup_ui(self):
        """Setup the progress widget UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(5)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #506478;
                border-radius: 8px;
                background-color: rgba(20, 30, 40, 180);
                text-align: center;
                font-size: 12pt;
                color: #DCDCDC;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00AA00, stop:1 #00FF41);
                border-radius: 7px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Statistics row
        stats_layout = QHBoxLayout()
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #64C8FF; font-size: 11pt; font-weight: bold;")
        
        self.eta_label = QLabel("ETA: --:--")
        self.eta_label.setStyleSheet("color: #DCDCDC; font-size: 11pt;")
        
        self.speed_label = QLabel("Speed: -- items/s")
        self.speed_label.setStyleSheet("color: #DCDCDC; font-size: 11pt;")
        
        self.results_label = QLabel("Found: 0")
        self.results_label.setStyleSheet("color: #00FF41; font-size: 11pt; font-weight: bold;")
        
        stats_layout.addWidget(self.status_label)
        stats_layout.addStretch()
        stats_layout.addWidget(self.results_label)
        stats_layout.addWidget(self.speed_label)
        stats_layout.addWidget(self.eta_label)
        
        layout.addLayout(stats_layout)
    
    def start_progress(self, total_items, status="Processing..."):
        """Start progress tracking"""
        self.total_items = total_items
        self.completed_items = 0
        self.results_found = 0
        self.start_time = datetime.now()
        
        self.progress_bar.setMaximum(total_items)
        self.progress_bar.setValue(0)
        self.status_label.setText(status)
        self.update_display()
    
    def update_progress(self, completed_items, results_found=None):
        """Update progress values"""
        self.completed_items = completed_items
        if results_found is not None:
            self.results_found = results_found
        
        self.progress_bar.setValue(completed_items)
        self.update_display()
    
    def increment_results(self):
        """Increment results counter"""
        self.results_found += 1
        self.results_label.setText(f"Found: {self.results_found}")
    
    def update_display(self):
        """Update ETA and speed calculations"""
        if not self.start_time or self.completed_items == 0:
            return
        
        elapsed = datetime.now() - self.start_time
        elapsed_seconds = elapsed.total_seconds()
        
        if elapsed_seconds > 0:
            # Calculate speed
            speed = self.completed_items / elapsed_seconds
            self.speed_label.setText(f"Speed: {speed:.1f} items/s")
            
            # Calculate ETA
            if speed > 0 and self.completed_items < self.total_items:
                remaining_items = self.total_items - self.completed_items
                eta_seconds = remaining_items / speed
                eta_time = datetime.now() + timedelta(seconds=eta_seconds)
                self.eta_label.setText(f"ETA: {eta_time.strftime('%H:%M:%S')}")
            else:
                self.eta_label.setText("ETA: Complete")
        
        # Update results counter
        self.results_label.setText(f"Found: {self.results_found}")
    
    def finish_progress(self, status="Complete"):
        """Finish progress tracking"""
        self.progress_bar.setValue(self.total_items)
        self.status_label.setText(status)
        self.eta_label.setText("ETA: Complete")
        
        if self.start_time:
            elapsed = datetime.now() - self.start_time
            elapsed_str = str(elapsed).split('.')[0]  # Remove microseconds
            self.speed_label.setText(f"Completed in: {elapsed_str}")
    
    def reset_progress(self):
        """Reset progress to initial state"""
        self.progress_bar.setValue(0)
        self.status_label.setText("Ready")
        self.eta_label.setText("ETA: --:--")
        self.speed_label.setText("Speed: -- items/s")
        self.results_label.setText("Found: 0")
        self.start_time = None
        self.completed_items = 0
        self.results_found = 0