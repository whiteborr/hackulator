# app/widgets/memory_widget.py
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel, QProgressBar
from PyQt6.QtCore import QTimer
from app.core.memory_manager import memory_manager

class MemoryWidget(QWidget):
    """Widget to display memory usage"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Memory label
        self.memory_label = QLabel("Memory:")
        self.memory_label.setStyleSheet("color: #64C8FF; font-size: 10pt;")
        
        # Memory progress bar
        self.memory_bar = QProgressBar()
        self.memory_bar.setFixedSize(100, 15)
        self.memory_bar.setRange(0, 100)
        self.memory_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #555;
                border-radius: 3px;
                text-align: center;
                font-size: 8pt;
            }
            QProgressBar::chunk {
                background-color: #64C8FF;
                border-radius: 2px;
            }
        """)
        
        # Memory percentage label
        self.percent_label = QLabel("0%")
        self.percent_label.setStyleSheet("color: #DCDCDC; font-size: 10pt;")
        self.percent_label.setFixedWidth(30)
        
        layout.addWidget(self.memory_label)
        layout.addWidget(self.memory_bar)
        layout.addWidget(self.percent_label)
        
    def setup_timer(self):
        """Setup timer to update memory display"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_memory_display)
        self.timer.start(2000)  # Update every 2 seconds
        
    def update_memory_display(self):
        """Update memory usage display"""
        usage = memory_manager.get_memory_usage()
        self.memory_bar.setValue(int(usage))
        self.percent_label.setText(f"{usage:.0f}%")
        
        # Change color based on usage
        if usage > 80:
            color = "#FF4444"  # Red
        elif usage > 60:
            color = "#FFAA00"  # Orange
        else:
            color = "#64C8FF"  # Blue
            
        self.memory_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid #555;
                border-radius: 3px;
                text-align: center;
                font-size: 8pt;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 2px;
            }}
        """)