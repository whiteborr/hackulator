# status_demo.py - Simple demo of status bar communication
import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QPushButton, QVBoxLayout, QStatusBar
from PyQt6.QtCore import pyqtSignal

class DemoPage(QWidget):
    status_updated = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        
        # Demo buttons that emit status updates
        btn1 = QPushButton("Start Scan")
        btn1.clicked.connect(lambda: self.status_updated.emit("Scanning target..."))
        
        btn2 = QPushButton("Export Results")
        btn2.clicked.connect(lambda: self.status_updated.emit("Exporting to CSV..."))
        
        btn3 = QPushButton("Clear Status")
        btn3.clicked.connect(lambda: self.status_updated.emit("Ready"))
        
        layout.addWidget(btn1)
        layout.addWidget(btn2)
        layout.addWidget(btn3)

class DemoMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Status Bar Demo")
        self.setGeometry(300, 300, 400, 200)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Create demo page
        self.demo_page = DemoPage()
        self.setCentralWidget(self.demo_page)
        
        # Connect status signal
        self.demo_page.status_updated.connect(self.update_status_bar)
    
    def update_status_bar(self, message):
        """Handler for status updates"""
        self.status_bar.showMessage(message)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = DemoMainWindow()
    window.show()
    sys.exit(app.exec())