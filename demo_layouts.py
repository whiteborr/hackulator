# demo_layouts.py
"""
Demo script to compare original fixed-geometry UI vs new layout-based UI
Run this to see both versions side by side or switch between them
"""
import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication, QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

# Add project root to path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

from app.core.error_handler import setup_global_exception_handler

class VersionSelector(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hackulator - Version Selector")
        self.setFixedSize(500, 300)
        self.selected_version = None
        
        # Apply dark theme
        self.setStyleSheet("""
            QDialog {
                background-color: #0A0A0A;
                color: #DCDCDC;
            }
            QLabel {
                color: #64C8FF;
                font-size: 14pt;
                font-weight: bold;
            }
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-size: 12pt;
                font-weight: bold;
                margin: 5px;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
            QPushButton:pressed {
                background-color: rgba(100, 200, 255, 100);
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title = QLabel("🛡️ Hackulator UI Comparison")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 18pt; margin-bottom: 20px;")
        layout.addWidget(title)
        
        # Description
        desc = QLabel("Choose which version to run:")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setStyleSheet("font-size: 12pt; color: #DCDCDC; margin-bottom: 10px;")
        layout.addWidget(desc)
        
        # Buttons
        button_layout = QVBoxLayout()
        
        # Original version button
        original_btn = QPushButton("🔧 Original Version (Fixed Geometry)")
        original_btn.clicked.connect(lambda: self.select_version("original"))
        button_layout.addWidget(original_btn)
        
        # Layout version button
        layout_btn = QPushButton("🎨 Layout Version (Responsive)")
        layout_btn.clicked.connect(lambda: self.select_version("layout"))
        button_layout.addWidget(layout_btn)
        
        # Comparison button
        compare_btn = QPushButton("⚖️ Run Both (Comparison)")
        compare_btn.clicked.connect(lambda: self.select_version("both"))
        button_layout.addWidget(compare_btn)
        
        layout.addLayout(button_layout)
        
        # Info text
        info_text = QLabel("""
        Original: Uses fixed positioning (.setGeometry(), .move())
        Layout: Uses dynamic layouts (QVBoxLayout, QHBoxLayout)
        Both: Opens both versions for side-by-side comparison
        """)
        info_text.setStyleSheet("font-size: 10pt; color: #888888; margin-top: 20px;")
        info_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(info_text)
        
    def select_version(self, version):
        self.selected_version = version
        self.accept()

def run_original_version():
    """Run the original fixed-geometry version"""
    from app.main_window import MainWindow
    
    window = MainWindow(project_root=project_root)
    window.setWindowTitle("Hackulator - Original (Fixed Geometry)")
    window.show()
    return window

def run_layout_version():
    """Run the new layout-based version"""
    from app.main_window_refactored import MainWindow
    
    window = MainWindow(project_root=project_root)
    window.setWindowTitle("Hackulator - Layout Version (Responsive)")
    window.show()
    return window

def main():
    app = QApplication(sys.argv)
    
    # Setup global error handling
    setup_global_exception_handler()
    
    # Load global stylesheet
    style_path = project_root / "resources" / "themes" / "default" / "style.qss"
    try:
        with open(style_path, "r") as f:
            app.setStyleSheet(f.read())
        print("Global stylesheet loaded successfully.")
    except FileNotFoundError:
        print(f"ERROR: Global stylesheet not found at {style_path}")
    
    # Show version selector
    selector = VersionSelector()
    if selector.exec() != QDialog.DialogCode.Accepted:
        return
    
    windows = []
    
    if selector.selected_version == "original":
        print("Starting original version...")
        windows.append(run_original_version())
        
    elif selector.selected_version == "layout":
        print("Starting layout version...")
        windows.append(run_layout_version())
        
    elif selector.selected_version == "both":
        print("Starting both versions for comparison...")
        
        # Run original version
        original_window = run_original_version()
        original_window.move(100, 100)  # Position on left
        windows.append(original_window)
        
        # Run layout version
        layout_window = run_layout_version()
        layout_window.move(800, 100)  # Position on right
        layout_window.resize(1000, 700)  # Make it smaller for comparison
        windows.append(layout_window)
        
        print("Both versions are now running side by side!")
        print("Original (left) vs Layout (right)")
    
    if not windows:
        print("No version selected, exiting...")
        return
    
    # Keep references to windows to prevent garbage collection
    app.windows = windows
    
    sys.exit(app.exec())

if __name__ == '__main__':
    main()