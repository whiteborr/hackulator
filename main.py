# main.py
import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication
from app.main_window import MainWindow

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    project_root = Path(__file__).resolve().parent
    
    # Load the global stylesheet for controls (buttons, inputs, etc.)
    style_path = project_root / "resources" / "themes" / "default" / "style.qss"
    try:
        with open(style_path, "r") as f:
            app.setStyleSheet(f.read())
        print("Global stylesheet loaded successfully.")
    except FileNotFoundError:
        print(f"ERROR: Global stylesheet not found at {style_path}")

    window = MainWindow(project_root=project_root)
    window.show()
    sys.exit(app.exec())