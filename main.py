# main.py
import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication
from app.main_window import MainWindow
from app.core.error_handler import setup_global_exception_handler

if __name__ == '__main__':
    try:
        app = QApplication(sys.argv)
        
        # Setup global error handling
        setup_global_exception_handler()
        
        project_root = Path(__file__).resolve().parent
        
        # Load the global stylesheet for controls (buttons, inputs, etc.)
        style_path = project_root / "resources" / "themes" / "default" / "style.qss"
        try:
            with open(style_path, "r") as f:
                app.setStyleSheet(f.read())
            print("Global stylesheet loaded successfully.")
        except FileNotFoundError:
            print(f"ERROR: Global stylesheet not found at {style_path}")

        print("Creating main window...")
        window = MainWindow(project_root=project_root)
        print("Showing main window...")
        window.show()
        print("Starting event loop...")
        sys.exit(app.exec())
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()