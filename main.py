import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFontDatabase
from app.main_window_refactored import MainWindow
from app.core.logger import logger
from app.core.config import config

def main():
    """
    The main entry point for the Hackulator application.
    """
    # --- Application Setup ---
    # This MUST be the first thing that happens.
    app = QApplication(sys.argv)

    # --- Configuration and Logging ---
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    # --- Font Loading ---
    font_path = os.path.join(project_root, "resources", "fonts", "neuropol.otf")
    if os.path.exists(font_path):
        QFontDatabase.addApplicationFont(font_path)
    logger.info("Application starting...")

    # --- Stylesheet ---
    # Load stylesheet from theme configuration if available
    theme_path = os.path.join(project_root, "resources", "themes", "default", "style.qss")
    if os.path.exists(theme_path):
        with open(theme_path, 'r') as f:
            app.setStyleSheet(f.read())
        print("Global stylesheet loaded successfully.")

    # --- Main Window ---
    # Now that QApplication exists, we can create the window.
    print("Creating main window...")
    window = MainWindow(project_root=project_root)
    window.show()

    # --- Start Event Loop ---
    sys.exit(app.exec())

if __name__ == "__main__":
    main()