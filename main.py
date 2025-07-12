import sys
import os
import atexit
import signal
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFontDatabase
from app.main_window import MainWindow
from app.core.logger import logger
from app.core.config import config
from app.core.error_handler import setup_global_error_handling
from app.core.local_dns_server import local_dns_server
from app.core.vpn_manager import vpn_manager

def cleanup_on_exit():
    """Cleanup function called when application exits"""
    try:
        # Stop local DNS server if running
        if hasattr(local_dns_server, 'running') and local_dns_server.running:
            local_dns_server.stop_server()
            logger.info("Local DNS server stopped during cleanup")
        
        # Disconnect VPN if connected
        if hasattr(vpn_manager, 'is_connected') and vpn_manager.is_connected:
            vpn_manager.disconnect()
            logger.info("VPN disconnected during cleanup")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

def signal_handler(signum, frame):
    """Handle system signals for graceful shutdown"""
    logger.info(f"Received signal {signum}, initiating cleanup...")
    cleanup_on_exit()
    sys.exit(0)

def main():
    """
    The main entry point for the Hackulator application.
    """
    # Register cleanup function
    atexit.register(cleanup_on_exit)
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # --- Application Setup ---
    # This MUST be the first thing that happens.
    app = QApplication(sys.argv)
    
    # Setup global error handling
    setup_global_error_handling()

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