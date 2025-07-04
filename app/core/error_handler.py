# app/core/error_handler.py
import sys
import traceback
import logging
from datetime import datetime
from PyQt6.QtWidgets import QMessageBox, QApplication

class GlobalErrorHandler:
    """Centralized error handling for the application"""
    
    def __init__(self, log_file="error.log"):
        self.log_file = log_file
        self.setup_logging()
    
    def setup_logging(self):
        """Setup error logging configuration"""
        logging.basicConfig(
            filename=self.log_file,
            level=logging.ERROR,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def handle_exception(self, exc_type, exc_value, exc_traceback):
        """Handle unhandled exceptions"""
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        # Log the error
        error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        logging.error(f"Unhandled exception:\n{error_msg}")
        
        # Show user-friendly dialog
        self.show_error_dialog(str(exc_value))
    
    def show_error_dialog(self, error_message):
        """Show user-friendly error dialog"""
        app = QApplication.instance()
        if app:
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Icon.Critical)
            msg_box.setWindowTitle("Unexpected Error")
            msg_box.setText("An unexpected error has occurred.")
            msg_box.setInformativeText(f"Error details have been logged to {self.log_file}")
            msg_box.setDetailedText(error_message)
            msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg_box.exec()

# Global instance
error_handler = GlobalErrorHandler()

def setup_global_error_handling():
    """Setup global error handling"""
    sys.excepthook = error_handler.handle_exception