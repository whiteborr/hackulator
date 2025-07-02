# app/core/error_handler.py
import sys
import traceback
from PyQt6.QtWidgets import QMessageBox
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger

class GlobalErrorHandler(QObject):
    error_occurred = pyqtSignal(str, str)  # title, message
    
    def __init__(self):
        super().__init__()
        self.error_occurred.connect(self.show_error_dialog)
    
    def handle_exception(self, exc_type, exc_value, exc_traceback):
        """Handle uncaught exceptions"""
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        logger.error(f"Uncaught exception: {error_msg}")
        
        # Emit signal to show user-friendly error
        self.error_occurred.emit(
            "Application Error",
            f"An unexpected error occurred:\n{exc_value}\n\nThe error has been logged."
        )
    
    def show_error_dialog(self, title, message):
        """Show error dialog to user"""
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Icon.Critical)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()

# Global instance
error_handler = GlobalErrorHandler()

def setup_global_exception_handler():
    """Setup global exception handler"""
    sys.excepthook = error_handler.handle_exception