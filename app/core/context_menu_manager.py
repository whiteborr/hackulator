# app/core/context_menu_manager.py
from PyQt6.QtWidgets import QMenu
from PyQt6.QtGui import QAction
from PyQt6.QtCore import QObject, pyqtSignal

class ContextMenuManager(QObject):
    """Manages context menus for various UI elements.
    
    Provides context menu creation and management for different types of UI widgets
    including terminal output, input fields, and results areas.
    
    Signals:
        copy_text (str): Emitted when text should be copied to clipboard
        clear_output (): Emitted when output should be cleared
        export_results (): Emitted when results should be exported
        save_to_file (str): Emitted when content should be saved to file
    """
    
    # Signals for menu actions
    copy_text = pyqtSignal(str)
    clear_output = pyqtSignal()
    export_results = pyqtSignal()
    save_to_file = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
    def create_terminal_menu(self, text_widget, selected_text=""):
        """Create context menu for terminal output areas.
        
        Args:
            text_widget (QWidget): The text widget to create menu for
            selected_text (str, optional): Currently selected text
            
        Returns:
            QMenu: Configured context menu for terminal output
        """
        menu = QMenu(text_widget)
        
        # Copy action (only if text is selected)
        if selected_text:
            copy_action = QAction("Copy", menu)
            copy_action.triggered.connect(lambda: self.copy_text.emit(selected_text))
            menu.addAction(copy_action)
            menu.addSeparator()
        
        # Select all action
        select_all_action = QAction("Select All", menu)
        select_all_action.triggered.connect(text_widget.selectAll)
        menu.addAction(select_all_action)
        
        menu.addSeparator()
        
        # Clear output action
        clear_action = QAction("Clear Output", menu)
        clear_action.triggered.connect(self.clear_output.emit)
        menu.addAction(clear_action)
        
        # Save output action
        save_action = QAction("Save Output to File", menu)
        save_action.triggered.connect(lambda: self.save_to_file.emit(text_widget.toPlainText()))
        menu.addAction(save_action)
        
        return menu
        
    def create_results_menu(self, results_widget, has_results=False):
        """Create context menu for results areas"""
        menu = QMenu(results_widget)
        
        if has_results:
            # Export actions
            export_action = QAction("Export Results", menu)
            export_action.triggered.connect(self.export_results.emit)
            menu.addAction(export_action)
            
            menu.addSeparator()
            
            # Copy results action
            copy_results_action = QAction("Copy All Results", menu)
            copy_results_action.triggered.connect(lambda: self.copy_text.emit(results_widget.toPlainText()))
            menu.addAction(copy_results_action)
            
            menu.addSeparator()
        
        # Clear results action
        clear_results_action = QAction("Clear Results", menu)
        clear_results_action.triggered.connect(self.clear_output.emit)
        menu.addAction(clear_results_action)
        
        return menu
        
    def create_input_menu(self, input_widget):
        """Create context menu for input fields.
        
        Args:
            input_widget (QWidget): The input widget to create menu for
            
        Returns:
            QMenu: Configured context menu for input fields
        """
        menu = QMenu(input_widget)
        
        # Standard edit actions
        if hasattr(input_widget, 'hasSelectedText') and input_widget.hasSelectedText():
            cut_action = QAction("Cut", menu)
            cut_action.triggered.connect(input_widget.cut)
            menu.addAction(cut_action)
            
            copy_action = QAction("Copy", menu)
            copy_action.triggered.connect(input_widget.copy)
            menu.addAction(copy_action)
            
            menu.addSeparator()
        
        # Paste action
        paste_action = QAction("Paste", menu)
        paste_action.triggered.connect(input_widget.paste)
        menu.addAction(paste_action)
        
        menu.addSeparator()
        
        # Select all action
        select_all_action = QAction("Select All", menu)
        select_all_action.triggered.connect(input_widget.selectAll)
        menu.addAction(select_all_action)
        
        # Clear action
        clear_action = QAction("Clear", menu)
        clear_action.triggered.connect(input_widget.clear)
        menu.addAction(clear_action)
        
        return menu