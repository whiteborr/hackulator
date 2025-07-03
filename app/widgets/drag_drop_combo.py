from PyQt6.QtWidgets import QComboBox
from PyQt6.QtCore import pyqtSignal

class DragDropComboBox(QComboBox):
    file_dropped = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)