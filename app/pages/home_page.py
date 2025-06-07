# app/pages/home_page.py
import logging
from PyQt6.QtWidgets import QWidget, QPushButton, QLabel, QTextEdit
from PyQt6.QtCore import pyqtSignal, QSize, Qt
from PyQt6.QtGui import QPixmap, QIcon, QFont

# ============================================================================
# Custom HoverButton Widget (for displaying info on hover)
# ============================================================================
class HoverButton(QPushButton):
    enter_signal = pyqtSignal(str, list)
    leave_signal = pyqtSignal()
    def __init__(self, title, description_lines, parent=None):
        super().__init__(parent)
        self.title = title
        self.description_lines = description_lines
    def enterEvent(self, event):
        super().enterEvent(event)
        self.enter_signal.emit(self.title, self.description_lines)
    def leaveEvent(self, event):
        super().leaveEvent(event)
        self.leave_signal.emit()

# ============================================================================
# The Main Home Page Widget
# ============================================================================
class HomePage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("HomePage")

        # --- UI Components ---
        self.background_label = QLabel(self)
        self.background_label.setScaledContents(True)

        # --- Info Panel Setup ---
        # Using the precise coordinates you captured.
        x = 340
        y = 175
        width = 1731 - x
        height = 770 - y
        
        self.info_panel = QTextEdit(self)
        self.info_panel.setObjectName("InfoPanel")
        self.info_panel.setReadOnly(True)
        self.info_panel.setGeometry(x, y, width, height)
        
        # --- Button Data and Creation ---
        # **FIX**: Using the precise coordinates you found with the helper tool.
        button_data = [
            {"name": "enumeration",   "title": "🛡️ ENUMERATION", "desc": ["Enumeration is the process of actively collecting information about a target system to identify potential entry points."], "center": (141, 178), "size": (127, 110), "icon": "resources/icons/1.png"},
            {"name": "vuln_scanning", "title": "🔍 VULN SCANNING", "desc": ["Identify known weaknesses in systems and services using automated tools."], "center": (141, 322), "size": (128, 108), "icon": "resources/icons/2.png"},
            {"name": "web_exploits",  "title": "💥 WEB EXPLOITS", "desc": ["Target vulnerabilities in web applications and client software."], "center": (141, 467), "size": (128, 108), "icon": "resources/icons/3.png"},
            {"name": "databases",     "title": "🗄️ DB ATTACKS", "desc": ["Exploit weaknesses in database queries and configurations."], "center": (141, 612), "size": (128, 108), "icon": "resources/icons/4.png"},
            {"name": "os_exploits",   "title": "🖥️ OS EXPLOITS", "desc": ["Leverage OS-level flaws for privilege escalation or persistence."], "center": (141, 756), "size": (128, 108), "icon": "resources/icons/5.png"},
            {"name": "cracking",      "title": "🔓 CRACKING", "desc": ["Break passwords by capturing and cracking authentication hashes."], "center": (141, 900), "size": (128, 108), "icon": "resources/icons/6.png"},
        ]
        
        self.nav_buttons = []
        for btn_info in button_data:
            icon_path = str(self.main_window.project_root / btn_info["icon"])
            button = HoverButton(btn_info["title"], btn_info["desc"], self)
            self.setup_icon_button(button, btn_info["center"], btn_info["size"], icon_path)
            button.clicked.connect(lambda checked, n=btn_info["name"]: self.navigate_signal.emit(n))
            button.enter_signal.connect(self.update_info_panel)
            button.leave_signal.connect(self.clear_info_panel)
            self.nav_buttons.append(button)

        self.apply_theme()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

    def setup_icon_button(self, button, center, size, icon_path):
        """Configures an icon button using fixed coordinates."""
        # **FIX**: Removed scaling logic. Using direct coordinates now.
        width, height = size
        cx, cy = center
        
        button.setGeometry(
            cx - width // 2, 
            cy - height // 2, 
            width, height
        )
        
        icon = QIcon(icon_path)
        if icon.isNull(): logging.warning(f"Could not load icon at {icon_path}")
        button.setIcon(icon)
        button.setIconSize(QSize(int(width * 0.9), int(height * 0.9)))
        
        border_radius = height // 2
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(0, 0, 0, 1);
                border: none;
                border-radius: {border_radius}px;
            }}
            QPushButton:hover {{
                background-color: rgba(255, 255, 255, 40);
            }}
        """)

    def apply_theme(self):
        """Sets the background image for this page."""
        theme = self.main_window.theme_manager
        background_path = theme.get("backgrounds.home")
        if background_path:
            self.background_label.setPixmap(QPixmap(background_path))

    def update_info_panel(self, title, description_lines):
        """Updates the info panel with formatted text when hovering."""
        desc_html = "<br>".join(description_lines)
        html_text = f"""
        <div style='color: #64C8FF; font-size: 22pt; font-weight: bold; padding-bottom: 20px;'>{title}</div>
        <div style='color: #DCDCDC; font-size: 16pt; line-height: 150%;'>{desc_html}</div>
        """
        self.info_panel.setHtml(html_text)
    
    def clear_info_panel(self):
        """Clears the info panel when the mouse leaves a button."""
        self.info_panel.clear()

    def resizeEvent(self, event):
        """Ensure the background always fills the page."""
        super().resizeEvent(event)
        self.background_label.setGeometry(0, 0, self.width(), self.height())
