# app/pages/enumeration_page.py
import logging
import os
from PyQt6.QtWidgets import QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox
from PyQt6.QtCore import pyqtSignal, QSize, Qt
from PyQt6.QtGui import QPixmap, QIcon, QFont

# Import the new custom scripts module
from app.core import custom_scripts

# ============================================================================
# Custom HoverButton Widget (for displaying info on hover)
# ============================================================================
class HoverButton(QPushButton):
    """A custom QPushButton that emits signals on mouse enter and leave events."""
    enter_signal = pyqtSignal(str, str) # title, description
    leave_signal = pyqtSignal()

    def __init__(self, title, description, parent=None):
        super().__init__(parent)
        self.title = title
        self.description = description

    def enterEvent(self, event):
        """Called when the mouse enters the widget's area."""
        super().enterEvent(event)
        self.enter_signal.emit(self.title, self.description)

    def leaveEvent(self, event):
        """Called when the mouse leaves the widget's area."""
        super().leaveEvent(event)
        self.leave_signal.emit()

# ============================================================================
# The Main Enumeration Page Widget
# ============================================================================
class EnumerationPage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.is_submenu_active = False
        self.setObjectName("EnumerationPage")

        self.background_label = QLabel(self)
        self.background_label.setScaledContents(True)

        # --- Data for UI Elements ---
        main_tools_data = [
            {"id": "dns_enum", "title": "DNS Enumeration", "desc": "Discover domains, subdomains, and IPs.", "icon": "resources/icons/1A.png", "center": (49, 157), "size": (39, 59)},
            {"id": "port_scan", "title": "Port Scanning", "desc": "Identify open ports and services running.", "icon": "resources/icons/1B.png", "center": (49, 234), "size": (39, 59)},
            {"id": "smb_enum", "title": "SMB Enumeration", "desc": "List shares and users via Windows SMB.", "icon": "resources/icons/1C.png", "center": (49, 311), "size": (39, 59)},
            {"id": "smtp_enum", "title": "SMTP Enumeration", "desc": "Probe mail servers for valid emails.", "icon": "resources/icons/1D.png", "center": (49, 389), "size": (39, 59)},
            {"id": "snmp_enum", "title": "SNMP Enumeration", "desc": "Extract network device info using SNMP.", "icon": "resources/icons/1E.png", "center": (49, 468), "size": (39, 59)},
            {"id": "http_fingerprint", "title": "HTTP/S Fingerprinting", "desc": "Identify web server type and technologies.", "icon": "resources/icons/1F.png", "center": (49, 545), "size": (39, 59)},
            {"id": "api_enum", "title": "API Enumeration & Abuse", "desc": "Discover and misuse APIs for data.", "icon": "resources/icons/1G.png", "center": (49, 620), "size": (39, 59)},
            {"id": "db_enum", "title": "Database Enumeration", "desc": "Find databases, tables, and credentials.", "icon": "resources/icons/1H.png", "center": (49, 700), "size": (39, 59)},
            {"id": "contactless_info", "title": "Contactless Info Gathering", "desc": "Use NFC/RFID tools to gather wireless data.", "icon": "resources/icons/1I.png", "center": (49, 779), "size": (39, 59)},
            {"id": "av_detect", "title": "AV Detection", "desc": "Check which antivirus tools are active.", "icon": "resources/icons/1J.png", "center": (49, 857), "size": (39, 59)},
        ]
        
        self.dns_tools_data = [
            {"id": "dns_hosts",    "text": "HOSTS",    "rect": (135, 225, 105, 30)},
            {"id": "dns_ptr",      "text": "PTR",      "rect": (135, 283, 105, 30)},
            {"id": "dns_dnsrecon", "text": "DNSRecon", "rect": (135, 341, 105, 30)},
            {"id": "dns_dnsenum",  "text": "DNSEnum",  "rect": (135, 398, 105, 30)},
            {"id": "dns_xfer",     "text": "XFER",     "rect": (135, 458, 105, 30)},
            {"id": "dns_nslookup", "text": "NSLOOKUP", "rect": (135, 518, 105, 30)},
        ]

        # --- Create Main Menu Widgets ---
        self.main_title = QLabel("Enumeration Tools", self)
        self.main_title.setObjectName("TitleLabel")
        
        self.main_back_button = QPushButton("< Back", self)
        self.main_back_button.setProperty("class", "backButton")
        self.main_back_button.clicked.connect(lambda: self.navigate_signal.emit("home"))
        
        self.info_panel = QTextEdit(self)
        self.info_panel.setObjectName("InfoPanel")
        self.info_panel.setReadOnly(True)
        
        self.main_tool_buttons = []
        for tool in main_tools_data:
            button = HoverButton(tool["title"], tool["desc"], self)
            icon_path = str(self.main_window.project_root / tool["icon"])
            self.setup_icon_button(button, tool["center"], tool["size"], icon_path)

            if tool["id"] == "dns_enum":
                button.clicked.connect(lambda: self.set_submenu_active(True))
            
            button.enter_signal.connect(self.update_info_panel)
            button.leave_signal.connect(self.clear_info_panel)

            self.main_tool_buttons.append(button)

        self.main_widgets = [self.main_title, self.main_back_button, self.info_panel] + self.main_tool_buttons

        # --- Create DNS Sub-menu Widgets ---
        self.dns_back_button = QPushButton("< Back", self)
        self.dns_back_button.setProperty("class", "backButton")
        self.dns_back_button.clicked.connect(lambda: self.set_submenu_active(False))

        self.target_input = QLineEdit(self)
        self.target_input.setObjectName("TargetInput")
        self.target_input.setPlaceholderText("Enter target...")

        self.dns_terminal_output = QTextEdit(self)
        self.dns_terminal_output.setObjectName("InfoPanel")
        self.dns_terminal_output.setReadOnly(True)
        
        self.wordlist_combo = QComboBox(self)
        self.wordlist_combo.setProperty("class", "wordlistCombo")
        self.populate_wordlists()

        self.dns_tool_buttons = []
        for tool_data in self.dns_tools_data:
            button = QPushButton(tool_data["text"], self)
            button.setProperty("class", "dnsToolButton")
            if tool_data["id"] == "dns_hosts":
                button.clicked.connect(self.run_host_wordlist_scan)
            self.dns_tool_buttons.append(button)
        
        self.submenu_widgets = [self.dns_back_button, self.target_input, self.dns_terminal_output, self.wordlist_combo] + self.dns_tool_buttons
        
        # Position and set initial state
        self.resizeEvent(None) 
        self.set_submenu_active(False)
        self.apply_theme()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)


    def setup_icon_button(self, button, center, size, icon_path):
        """Helper function to configure an oval icon button with scaling."""
        new_size = self.main_window.size()
        original_size = self.main_window.original_size
        ws = new_size.width() / original_size.width()
        hs = new_size.height() / original_size.height()

        scaled_cx = int(center[0] * ws)
        scaled_cy = int(center[1] * hs)
        scaled_w = int(size[0] * ws)
        scaled_h = int(size[1] * hs)
        
        button.setGeometry(scaled_cx - scaled_w // 2, scaled_cy - scaled_h // 2, scaled_w, scaled_h)
        
        icon = QIcon(icon_path)
        if icon.isNull():
            logging.warning(f"Could not load icon at: {icon_path}")
        
        button.setIcon(icon)
        button.setIconSize(QSize(int(scaled_w * 0.9), int(scaled_h * 0.9)))
        
        border_radius = scaled_h // 2
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(0, 0, 0, 1);
                border: none;
                border-radius: {border_radius}px;
            }}
            QPushButton:hover {{
                background-color: rgba(255, 255, 255, 40);
                border-radius: {border_radius}px;
            }}
        """)

    def populate_wordlists(self):
        """Finds .txt files in the wordlists folder and adds them to the dropdown."""
        wordlist_dir = self.main_window.project_root / "resources" / "wordlists"
        if not os.path.isdir(wordlist_dir):
            logging.warning(f"Wordlist directory not found: {wordlist_dir}")
            return
        
        for filename in os.listdir(wordlist_dir):
            if filename.endswith(".txt"):
                full_path = os.path.join(wordlist_dir, filename)
                self.wordlist_combo.addItem(filename, full_path)

    def set_submenu_active(self, active):
        """Controls the visibility of widgets and changes the background skin."""
        self.is_submenu_active = active
        for widget in self.main_widgets:
            widget.setVisible(not active)
        for widget in self.submenu_widgets:
            widget.setVisible(active)
            
        if self.main_tool_buttons:
            dns_button = self.main_tool_buttons[0]
            dns_button.setVisible(True)

        self.update_background()

    def update_background(self):
        """Sets the pixmap on the background QLabel based on the current state."""
        theme = self.main_window.theme_manager
        
        if self.is_submenu_active:
            background_path = theme.get("backgrounds.enumeration_dns")
        else:
            background_path = theme.get("backgrounds.enumeration")
        
        if background_path:
            self.background_label.setPixmap(QPixmap(background_path))

    def apply_theme(self):
        self.update_background()

    def resizeEvent(self, event):
        """Reposition all widgets when the window is resized."""
        if event: 
            super().resizeEvent(event)
        
        self.background_label.setGeometry(0, 0, self.width(), self.height())
        
        new_size = self.main_window.size()
        original_size = self.main_window.original_size
        ws = new_size.width() / original_size.width()
        hs = new_size.height() / original_size.height()

        self.main_title.setGeometry(int(340 * ws), int(40 * hs), int(400 * ws), int(50 * hs))
        self.main_back_button.setGeometry(int(20 * ws), int(20 * hs), int(150 * ws), int(50 * hs))
        
        term_x = 340
        term_y = 175
        term_width = 1731 - term_x
        term_height = 770 - term_y
        self.info_panel.setGeometry(term_x, term_y, term_width, term_height)
        self.dns_terminal_output.setGeometry(term_x, term_y, term_width, term_height)

        self.dns_back_button.setGeometry(int(40 * ws), int(850 * hs), int(150 * ws), int(50 * hs))

        controls_y = term_y + term_height + 15
        padding = 10
        target_input_width = (term_width - padding) // 2
        wordlist_combo_width = target_input_width
        self.target_input.setGeometry(term_x, controls_y, target_input_width, 40)
        self.wordlist_combo.setGeometry(term_x + target_input_width + padding, controls_y, wordlist_combo_width, 40)
        
        for i, button in enumerate(self.dns_tool_buttons):
            x, y, w, h = self.dns_tools_data[i]["rect"]
            button.setGeometry(x, y, w, h)
            border_radius = h // 2
            button.setStyleSheet(f"""
                QPushButton {{
                    background-color: rgba(50, 60, 70, 180);
                    border: 2px solid #808080;
                    border-radius: {border_radius}px;
                    font-family: "Consolas", "Monaco", monospace;
                    font-size: 14pt;
                    color: #DCDCDC;
                }}
                QPushButton:hover {{
                    background-color: rgba(80, 100, 120, 200);
                    border: 2px solid #64C8FF;
                    border-radius: {border_radius}px;
                }}
            """)
        
    def update_info_panel(self, title, description):
        html_text = f"""
        <div style='color: #64C8FF; font-size: 22pt; font-weight: bold; padding-bottom: 20px;'>{title}</div>
        <div style='color: #DCDCDC; font-size: 16pt; font-family: "Neuropol";'>{description}</div>
        """
        self.info_panel.setHtml(html_text)
    
    def clear_info_panel(self):
        self.info_panel.clear()

    # --- Script Execution and UI Update Methods ---

    def run_host_wordlist_scan(self):
        """Handler for the 'HOSTS' button click."""
        target = self.target_input.text()
        wordlist_path = self.wordlist_combo.currentData()

        if not target:
            self.dns_terminal_output.setHtml("<p style='color: #FF4500;'>! Please enter a target first.</p>")
            return
        if not wordlist_path:
            self.dns_terminal_output.setHtml("<p style='color: #FF4500;'>! No wordlist selected or found.</p>")
            return
        
        self.dns_terminal_output.clear()
        self.dns_terminal_output.insertHtml(f"<p style='color: #64C8FF;'>&gt; Running HOSTS scan on {target}...</p><br>")
        
        self.set_buttons_enabled(False)

        custom_scripts.enumerate_hostnames(
            target=target, 
            wordlist_path=wordlist_path,
            output_callback=self.append_terminal_output,
            status_callback=self.update_status,
            finished_callback=self.on_script_finished
        )

    def append_terminal_output(self, text):
        """Appends a line of styled HTML text to the DNS terminal."""
        # The text coming from the worker is already formatted as HTML
        self.dns_terminal_output.insertHtml(text)
        self.dns_terminal_output.verticalScrollBar().setValue(self.dns_terminal_output.verticalScrollBar().maximum())

    def update_status(self, status_text):
        """(Placeholder) In a real app, you might have a status bar label to update."""
        print(f"STATUS: {status_text}")

    def on_script_finished(self):
        """Re-enables buttons after a script is finished."""
        self.set_buttons_enabled(True)
        self.append_terminal_output("<br><p style='color: #64C8FF;'>--- Scan Finished ---</p>")

    def set_buttons_enabled(self, enabled):
        """Enables or disables all tool buttons."""
        for button in self.dns_tool_buttons:
            button.setEnabled(enabled)
