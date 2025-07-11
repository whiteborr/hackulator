# app/widgets/enhanced_help_panel.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTextEdit, QTabWidget, QScrollArea,
                             QFrame, QSplitter)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap, QIcon

class EnhancedHelpPanel(QWidget):
    """Enhanced help panel with tool-specific documentation"""
    
    closed = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Hackulator Help")
        self.setWindowFlags(Qt.WindowType.Window)
        self.resize(1000, 700)
        
        self.setup_ui()
        self.load_help_content()
        
    def setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        
        title_label = QLabel("Hackulator Help & Documentation")
        title_label.setStyleSheet("font-size: 18pt; font-weight: bold; color: #64C8FF;")
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        header_layout.addWidget(close_button)
        
        layout.addLayout(header_layout)
        
        # Main content area
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Tool list
        self.tool_list = QWidget()
        self.tool_list.setFixedWidth(250)
        self.setup_tool_list()
        splitter.addWidget(self.tool_list)
        
        # Right panel - Help content
        self.help_tabs = QTabWidget()
        self.setup_help_tabs()
        splitter.addWidget(self.help_tabs)
        
        layout.addWidget(splitter)
        
    def setup_tool_list(self):
        """Setup the tool list"""
        layout = QVBoxLayout(self.tool_list)
        
        list_label = QLabel("Tools")
        list_label.setStyleSheet("font-size: 14pt; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(list_label)
        
        # Tool buttons
        tools = [
            ("DNS Enumeration", "dns"),
            ("Port Scanning", "port"),
            ("SMB Enumeration", "smb"),
            ("SMTP Enumeration", "smtp"),
            ("SNMP Enumeration", "snmp"),
            ("HTTP Enumeration", "http"),
            ("API Enumeration", "api"),
            ("RPC Enumeration", "rpc"),
            ("LDAP Enumeration", "ldap"),
            ("Database Enumeration", "db")
        ]
        
        for tool_name, tool_id in tools:
            button = QPushButton(tool_name)
            button.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    padding: 8px;
                    border: 1px solid #444;
                    background-color: #2a2a2a;
                    color: #FFFFFF;
                }
                QPushButton:hover {
                    background-color: #3a3a3a;
                    border-color: #64C8FF;
                }
                QPushButton:pressed {
                    background-color: #1a1a1a;
                }
            """)
            button.clicked.connect(lambda checked, tid=tool_id: self.show_tool_help(tid))
            layout.addWidget(button)
        
        layout.addStretch()
        
    def setup_help_tabs(self):
        """Setup help content tabs"""
        # Overview tab
        overview_widget = QScrollArea()
        overview_content = QTextEdit()
        overview_content.setReadOnly(True)
        overview_content.setHtml(self.get_overview_content())
        overview_widget.setWidget(overview_content)
        self.help_tabs.addTab(overview_widget, "Overview")
        
        # Tool Help tab
        self.tool_help_widget = QScrollArea()
        self.tool_help_content = QTextEdit()
        self.tool_help_content.setReadOnly(True)
        self.tool_help_widget.setWidget(self.tool_help_content)
        self.help_tabs.addTab(self.tool_help_widget, "Tool Help")
        
        # Keyboard Shortcuts tab
        shortcuts_widget = QScrollArea()
        shortcuts_content = QTextEdit()
        shortcuts_content.setReadOnly(True)
        shortcuts_content.setHtml(self.get_shortcuts_content())
        shortcuts_widget.setWidget(shortcuts_content)
        self.help_tabs.addTab(shortcuts_widget, "Shortcuts")
        
        # Tips & Tricks tab
        tips_widget = QScrollArea()
        tips_content = QTextEdit()
        tips_content.setReadOnly(True)
        tips_content.setHtml(self.get_tips_content())
        tips_widget.setWidget(tips_content)
        self.help_tabs.addTab(tips_widget, "Tips & Tricks")
        
    def load_help_content(self):
        """Load help content"""
        self.help_data = {
            "dns": {
                "title": "DNS Enumeration",
                "description": "Comprehensive DNS reconnaissance and subdomain discovery",
                "features": [
                    "Subdomain enumeration with wordlists",
                    "Bruteforce subdomain discovery",
                    "Multiple DNS record types (A, CNAME, MX, TXT, NS, SRV)",
                    "PTR record enumeration for IP ranges",
                    "Zone transfer attempts",
                    "Custom DNS server support"
                ],
                "usage": [
                    "1. Enter target domain (e.g., example.com)",
                    "2. Select record types to query",
                    "3. Choose enumeration method (Wordlist or Bruteforce)",
                    "4. Configure DNS server (optional)",
                    "5. Click Run to start enumeration"
                ],
                "tips": [
                    "Use different wordlists for different target types",
                    "PTR enumeration works best with IP ranges",
                    "SRV records reveal service information",
                    "Zone transfers are rare but valuable"
                ]
            },
            "port": {
                "title": "Port Scanning",
                "description": "Network port discovery and service identification",
                "features": [
                    "TCP connect and SYN stealth scans",
                    "UDP port scanning",
                    "Service version detection",
                    "OS fingerprinting",
                    "Network sweep capabilities",
                    "Custom port ranges"
                ],
                "usage": [
                    "1. Enter target IP or range",
                    "2. Select scan type",
                    "3. Configure port range",
                    "4. Enable additional options (OS/Service detection)",
                    "5. Start scan"
                ],
                "tips": [
                    "SYN scans are stealthier but require privileges",
                    "UDP scans take longer but find different services",
                    "Service detection provides valuable information",
                    "Use timing options to avoid detection"
                ]
            },
            "smb": {
                "title": "SMB Enumeration",
                "description": "Windows SMB/NetBIOS service enumeration",
                "features": [
                    "Share enumeration and permissions",
                    "OS and version detection",
                    "NetBIOS information gathering",
                    "Vulnerability scanning (MS17-010, etc.)",
                    "Anonymous and authenticated access",
                    "Domain information extraction"
                ],
                "usage": [
                    "1. Enter target IP or hostname",
                    "2. Select scan type",
                    "3. Configure authentication (if needed)",
                    "4. Run enumeration"
                ],
                "tips": [
                    "Try anonymous access first",
                    "Check for null sessions",
                    "Look for writable shares",
                    "Enumerate users and groups when possible"
                ]
            }
        }
        
    def show_tool_help(self, tool_id):
        """Show help for specific tool"""
        if tool_id in self.help_data:
            help_info = self.help_data[tool_id]
            
            html_content = f"""
            <h2 style="color: #64C8FF;">{help_info['title']}</h2>
            <p style="font-size: 12pt; margin-bottom: 20px;">{help_info['description']}</p>
            
            <h3 style="color: #87CEEB;">Features</h3>
            <ul>
            """
            
            for feature in help_info['features']:
                html_content += f"<li>{feature}</li>"
            
            html_content += """
            </ul>
            
            <h3 style="color: #87CEEB;">Usage</h3>
            <ol>
            """
            
            for step in help_info['usage']:
                html_content += f"<li>{step}</li>"
            
            html_content += """
            </ol>
            
            <h3 style="color: #87CEEB;">Tips</h3>
            <ul>
            """
            
            for tip in help_info['tips']:
                html_content += f"<li>{tip}</li>"
            
            html_content += "</ul>"
            
            self.tool_help_content.setHtml(html_content)
            self.help_tabs.setCurrentIndex(1)  # Switch to Tool Help tab
        
    def get_overview_content(self):
        """Get overview content"""
        return """
        <h2 style="color: #64C8FF;">Hackulator Overview</h2>
        <p>Hackulator is a comprehensive penetration testing toolkit with advanced enumeration capabilities.</p>
        
        <h3 style="color: #87CEEB;">Main Features</h3>
        <ul>
            <li><strong>DNS Enumeration:</strong> Subdomain discovery and DNS reconnaissance</li>
            <li><strong>Port Scanning:</strong> Network service discovery and identification</li>
            <li><strong>SMB Enumeration:</strong> Windows share and service enumeration</li>
            <li><strong>SMTP Enumeration:</strong> Email server user enumeration</li>
            <li><strong>SNMP Enumeration:</strong> Network device information gathering</li>
            <li><strong>HTTP Enumeration:</strong> Web server fingerprinting and directory discovery</li>
            <li><strong>API Enumeration:</strong> REST API endpoint discovery</li>
            <li><strong>Advanced Reporting:</strong> Professional PDF and HTML reports</li>
        </ul>
        
        <h3 style="color: #87CEEB;">Getting Started</h3>
        <ol>
            <li>Select an enumeration tool from the left panel</li>
            <li>Enter your target (IP, domain, or range)</li>
            <li>Configure scan options</li>
            <li>Click Run to start the scan</li>
            <li>Export results when complete</li>
        </ol>
        
        <h3 style="color: #87CEEB;">Best Practices</h3>
        <ul>
            <li>Always ensure you have permission to scan targets</li>
            <li>Start with passive reconnaissance</li>
            <li>Use appropriate timing to avoid detection</li>
            <li>Document all findings thoroughly</li>
            <li>Verify results with multiple tools</li>
        </ul>
        """
        
    def get_shortcuts_content(self):
        """Get keyboard shortcuts content"""
        return """
        <h2 style="color: #64C8FF;">Keyboard Shortcuts</h2>
        
        <h3 style="color: #87CEEB;">Global Shortcuts</h3>
        <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
            <tr style="background-color: #2a2a2a;">
                <th>Shortcut</th>
                <th>Action</th>
            </tr>
            <tr><td>F1</td><td>Show this help panel</td></tr>
            <tr><td>F5</td><td>Run current scan</td></tr>
            <tr><td>F11</td><td>Toggle fullscreen</td></tr>
            <tr><td>Ctrl+E</td><td>Export results</td></tr>
            <tr><td>Ctrl+L</td><td>Clear output</td></tr>
            <tr><td>Ctrl+M</td><td>Minimize to tray</td></tr>
            <tr><td>Ctrl+Q</td><td>Quit application</td></tr>
            <tr><td>Ctrl+T</td><td>Open theme selector</td></tr>
            <tr><td>Escape</td><td>Go back/Cancel</td></tr>
        </table>
        
        <h3 style="color: #87CEEB;">Enumeration Shortcuts</h3>
        <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
            <tr style="background-color: #2a2a2a;">
                <th>Shortcut</th>
                <th>Action</th>
            </tr>
            <tr><td>Enter</td><td>Start scan (when in input field)</td></tr>
            <tr><td>Ctrl+Shift+R</td><td>Show running scans</td></tr>
            <tr><td>Ctrl+Shift+S</td><td>Open session manager</td></tr>
            <tr><td>Ctrl+R</td><td>Generate reports</td></tr>
        </table>
        """
        
    def get_tips_content(self):
        """Get tips and tricks content"""
        return """
        <h2 style="color: #64C8FF;">Tips & Tricks</h2>
        
        <h3 style="color: #87CEEB;">DNS Enumeration Tips</h3>
        <ul>
            <li><strong>Wordlist Selection:</strong> Use targeted wordlists for better results</li>
            <li><strong>Bruteforce Length:</strong> Start with 3-4 characters, increase if needed</li>
            <li><strong>Record Types:</strong> Always check SRV records for service discovery</li>
            <li><strong>PTR Records:</strong> Use IP ranges like 192.168.1.0 for reverse lookups</li>
        </ul>
        
        <h3 style="color: #87CEEB;">Port Scanning Tips</h3>
        <ul>
            <li><strong>Scan Types:</strong> Use SYN scans for stealth, TCP connect for reliability</li>
            <li><strong>Timing:</strong> Slower scans avoid detection but take longer</li>
            <li><strong>UDP Scanning:</strong> Takes time but finds different services</li>
            <li><strong>Service Detection:</strong> Provides valuable version information</li>
        </ul>
        
        <h3 style="color: #87CEEB;">SMB Enumeration Tips</h3>
        <ul>
            <li><strong>Anonymous Access:</strong> Try null sessions first</li>
            <li><strong>Share Permissions:</strong> Look for writable shares</li>
            <li><strong>Vulnerabilities:</strong> Check for MS17-010 and other SMB exploits</li>
            <li><strong>Domain Info:</strong> Extract user and group information</li>
        </ul>
        
        <h3 style="color: #87CEEB;">General Tips</h3>
        <ul>
            <li><strong>Multiple Views:</strong> Use text, graph, and table views for different perspectives</li>
            <li><strong>Export Options:</strong> Choose appropriate format for your needs</li>
            <li><strong>Session Management:</strong> Organize scans by project or target</li>
            <li><strong>Advanced Reporting:</strong> Generate professional reports for clients</li>
            <li><strong>Themes:</strong> Customize the interface to your preference</li>
        </ul>
        
        <h3 style="color: #87CEEB;">Performance Tips</h3>
        <ul>
            <li><strong>Threading:</strong> Adjust thread count based on target capacity</li>
            <li><strong>Timeouts:</strong> Increase timeouts for slow networks</li>
            <li><strong>Rate Limiting:</strong> Use slower rates to avoid detection</li>
            <li><strong>Memory Usage:</strong> Monitor memory usage during large scans</li>
        </ul>
        """
        
    def closeEvent(self, event):
        """Handle close event"""
        self.closed.emit()
        event.accept()