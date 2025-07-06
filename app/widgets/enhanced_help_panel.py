# app/widgets/enhanced_help_panel.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTextEdit, QComboBox)
from PyQt6.QtCore import Qt

class EnhancedHelpPanel(QWidget):
    """Enhanced help panel with detailed tool information and examples"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_tool = None
        self.setup_ui()
        self.setup_tool_data()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header with tool selector
        header_layout = QHBoxLayout()
        header = QLabel("🛠️ Tool Help & Documentation")
        header.setStyleSheet("color: #64C8FF; font-size: 14pt; font-weight: bold;")
        
        self.tool_selector = QComboBox()
        self.tool_selector.setStyleSheet("""
            QComboBox {
                background-color: rgba(50, 50, 50, 150);
                color: #DCDCDC;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 5px;
                min-width: 150px;
            }
        """)
        self.tool_selector.currentTextChanged.connect(self.on_tool_changed)
        
        header_layout.addWidget(header)
        header_layout.addStretch()
        header_layout.addWidget(QLabel("Select Tool:"))
        header_layout.addWidget(self.tool_selector)
        
        # Main content area
        self.content_area = QTextEdit()
        self.content_area.setReadOnly(True)
        self.content_area.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 5px;
                color: #DCDCDC;
                font-size: 11pt;
                padding: 10px;
            }
        """)
        
        # Close button
        close_layout = QHBoxLayout()
        close_button = QPushButton("✖️ Close")
        close_button.clicked.connect(self.hide)
        close_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 100, 100, 150);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: rgba(255, 100, 100, 200);
            }
        """)
        
        close_layout.addStretch()
        close_layout.addWidget(close_button)
        
        layout.addLayout(header_layout)
        layout.addWidget(self.content_area)
        layout.addLayout(close_layout)
        
    def setup_tool_data(self):
        """Setup comprehensive tool information"""
        self.tool_data = {
            "DNS Enumeration": {
                "purpose": "Discover subdomains, DNS records, and perform zone transfers",
                "use_cases": [
                    "Subdomain discovery for attack surface mapping",
                    "DNS record enumeration (A, CNAME, MX, TXT, NS)",
                    "Reverse DNS lookups for IP ranges",
                    "Zone transfer attempts",
                    "Wildcard DNS detection"
                ],
                "commands": [
                    "dnsrecon -d example.com -t std",
                    "dnsrecon -d example.com -D subdomain_list.txt -t brt",
                    "dnsenum example.com",
                    "dig axfr domain.com @<DNS IP>",
                    "for ip in $(cat wordlist.txt); do host $ip.example.com; done"
                ],
                "options": {
                    "Record Types": "A, AAAA, CNAME, MX, TXT, NS, PTR",
                    "Methods": "Wordlist enumeration, Bruteforce generation",
                    "DNS Server": "Custom DNS server (optional)",
                    "Wordlists": "Custom subdomain wordlists"
                }
            },
            "Port Scanning": {
                "purpose": "Discover open ports and running services on target systems",
                "use_cases": [
                    "Network reconnaissance and service discovery",
                    "TCP connect scans for service identification",
                    "Network sweeps for host discovery",
                    "Banner grabbing and service fingerprinting",
                    "Vulnerability assessment preparation"
                ],
                "commands": [
                    "nmap -sS <target>",
                    "nmap -sT <target>",
                    "nmap -sV -sT -A <target>",
                    "nmap -v -sn x.x.x.1-254 -oG ping-sweep.txt",
                    "nmap -sT -A --top-ports=20 x.x.x.1-254"
                ],
                "options": {
                    "Scan Types": "TCP Connect, Network Sweep",
                    "Port Ranges": "Custom ports, common ports, top 100/1000",
                    "Service Detection": "Banner grabbing and version detection",
                    "Threading": "Concurrent scanning for performance"
                }
            },
            "SMB Enumeration": {
                "purpose": "Enumerate SMB shares, users, and detect SMB vulnerabilities",
                "use_cases": [
                    "SMB share discovery and enumeration",
                    "NetBIOS information gathering",
                    "OS fingerprinting via SMB",
                    "Vulnerability scanning (MS17-010, MS08-067)",
                    "Anonymous and authenticated enumeration"
                ],
                "commands": [
                    "nmap --script=smb2-security-mode.nse -p139,445 <target>",
                    "nmap -p139,445 --script=smb-enum* <target>",
                    "smbclient -L \\\\\\\\<target ip>",
                    "crackmapexec smb <target> -u '' -p '' --shares",
                    "nmap --script=smb-vulns*.nse -p139,445 <target>"
                ],
                "options": {
                    "Scan Types": "Basic Info, Share Enumeration, Vulnerability Scan",
                    "Authentication": "Anonymous or credential-based access",
                    "Ports": "139 (NetBIOS), 445 (SMB)",
                    "Tools": "smbclient, nbtscan, nmap SMB scripts"
                }
            },
            "SMTP Enumeration": {
                "purpose": "Enumerate valid email addresses and users via SMTP",
                "use_cases": [
                    "User enumeration for password attacks",
                    "Email address validation",
                    "Mail server reconnaissance",
                    "SMTP service fingerprinting",
                    "Phishing campaign preparation"
                ],
                "commands": [
                    "nc -nv <target> 25",
                    "VRFY root",
                    "EXPN <username>",
                    "RCPT TO:<user@domain.com>",
                    "smtp-user-enum -M VRFY -U users.txt -t <target>"
                ],
                "options": {
                    "Methods": "VRFY, EXPN, RCPT TO with automatic fallback",
                    "Port": "25 (default), custom ports supported",
                    "Domain": "Target domain for RCPT TO testing",
                    "Wordlists": "Username lists for enumeration"
                }
            },
            "SNMP Enumeration": {
                "purpose": "Extract system information via SNMP community strings",
                "use_cases": [
                    "System information gathering",
                    "Network device enumeration",
                    "User account discovery",
                    "Process and software enumeration",
                    "Network interface discovery"
                ],
                "commands": [
                    "snmpwalk -c public -v1 <target>",
                    "snmpwalk -c public -v1 <target> 1.3.6.1.4.1.77.1.2.25",
                    "onesixtyone -c community.txt <target>",
                    "snmp-check <target>",
                    "nmap -sU --script snmp-* <target>"
                ],
                "options": {
                    "Versions": "SNMPv1, v2c, v3 support",
                    "Communities": "public, private, custom strings",
                    "Scan Types": "Basic Info, Users, Processes, Software, Network",
                    "MIB Objects": "Specific OID queries for targeted information"
                }
            },
            "HTTP Enumeration": {
                "purpose": "Web server fingerprinting and directory enumeration",
                "use_cases": [
                    "Web server identification and versioning",
                    "Directory and file discovery",
                    "SSL/TLS certificate analysis",
                    "Security header assessment",
                    "Technology stack detection"
                ],
                "commands": [
                    "nmap --script http-headers <target>",
                    "gobuster dir -u http://<target> -w wordlist.txt",
                    "nikto -h <target>",
                    "dirb http://<target> wordlist.txt",
                    "whatweb <target>"
                ],
                "options": {
                    "Scan Types": "Basic Fingerprint, Directory Enum, Nmap Scripts, Nikto",
                    "Extensions": "File extensions (.php, .asp, .jsp, etc.)",
                    "Wordlists": "Directory and file wordlists",
                    "SSL Analysis": "Certificate details and cipher analysis"
                }
            },
            "API Enumeration": {
                "purpose": "Discover and test API endpoints for security vulnerabilities",
                "use_cases": [
                    "REST API endpoint discovery",
                    "GraphQL schema enumeration",
                    "HTTP method testing",
                    "Authentication bypass attempts",
                    "API vulnerability assessment"
                ],
                "commands": [
                    "gobuster dir -u http://<target>/api -w api-wordlist.txt",
                    "curl -X OPTIONS http://<target>/api/",
                    "wfuzz -c -z file,wordlist.txt http://<target>/api/FUZZ",
                    "ffuf -w wordlist.txt -u http://<target>/api/FUZZ",
                    "arjun -u http://<target>/api/endpoint"
                ],
                "options": {
                    "Scan Types": "Basic Discovery, Gobuster Enum, HTTP Methods, Auth Bypass",
                    "API Types": "REST, GraphQL, Swagger/OpenAPI",
                    "Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                    "Wordlists": "API-specific endpoint wordlists"
                }
            }
        }
        
        # Populate tool selector
        self.tool_selector.addItems(list(self.tool_data.keys()))
        self.tool_selector.setCurrentText("DNS Enumeration")
        self.on_tool_changed("DNS Enumeration")
        
    def on_tool_changed(self, tool_name):
        """Update content when tool selection changes"""
        if tool_name in self.tool_data:
            self.current_tool = tool_name
            self.update_content(self.tool_data[tool_name])
            
    def update_content(self, tool_info):
        """Update the content area with tool information"""
        html_content = f"""
        <h2 style='color: #64C8FF; border-bottom: 2px solid #64C8FF; padding-bottom: 5px;'>
            {self.current_tool}
        </h2>
        
        <h3 style='color: #00FF41; margin-top: 20px;'>🎯 Purpose</h3>
        <p style='color: #DCDCDC; margin-left: 15px; line-height: 1.4;'>
            {tool_info['purpose']}
        </p>
        
        <h3 style='color: #00FF41; margin-top: 20px;'>📋 Common Use Cases</h3>
        <ul style='color: #DCDCDC; margin-left: 15px; line-height: 1.4;'>
        """
        
        for use_case in tool_info['use_cases']:
            html_content += f"<li>{use_case}</li>"
            
        html_content += """
        </ul>
        
        <h3 style='color: #00FF41; margin-top: 20px;'>⚙️ Configuration Options</h3>
        <table style='width: 100%; border-collapse: collapse; margin-left: 15px;'>
        """
        
        for option, description in tool_info['options'].items():
            html_content += f"""
            <tr>
                <td style='color: #87CEEB; font-weight: bold; padding: 5px; width: 150px; vertical-align: top;'>
                    {option}:
                </td>
                <td style='color: #DCDCDC; padding: 5px;'>{description}</td>
            </tr>
            """
            
        html_content += """
        </table>
        
        <h3 style='color: #00FF41; margin-top: 20px;'>💻 Example Commands</h3>
        <div style='background-color: rgba(0, 0, 0, 200); border: 1px solid #555; border-radius: 5px; padding: 10px; margin-left: 15px;'>
        """
        
        for i, command in enumerate(tool_info['commands'], 1):
            html_content += f"""
            <p style='color: #90EE90; font-family: monospace; margin: 5px 0;'>
                <span style='color: #FFD700;'>{i}.</span> {command}
            </p>
            """
            
        html_content += """
        </div>
        
        <div style='background-color: rgba(255, 165, 0, 50); border: 1px solid #FFA500; border-radius: 5px; padding: 10px; margin: 20px 15px;'>
            <p style='color: #FFA500; font-weight: bold; margin: 0;'>⚠️ Important Notes:</p>
            <ul style='color: #DCDCDC; margin: 5px 0 0 20px;'>
                <li>Always ensure you have proper authorization before scanning</li>
                <li>Use rate limiting to avoid overwhelming target systems</li>
                <li>Some tools may require additional software installation</li>
                <li>Results may vary based on target configuration and security measures</li>
            </ul>
        </div>
        """
        
        self.content_area.setHtml(html_content)
        
    def show_tool_help(self, tool_name):
        """Show help for specific tool"""
        if tool_name in self.tool_data:
            self.tool_selector.setCurrentText(tool_name)
            self.show()