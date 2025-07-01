# Additional methods for enumeration_page.py

# SMTP Enumeration Methods
def run_smtp_enum(self):
    target = self.target_input.text().strip()
    if not target:
        self.dns_terminal_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter target and domain</p>")
        return
    
    domain = target.split('.')[0] if '.' in target else "example.com"
    wordlist = self.wordlist_combo.currentData() or "resources/wordlists/subdomains-top1000.txt"
    
    self.dns_terminal_output.clear()
    self.set_buttons_enabled(False)
    self.append_terminal_output(f"<p style='color: #64C8FF;'>[*] SMTP enumeration on {target}</p>")
    
    import subprocess, threading
    def run_scan():
        try:
            cmd = ["python", "tools/smtp_enum.py", target, "--domain", domain, "--wordlist", wordlist]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.main_window.project_root))
            self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result.stdout}</pre>")
            if result.stderr: self.append_terminal_output(f"<p style='color: #FF4500;'>{result.stderr}</p>")
        except Exception as e:
            self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] {str(e)}</p>")
        finally: self.set_buttons_enabled(True)
    threading.Thread(target=run_scan, daemon=True).start()

# SNMP Enumeration Methods
def run_snmp_scan(self):
    target = self.target_input.text().strip()
    if not target: return self.show_error("Please enter a target IP")
    self.run_tool_command(["python", "tools/snmp_enum.py", target], f"SNMP scan on {target}")

def run_snmp_community(self):
    target = self.target_input.text().strip()
    if not target: return self.show_error("Please enter a target IP")
    self.run_tool_command(["python", "tools/snmp_enum.py", target, "--community", "public"], f"SNMP community test on {target}")

def run_snmp_walk(self):
    target = self.target_input.text().strip()
    if not target: return self.show_error("Please enter a target IP")
    self.run_tool_command(["python", "tools/snmp_enum.py", target, "--walk"], f"SNMP walk on {target}")

def run_snmp_range(self):
    target = self.target_input.text().strip()
    if not target: return self.show_error("Please enter a network range")
    self.run_tool_command(["python", "tools/snmp_enum.py", target, "--range"], f"SNMP range scan on {target}")

# HTTP Enumeration Methods
def run_http_fingerprint(self):
    target = self.target_input.text().strip()
    if not target: return self.show_error("Please enter a target")
    self.run_tool_command(["python", "tools/http_enum.py", target], f"HTTP fingerprinting on {target}")

def run_http_ssl(self):
    target = self.target_input.text().strip()
    if not target: return self.show_error("Please enter a target")
    self.run_tool_command(["python", "tools/http_enum.py", target, "--https", "--ssl-scan"], f"SSL scan on {target}")

def run_http_dir(self):
    target = self.target_input.text().strip()
    if not target: return self.show_error("Please enter a target")
    self.run_tool_command(["python", "tools/http_enum.py", target, "--dir-scan"], f"Directory scan on {target}")

# API Enumeration Methods
def run_api_discover(self):
    target = self.target_input.text().strip()
    if not target: return self.show_error("Please enter a target")
    self.run_tool_command(["python", "tools/api_enum.py", target], f"API discovery on {target}")

def run_api_methods(self):
    target = self.target_input.text().strip()
    if not target: return self.show_error("Please enter a target")
    self.run_tool_command(["python", "tools/api_enum.py", target, "--methods"], f"API methods test on {target}")

def run_api_auth(self):
    target = self.target_input.text().strip()
    if not target: return self.show_error("Please enter a target")
    self.run_tool_command(["python", "tools/api_enum.py", target, "--auth-bypass"], f"API auth bypass test on {target}")

# Database Enumeration Methods
def run_db_scan(self):
    target = self.target_input.text().strip()
    if not target: return self.show_error("Please enter a target IP")
    self.run_tool_command(["python", "tools/db_enum.py", target], f"Database scan on {target}")

def run_db_detailed(self):
    target = self.target_input.text().strip()
    if not target: return self.show_error("Please enter a target IP")
    self.run_tool_command(["python", "tools/db_enum.py", target, "--detailed"], f"Detailed database scan on {target}")

# Helper methods
def show_error(self, message):
    self.dns_terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {message}</p>")

def run_tool_command(self, cmd, description):
    self.dns_terminal_output.clear()
    self.set_buttons_enabled(False)
    self.append_terminal_output(f"<p style='color: #64C8FF;'>[*] {description}</p>")
    
    import subprocess, threading
    def run_scan():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.main_window.project_root))
            self.append_terminal_output(f"<pre style='color: #DCDCDC;'>{result.stdout}</pre>")
            if result.stderr: self.append_terminal_output(f"<p style='color: #FF4500;'>{result.stderr}</p>")
        except Exception as e:
            self.append_terminal_output(f"<p style='color: #FF4500;'>[ERROR] {str(e)}</p>")
        finally: self.set_buttons_enabled(True)
    threading.Thread(target=run_scan, daemon=True).start()