# app/tools/smtp_scanner.py
import socket
import time
import os
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

class SMTPSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)
    progress_start = pyqtSignal(int)

class SMTPEnumWorker(QRunnable):
    """SMTP enumeration worker using VRFY, EXPN, and RCPT TO"""
    
    def __init__(self, target, port=25, wordlist_path=None, domain="", helo_name="test.local"):
        super().__init__()
        self.signals = SMTPSignals()
        self.target = target
        self.port = port
        self.wordlist_path = wordlist_path
        self.domain = domain or target
        self.helo_name = helo_name
        self.is_running = True
        self.results = {'valid_users': [], 'server_info': {}}
        
    def send_and_recv(self, sock, command, delay=0.5):
        """Send a command to the socket and return the response"""
        try:
            time.sleep(delay)
            sock.sendall((command + "\r\n").encode())
            return sock.recv(1024).decode().strip()
        except Exception as e:
            return f"Error: {str(e)}"
    
    def test_smtp_connection(self):
        """Test basic SMTP connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, self.port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return True, banner
        except Exception as e:
            return False, str(e)
    
    def enumerate_user(self, username):
        """Enumerate a single user using VRFY, EXPN, and RCPT TO"""
        if not self.is_running:
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, self.port))
            
            # Get banner
            banner = sock.recv(1024).decode().strip()
            
            # Try EHLO first, fallback to HELO
            try:
                response = self.send_and_recv(sock, f"EHLO {self.helo_name}")
                if not response.startswith("250"):
                    response = self.send_and_recv(sock, f"HELO {self.helo_name}")
            except:
                response = self.send_and_recv(sock, f"HELO {self.helo_name}")
            
            # Try VRFY
            vrfy_response = self.send_and_recv(sock, f"VRFY {username}")
            if "250" in vrfy_response or "252" in vrfy_response:
                sock.close()
                return {
                    'username': username,
                    'method': 'VRFY',
                    'response': vrfy_response,
                    'status': 'valid'
                }
            
            # Try EXPN
            expn_response = self.send_and_recv(sock, f"EXPN {username}")
            if "250" in expn_response:
                sock.close()
                return {
                    'username': username,
                    'method': 'EXPN',
                    'response': expn_response,
                    'status': 'valid'
                }
            
            # Try RCPT TO
            self.send_and_recv(sock, "MAIL FROM:<test@test.local>")
            rcpt_response = self.send_and_recv(sock, f"RCPT TO:<{username}@{self.domain}>")
            if "250" in rcpt_response or "252" in rcpt_response:
                sock.close()
                return {
                    'username': username,
                    'method': 'RCPT TO',
                    'response': rcpt_response,
                    'status': 'possible'
                }
            
            sock.close()
            return None
            
        except Exception as e:
            return {
                'username': username,
                'method': 'ERROR',
                'response': str(e),
                'status': 'error'
            }
    
    def load_usernames(self):
        """Load usernames from wordlist"""
        usernames = []
        
        if self.wordlist_path and os.path.exists(self.wordlist_path):
            try:
                with open(self.wordlist_path, 'r') as f:
                    usernames = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Failed to load wordlist: {str(e)}</p>")
        
        if not usernames:
            # Default common usernames
            usernames = ['admin', 'administrator', 'root', 'user', 'test', 'guest', 'mail', 'postmaster', 'webmaster']
        
        return usernames
    
    def run(self):
        try:
            self.signals.status.emit(f"Starting SMTP enumeration on {self.target}:{self.port}...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Testing SMTP connection to {self.target}:{self.port}...</p><br>")
            
            # Test connection
            connected, banner = self.test_smtp_connection()
            if not connected:
                self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Failed to connect: {banner}</p>")
                self.signals.status.emit("SMTP connection failed")
                return
            
            self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Connected successfully</p>")
            self.signals.output.emit(f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ Banner: {banner}</p><br>")
            self.results['server_info']['banner'] = banner
            
            # Load usernames
            usernames = self.load_usernames()
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Testing {len(usernames)} usernames...</p><br>")
            self.signals.progress_start.emit(len(usernames))
            
            valid_users = []
            completed = 0
            
            for username in usernames:
                if not self.is_running:
                    break
                
                result = self.enumerate_user(username)
                completed += 1
                
                if result:
                    if result['status'] == 'valid':
                        valid_users.append(result)
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>[+] Valid user found: {username} (via {result['method']})</p>"
                        )
                        self.signals.output.emit(
                            f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {result['response']}</p>"
                        )
                    elif result['status'] == 'possible':
                        valid_users.append(result)
                        self.signals.output.emit(
                            f"<p style='color: #FFAA00;'>[?] Possible user: {username} (via {result['method']})</p>"
                        )
                        self.signals.output.emit(
                            f"<p style='color: #DCDCDC;'>&nbsp;&nbsp;&nbsp;→ {result['response']}</p>"
                        )
                    elif result['status'] == 'error':
                        self.signals.output.emit(
                            f"<p style='color: #FF4500;'>[!] Error testing {username}: {result['response']}</p>"
                        )
                
                if completed % 5 == 0:
                    self.signals.progress_update.emit(completed, len(valid_users))
            
            # Store results
            self.results['valid_users'] = valid_users
            if self.results['valid_users'] or self.results['server_info']:
                final_results = {self.target: self.results}
                self.signals.results_ready.emit(final_results)
                
                if valid_users:
                    self.signals.output.emit(f"<br><p style='color: #00FF41;'>Found {len(valid_users)} valid/possible users</p>")
                else:
                    self.signals.output.emit("<br><p style='color: #FFAA00;'>No valid users found</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No SMTP information could be retrieved</p>")
            
            self.signals.status.emit("SMTP enumeration completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] SMTP enumeration failed: {str(e)}</p>")
            self.signals.status.emit("SMTP enumeration error")
        finally:
            self.signals.finished.emit()