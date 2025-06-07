# app/core/custom_scripts.py
import os
import dns.resolver
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable, QThreadPool

class WorkerSignals(QObject):
    """
    Defines the signals available from a running worker thread.
    """
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()


class HostWordlistWorker(QRunnable):
    """
    A QRunnable worker that executes the dnspython enumeration script in a separate thread.
    """
    def __init__(self, target, wordlist_path):
        super().__init__()
        self.signals = WorkerSignals()
        self.target = target
        self.wordlist_path = wordlist_path
        self.is_running = True

    def run(self):
        """The main logic for the worker thread."""
        try:
            self.signals.status.emit(f"Running: Enumerate Hostnames on {self.target}...")
            
            with open(self.wordlist_path, 'r') as file:
                subdomains = [line.strip() for line in file if line.strip()]

            resolver = dns.resolver.Resolver()
            
            for sub in subdomains:
                if not self.is_running:
                    break
                
                domain = f"{sub}.{self.target}"
                try:
                    # Resolve the domain to an A record (IPv4 address)
                    answers = resolver.resolve(domain, 'A')
                    
                    # **FIX**: Build a nicely formatted HTML block for the output
                    # The main 'Found' line
                    found_line = f"<p style='color: #00FF41; font-family: \"Neuropol\";'>[+] Found: {domain}</p>"
                    # Create indented lines for each IP address
                    ip_lines = "".join([f"<p style='color: #DCDCDC; font-family: \"Neuropol\"; padding-left: 20px;'>&nbsp;&nbsp;&nbsp;-&gt; {rdata.address}</p>" for rdata in answers])
                    
                    # Combine and emit the full HTML block
                    output_html = found_line + ip_lines
                    self.signals.output.emit(output_html)

                except dns.resolver.NXDOMAIN:
                    pass 
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.Timeout:
                    output_html = f"<p style='color: #FFA500; font-family: \"Neuropol\";'>[-] Timeout: {domain}</p>"
                    self.signals.output.emit(output_html)
                except Exception as e:
                    output_html = f"<p style='color: #FF4500; font-family: \"Neuropol\";'>[!] Error with {domain}: {e}</p>"
                    self.signals.output.emit(output_html)

            self.signals.status.emit("Finished: Enumerate Hostnames")

        except FileNotFoundError:
            self.signals.output.emit(f"[ERROR] Wordlist not found at: {self.wordlist_path}")
            self.signals.status.emit("Error: File not found")
        except Exception as e:
            self.signals.output.emit(f"[ERROR] An unexpected error occurred: {e}")
            self.signals.status.emit("Error: Script crashed")
        finally:
            self.signals.finished.emit()

    def stop(self):
        self.is_running = False


def enumerate_hostnames(target, wordlist_path, output_callback, status_callback, finished_callback):
    """
    Creates and runs the script worker in the global thread pool.
    """
    worker = HostWordlistWorker(target, wordlist_path)
    
    # Connect the worker's signals to the UI's callback functions
    worker.signals.output.connect(output_callback)
    worker.signals.status.connect(status_callback)
    worker.signals.finished.connect(finished_callback)
    
    QThreadPool.globalInstance().start(worker)
