# app/core/custom_scripts.py
import os
import dns.resolver
import random
import string
import concurrent.futures
from collections import defaultdict
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable, QThreadPool
from app.core.logger import logger
from app.core.config import config

class WorkerSignals(QObject):
    """Defines the signals available from a running worker thread."""
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    wildcard_result = pyqtSignal(str)
    results_ready = pyqtSignal(dict)  # Emit results for export
    progress_update = pyqtSignal(int, int)  # completed_items, results_found
    progress_start = pyqtSignal(int)  # total_items


class HostWordlistWorker(QRunnable):
    """
    A QRunnable worker that executes the dnspython enumeration script concurrently
    and formats the output cleanly after collecting all results.
    """
    def __init__(self, target, wordlist_path, record_types=None):
        super().__init__()
        self.signals = WorkerSignals()
        self.target = target
        self.wordlist_path = wordlist_path
        self.is_running = True
        self.record_types = record_types or ['A']
        self.resolver = dns.resolver.Resolver()
        # Configure DNS resolver from config
        dns_config = config.get_dns_config()
        self.resolver.timeout = dns_config.get('timeout', 3)
        self.resolver.lifetime = dns_config.get('lifetime', 10)
        self.max_workers = dns_config.get('max_workers', 50)
        self.wildcard_test_count = dns_config.get('wildcard_test_count', 3)
        self.wildcard_test_length = dns_config.get('wildcard_test_length', 12)
        self.wildcard_ips = set()

    def _random_string(self, length=None):
        """Generates a random string for wildcard testing."""
        if length is None:
            length = self.wildcard_test_length
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def detect_wildcard(self):
        """Detects wildcard DNS by resolving random subdomains."""
        test_domains = [f"{self._random_string()}.{self.target}" for _ in range(self.wildcard_test_count)]
        for test_domain in test_domains:
            try:
                answers = self.resolver.resolve(test_domain, 'A')
                for rdata in answers:
                    self.wildcard_ips.add(rdata.address)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception as e:
                logger.log_dns_error(test_domain, str(e))
                self.signals.output.emit(f"<p style='color: orange;'>[Wildcard Detection Error]: {test_domain} - {e}</p>")

    def query_subdomain(self, subdomain):
        """
        The task for each thread. Queries a single domain and **returns** its results.
        It no longer emits signals directly.
        """
        if not self.is_running:
            return None

        domain = f"{subdomain}.{self.target}"
        domain_results = defaultdict(list)

        for record_type in self.record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                
                if record_type == "A": values = [r.address for r in answers]
                elif record_type == "AAAA": values = [r.address for r in answers]
                elif record_type == "CNAME": values = [r.target.to_text() for r in answers]
                elif record_type == "MX": values = [f"{r.preference} {r.exchange.to_text()}" for r in answers]
                elif record_type == "TXT": values = [b''.join(r.strings).decode('utf-8', errors='ignore').replace('"', '') for r in answers]
                else: values = [r.to_text() for r in answers]

                if record_type == "A" and self.wildcard_ips and set(values).issubset(self.wildcard_ips):
                    continue
                
                if values:
                    domain_results[record_type].extend(values)
            
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception:
                pass
        
        return domain, domain_results

    def run(self):
        """The main logic for the worker thread."""
        try:
            logger.log_scan_start(self.target, self.wordlist_path, self.record_types)
            self.signals.status.emit(f"Running: Enumerate Hostnames on {self.target}...")
            
            self.signals.wildcard_result.emit("<p style='color: #00FF41; font-family: \"Neuropol X\";'>Checking for wildcard...</p>")
            self.detect_wildcard()
            
            if self.wildcard_ips:
                self.signals.wildcard_result.emit(f"<p style='color: orange; font-family: \"Neuropol X\";'>[✓] Wildcard DNS detected!!!</p>")
            else:
                self.signals.wildcard_result.emit("<p style='color: #00FF41; font-family: \"Neuropol X\";'>[✓] No wildcard DNS detected.</p>")

            with open(self.wordlist_path, 'r') as file:
                subdomains = [line.strip() for line in file if line.strip()]

            # Emit progress start
            self.signals.progress_start.emit(len(subdomains))
            
            # **FIX**: Collect all results from threads before processing
            all_results = defaultdict(lambda: defaultdict(list))
            completed_count = 0
            results_count = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Use map to get results as they complete
                future_to_subdomain = {executor.submit(self.query_subdomain, sub): sub for sub in subdomains}
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    result = future.result()
                    completed_count += 1
                    
                    if result:
                        domain, domain_results = result
                        if domain_results:  # Only count if results found
                            results_count += 1
                        for record_type, values in domain_results.items():
                            all_results[domain][record_type].extend(values)
                    
                    # Emit progress update every 10 completed items or at end
                    if completed_count % 10 == 0 or completed_count == len(subdomains):
                        self.signals.progress_update.emit(completed_count, results_count)

            # **FIX**: Process and format the collected results in the correct order
            # First, group all results by record type
            grouped_by_type = defaultdict(dict)
            for domain, types in all_results.items():
                for r_type, values in types.items():
                    grouped_by_type[r_type][domain] = values

            # Now, iterate through the desired order of record types
            display_order = ['A', 'AAAA', 'CNAME', 'MX', 'TXT']
            for record_type in display_order:
                if record_type in grouped_by_type:
                    # Sort the domains alphabetically within this record type
                    for domain in sorted(grouped_by_type[record_type].keys()):
                        records = grouped_by_type[record_type][domain]
                        records.sort()

                        found_line = f"<p style='color: #00FF41; font-family: \"Neuropol X\";'>[+] Found ({record_type}): {domain}</p>"
                        data_lines_str = "".join([f"&nbsp;&nbsp;&nbsp;-&gt; {record}<br>" for record in records])
                        indented_data_block = f"<p style='color: #DCDCDC; font-family: \"Neuropol X\"; padding-left: 20px;'>{data_lines_str}</p>"
                        
                        self.signals.output.emit(found_line + indented_data_block)

            results_count = len(all_results)
            logger.log_scan_complete(self.target, results_count)
            
            # Emit results for export
            self.signals.results_ready.emit(dict(all_results))
            
            self.signals.status.emit("Finished: Enumerate Hostnames")
        except FileNotFoundError:
            logger.error(f"Wordlist not found: {self.wordlist_path}")
            self.signals.output.emit(f"[ERROR] Wordlist not found at: {self.wordlist_path}")
            self.signals.status.emit("Error: File not found")
        except Exception as e:
            logger.error(f"Unexpected error in DNS enumeration: {str(e)}")
            self.signals.output.emit(f"[ERROR] An unexpected error occurred: {e}")
            self.signals.status.emit("Error: Script crashed")
        finally:
            self.signals.finished.emit()


def enumerate_hostnames(target, wordlist_path, output_callback, status_callback, finished_callback, record_types=None, wildcard_callback=None, results_callback=None, progress_callback=None, progress_start_callback=None):
    """
    Creates and runs the script worker.
    """
    worker = HostWordlistWorker(target, wordlist_path, record_types)
    worker.signals.output.connect(output_callback)
    worker.signals.status.connect(status_callback)
    worker.signals.finished.connect(finished_callback)
    if wildcard_callback:
        worker.signals.wildcard_result.connect(wildcard_callback)
    if results_callback:
        worker.signals.results_ready.connect(results_callback)
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    QThreadPool.globalInstance().start(worker)
