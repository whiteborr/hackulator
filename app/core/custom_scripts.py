# --- FULLY CORRECTED AND UPDATED custom_scripts.py ---
import os
import dns.resolver
import dns.zone
import dns.query
import random
import string
import concurrent.futures
import itertools
from collections import defaultdict
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable, QThreadPool
from app.core.logger import logger
from app.core.config import config

class WorkerSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    wildcard_result = pyqtSignal(str)
    results_ready = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)
    progress_start = pyqtSignal(int)
    # Signal to emit results as they are found
    result_found = pyqtSignal(str, str, list)

class HostWordlistWorker(QRunnable):
    def __init__(self, target, wordlist_path, record_types=None, use_bruteforce=False, char_sets=None, max_length=16, dns_server=None):
        super().__init__()
        self.signals = WorkerSignals()
        self.target = target
        self.wordlist_path = wordlist_path
        self.use_bruteforce = use_bruteforce
        self.char_sets = char_sets or []
        # Support up to 16 characters
        self.max_length = max_length
        self.dns_server = dns_server
        self.is_running = True
        self.record_types = record_types or ['A']
        self.resolver = dns.resolver.Resolver()
        
        if self.dns_server:
            self.resolver.nameservers = [self.dns_server]
            
        dns_config = config.get_dns_config()
        self.resolver.timeout = dns_config.get('timeout', 3)
        self.resolver.lifetime = dns_config.get('lifetime', 10)
        
        try:
            from app.core.rate_limiter import rate_limiter
            self.max_workers = rate_limiter.get_recommended_thread_count() if rate_limiter.is_enabled() else dns_config.get('max_workers', 50)
        except ImportError:
            self.max_workers = dns_config.get('max_workers', 50)
            
        self.wildcard_test_count = dns_config.get('wildcard_test_count', 3)
        self.wildcard_test_length = dns_config.get('wildcard_test_length', 12)
        self.wildcard_ips = set()

    def _random_string(self, length=None):
        length = length or self.wildcard_test_length
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def detect_wildcard(self):
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
        if not self.is_running:
            return
        
        domain = f"{subdomain}.{self.target}"
        for record_type in self.record_types:
            if not self.is_running:
                return
            try:
                answers = self.resolver.resolve(domain, record_type)
                if record_type in ['A', 'AAAA']:
                    values = [r.address for r in answers]
                elif record_type == "CNAME":
                    values = [r.target.to_text().rstrip('.') for r in answers]
                elif record_type == "MX":
                    values = [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers]
                elif record_type == "TXT":
                    values = [b''.join(r.strings).decode('utf-8', errors='ignore').replace('"', '') for r in answers]
                else: # NS, PTR, etc.
                    values = [r.target.to_text().rstrip('.') for r in answers]
                
                # Filter out wildcard results
                if record_type == "A" and self.wildcard_ips and set(values).issubset(self.wildcard_ips):
                    continue
                    
                if values:
                    # Emit result as soon as it's found
                    self.signals.result_found.emit(domain, record_type, values)

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception:
                pass

    def _generate_subdomains(self):
        """Yields subdomains from bruteforce or wordlist."""
        if self.use_bruteforce:
            chars = ''
            if '0-9' in self.char_sets: chars += '0123456789'

            if 'a-z' in self.char_sets: chars += 'abcdefghijklmnopqrstuvwxyz'
            if '-' in self.char_sets: chars += '-'
            
            if not chars: return

            for length in range(1, self.max_length + 1):
                for combo in itertools.product(chars, repeat=length):
                    if not self.is_running: return
                    yield ''.join(combo)
        else:
            if self.wordlist_path:
                try:
                    with open(self.wordlist_path, 'r') as file:
                        for line in file:
                            if not self.is_running: return
                            yield line.strip()
                except FileNotFoundError:
                    self.signals.output.emit(f"[ERROR] Wordlist not found at: {self.wordlist_path}")
                    return
            else: # Default list
                for sub in ['www', 'mail', 'ftp', 'admin', 'test']:
                    yield sub

    def run(self):
        try:
            wordlist_name = os.path.basename(self.wordlist_path) if self.wordlist_path else "bruteforce"
            logger.log_scan_start(self.target, wordlist_name, self.record_types)
            self.signals.status.emit(f"Running: Enumerate Hostnames on {self.target}...")

            self.signals.wildcard_result.emit("<p style='color: #00FF41;'>Checking for wildcard...</p>")
            self.detect_wildcard()
            if self.wildcard_ips:
                self.signals.wildcard_result.emit("<p style='color: orange;'>[✓] Wildcard DNS detected!</p>")
            else:
                self.signals.wildcard_result.emit("<p style='color: #00FF41;'>[✓] No wildcard DNS detected.</p>")
            
            subdomains = list(self._generate_subdomains())
            if not self.is_running:
                return

            if self.use_bruteforce:
                self.signals.output.emit(f"<p style='color: #00BFFF;'>Bruteforcing.... Please wait....</p><br>")
            else:
                # Don't show message for wordlist - handled by main UI
                pass
            self.signals.progress_start.emit(len(subdomains))
            
            completed_count = 0
            results_count = 0
            
            all_results = defaultdict(lambda: defaultdict(list))

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_subdomain = {executor.submit(self.query_subdomain, sub): sub for sub in subdomains}
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    if not self.is_running:
                        # Attempt to cancel remaining futures
                        for f in future_to_subdomain:
                            f.cancel()
                        break
                    
                    # Process future to catch exceptions and collect results
                    future.result()
                    completed_count += 1
                    if completed_count % 10 == 0 or completed_count == len(subdomains):
                        self.signals.progress_update.emit(completed_count, len(all_results))
            
            if self.is_running:
                self.signals.progress_update.emit(len(subdomains), len(all_results))
                final_count = getattr(self, 'final_result_count', len(all_results))
                logger.log_scan_complete(self.target, final_count)
                # Always emit results, even if empty
                self.signals.results_ready.emit(dict(all_results))
                self.signals.status.emit("Finished: Enumerate Hostnames")

        except Exception as e:
            logger.error(f"Unexpected error in DNS enumeration: {str(e)}")
            self.signals.output.emit(f"[ERROR] An unexpected error occurred: {e}")
            self.signals.status.emit("Error: Script crashed")
        finally:
            self.signals.finished.emit()


def enumerate_hostnames(target, wordlist_path, output_callback, status_callback, finished_callback, record_types=None, use_bruteforce=False, char_sets=None, max_length=16, dns_server=None, wildcard_callback=None, results_callback=None, progress_callback=None, progress_start_callback=None, scan_controller=None):
    worker = HostWordlistWorker(target, wordlist_path, record_types, use_bruteforce, char_sets, max_length, dns_server)
    if scan_controller:
        worker.scan_controller = scan_controller
        
    # Connect signals from the worker to the main GUI callbacks
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
        
    # Store results for export
    collected_results = defaultdict(lambda: defaultdict(list))
    
    # --- Real-time result display logic ---
    def display_realtime_result(domain, record_type, records):
        records.sort()
        found_line = f"<p style='color: #00FF41;'>[+] Found ({record_type}): {domain}</p>"
        data_lines_str = "".join([f"&nbsp;&nbsp;&nbsp;-&gt; {record}<br>" for record in records])
        indented_data_block = f"<p style='color: #DCDCDC; padding-left: 20px;'>{data_lines_str}</p>"
        output_callback(found_line + indented_data_block + "<br>")
        
        # Also collect results for export
        collected_results[domain][record_type].extend(records)
        # Update worker's result count for accurate logging
        worker.final_result_count = len(collected_results)
        
    def send_collected_results():
        if results_callback:
            # Send collected results even if empty to trigger final merge
            results_callback(dict(collected_results))
    
    worker.signals.result_found.connect(display_realtime_result)
    worker.signals.finished.connect(send_collected_results)
    
    QThreadPool.globalInstance().start(worker)
    return worker

# --- Additional DNS Scripts (Restored) ---
def try_zone_transfer(domain, nameservers):
    results = {}
    for ns in nameservers:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            records = {}
            for name, node in zone.nodes.items():
                rdatasets = node.rdatasets
                records[str(name)] = [r.to_text() for rd in rdatasets for r in rd]
            results[ns] = records
        except Exception as e:
            results[ns] = f"Failed: {str(e)}"
    return results

def run_zone_transfer(target, output_callback, status_callback, finished_callback):
    try:
        try:
            resolver = dns.resolver.Resolver(filename=None)
        except:
            resolver = dns.resolver.Resolver()
        nameservers = [str(r.target).rstrip('.') for r in resolver.resolve(target, 'NS')]
        output_callback(f"<p style='color:#00BFFF;'>[INFO] Trying zone transfer on: {', '.join(nameservers)}</p>")
        results = try_zone_transfer(target, nameservers)
        for ns, recs in results.items():
            output_callback(f"<p><b>{ns}</b>:</p>")
            if isinstance(recs, str):
                output_callback(f"<p style='color:red;'> {recs}</p>")
            else:
                for name, data in recs.items():
                    data_lines = "<br>".join(data)
                    output_callback(f"<p>&nbsp;&nbsp;&nbsp;<b>{name}:</b><br>{data_lines}</p>")
        status_callback("Zone transfer attempt finished")
    except Exception as e:
        output_callback(f"<p style='color:red;'>[ERROR] Zone Transfer failed: {e}</p>")
        status_callback("Zone transfer error")
    finally:
        finished_callback()

class PTRWorker(QRunnable):
    def __init__(self, ip_range, dns_server):
        super().__init__()
        self.signals = WorkerSignals()
        self.ip_range = ip_range
        self.dns_server = dns_server
        self.is_running = True
        self.completed_count = 0
        self.results_count = 0
    
    def run(self):
        import ipaddress
        import concurrent.futures
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 5
        if self.dns_server:
            resolver.nameservers = [self.dns_server]
        
        results = {}
        try:
            ips = []
            
            if '-' in self.ip_range:
                parts = self.ip_range.split('-')
                start_ip = parts[0].strip()
                end_part = parts[1].strip()
                
                if '.' in end_part:
                    # Full IP range like 192.168.1.0-192.168.16.0
                    start_parts = start_ip.split('.')
                    end_parts = end_part.split('.')
                    
                    # Check if it's a cross-subnet range
                    if start_parts[2] != end_parts[2]:
                        # Scan subnet by subnet
                        start_subnet = int(start_parts[2])
                        end_subnet = int(end_parts[2])
                        base_network = f"{start_parts[0]}.{start_parts[1]}"
                        
                        self.signals.output.emit(f"<p style='color: #00BFFF;'>[INFO] Cross-subnet range detected. Scanning {end_subnet - start_subnet + 1} subnets...</p>")
                        
                        for subnet in range(start_subnet, end_subnet + 1):
                            # Scan each subnet from .1 to .254 (skip .0 and .255)
                            for host in range(1, 255):
                                ips.append(ipaddress.ip_address(f"{base_network}.{subnet}.{host}"))
                    else:
                        # Same subnet range
                        start = ipaddress.ip_address(start_ip)
                        end = ipaddress.ip_address(end_part)
                        current = int(start)
                        end_int = int(end)
                        
                        while current <= end_int:
                            ips.append(ipaddress.ip_address(current))
                            current += 1
                else:
                    # Last octet range like 192.168.1.1-254
                    base_ip = '.'.join(start_ip.split('.')[:-1])
                    start_octet = int(start_ip.split('.')[-1])
                    end_octet = int(end_part)
                    for i in range(start_octet, end_octet + 1):
                        ips.append(ipaddress.ip_address(f"{base_ip}.{i}"))
            elif '/' in self.ip_range:
                network = ipaddress.ip_network(self.ip_range, strict=False)
                ips = list(network.hosts())
            else:
                ip_parts = self.ip_range.split('.')
                if len(ip_parts) == 4:
                    if ip_parts[3] == '0':
                        if ip_parts[2] == '0':
                            network = ipaddress.ip_network(f"{self.ip_range}/16", strict=False)
                        else:
                            network = ipaddress.ip_network(f"{self.ip_range}/24", strict=False)
                        ips = list(network.hosts())
                    else:
                        ips = [ipaddress.ip_address(self.ip_range)]
            
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Querying PTR records.... please wait...</p><br>")
            self.signals.progress_start.emit(len(ips))
            
            def query_single_ptr(ip):
                if not self.is_running:
                    return None
                try:
                    reverse_name = dns.reversename.from_address(str(ip))
                    answers = resolver.resolve(reverse_name, 'PTR')
                    values = [r.target.to_text().rstrip('.') for r in answers]
                    if values:
                        return str(ip), values
                except dns.resolver.NXDOMAIN:
                    # No PTR record exists
                    pass
                except dns.resolver.Timeout:
                    # DNS timeout
                    pass
                except Exception as e:
                    # Silent error handling
                    pass
                return None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_ip = {executor.submit(query_single_ptr, ip): ip for ip in ips}
                for future in concurrent.futures.as_completed(future_to_ip):
                    if not self.is_running:
                        break
                    result = future.result()
                    self.completed_count += 1
                    
                    if result:
                        ip, values = result
                        results[ip] = {'PTR': values}
                        self.results_count += 1
                        self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found (PTR): {ip}</p>")
                        for value in values:
                            self.signals.output.emit(f"<p style='color: #DCDCDC; padding-left: 20px;'>&nbsp;&nbsp;&nbsp;-&gt; {value}</p>")
                        self.signals.output.emit("<br>")
                        # Store individual result immediately
                        self.signals.results_ready.emit({ip: {'PTR': values}})
                    
                    # Update progress every 10 IPs or at the end
                    if self.completed_count % 10 == 0 or self.completed_count == len(ips):
                        self.signals.progress_update.emit(self.completed_count, self.results_count)
            
            # Final results summary already sent individually
        except Exception as e:
            self.signals.output.emit(f"<p style='color: red;'>[ERROR] PTR query failed: {str(e)}</p>")
        finally:
            self.signals.finished.emit()

def query_ptr_records(ip_range, dns_server, output_callback, results_callback):
    """Query PTR records for IP addresses or IP ranges using threaded worker"""
    worker = PTRWorker(ip_range, dns_server)
    worker.signals.output.connect(output_callback)
    worker.signals.results_ready.connect(results_callback)
    QThreadPool.globalInstance().start(worker)
    return worker

def query_direct_records(target, record_types, dns_server, output_callback, results_callback):
    """Query MX, NS, TXT, PTR records directly on the target domain"""
    resolver = dns.resolver.Resolver()
    if dns_server:
        resolver.nameservers = [dns_server]
    
    all_results = {target: {}}
    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            if rtype == "MX":
                values = [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers]
            elif rtype == "NS":
                values = [r.target.to_text().rstrip('.') for r in answers]
            elif rtype == "TXT":
                values = [b''.join(r.strings).decode('utf-8', errors='ignore').replace('"', '') for r in answers]
            elif rtype == "PTR":
                values = [r.target.to_text().rstrip('.') for r in answers]
            else:
                values = [r.to_text() for r in answers]
            
            if values:
                all_results[target][rtype] = values
                output_callback(f"<p style='color: #00FF41;'>[+] Found ({rtype}): {target}</p>")
                for value in values:
                    output_callback(f"<p style='color: #DCDCDC; padding-left: 20px;'>&nbsp;&nbsp;&nbsp;-&gt; {value}</p>")
                output_callback("<br>")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # No record exists - this is normal, don't show as error
            pass
        except Exception as e:
            output_callback(f"<p style='color: orange;'>[!] {rtype} query failed for {target}: {str(e)}</p>")
    
    if all_results[target]:  # Only send if we found any records
        results_callback(all_results)

def fetch_basic_records(domain):
    record_types = ['NS', 'MX', 'TXT']
    try:
        resolver = dns.resolver.Resolver(filename=None)
    except:
        resolver = dns.resolver.Resolver()
    output = {}
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            output[rtype] = [a.to_text() for a in answers]
        except Exception as e:
            output[rtype] = [f"Error: {e}"]
    return output