# app/tools/dns_utils.py
import dns.resolver
import dns.zone
import dns.query
from PyQt6.QtCore import QThreadPool
from collections import defaultdict
from .recon import PTRWorker

def enumerate_hostnames(target, wordlist_path, output_callback, status_callback, finished_callback, record_types=None, use_bruteforce=False, char_sets=None, max_length=16, dns_server=None, wildcard_callback=None, results_callback=None, progress_callback=None, progress_start_callback=None, scan_controller=None):
    from .recon import SubdomainGenerator, HostWordlistWorker
    
    # Create dedicated subdomain generator
    subdomain_generator = SubdomainGenerator(
        wordlist_path=wordlist_path,
        use_bruteforce=use_bruteforce,
        char_sets=char_sets,
        max_length=max_length
    )
    
    # Create worker that consumes from the generator
    worker = HostWordlistWorker(target, subdomain_generator, record_types, dns_server)
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