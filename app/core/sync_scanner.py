# app/core/sync_scanner.py
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import threading

def enumerate_hostnames_sync(target, wordlist_path, record_types):
    """Synchronous DNS enumeration for multi-target scanning"""
    results = {}
    
    try:
        # Read wordlist
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        # Limit to prevent overwhelming
        subdomains = subdomains[:500]
        
        def query_subdomain(subdomain):
            hostname = f"{subdomain}.{target}"
            subdomain_results = {}
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(hostname, record_type)
                    subdomain_results[record_type] = [str(answer) for answer in answers]
                except:
                    continue
            
            return hostname, subdomain_results
        
        # Use limited threading for sync operation
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(query_subdomain, sub) for sub in subdomains[:100]]
            
            for future in futures:
                try:
                    hostname, subdomain_results = future.result(timeout=5)
                    if subdomain_results:
                        results[hostname] = subdomain_results
                except:
                    continue
    
    except Exception as e:
        return {'error': str(e)}
    
    return results