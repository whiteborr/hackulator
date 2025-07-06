# app/tools/dns_scanner.py
import dns.resolver
from collections import defaultdict

def run_dns_scan(target, wordlist_path=None, record_types=None, dns_server=None):
    """
    Run DNS scan and return structured data for both text and tree views
    
    Returns:
        dict: Structured DNS results with domains as keys and record types as nested dict
    """
    if not record_types:
        record_types = ['A']
    
    resolver = dns.resolver.Resolver()
    if dns_server:
        resolver.nameservers = [dns_server]
    
    results = defaultdict(lambda: defaultdict(list))
    
    # Read wordlist if provided
    subdomains = []
    if wordlist_path:
        try:
            with open(wordlist_path, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            subdomains = ['www', 'mail', 'ftp', 'admin', 'test']
    else:
        subdomains = ['www', 'mail', 'ftp', 'admin', 'test']
    
    # Scan each subdomain
    for subdomain in subdomains:
        domain = f"{subdomain}.{target}"
        
        for record_type in record_types:
            try:
                if record_type == 'A':
                    # Query both A and AAAA for 'A' type
                    for rtype in ['A', 'AAAA']:
                        try:
                            answers = resolver.resolve(domain, rtype)
                            values = [r.address for r in answers]
                            if values:
                                results[domain][rtype].extend(values)
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                            continue
                elif record_type == 'SRV':
                    # Handle SRV records separately with service wordlist
                    continue  # Skip SRV in regular subdomain scan
                else:
                    answers = resolver.resolve(domain, record_type)
                    if record_type == 'MX':
                        values = [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers]
                    elif record_type == 'NS':
                        values = [r.target.to_text().rstrip('.') for r in answers]
                    elif record_type == 'TXT':
                        values = [b''.join(r.strings).decode('utf-8', errors='ignore').replace('"', '') for r in answers]
                    elif record_type == 'CNAME':
                        values = [r.target.to_text().rstrip('.') for r in answers]
                    else:
                        values = [r.to_text() for r in answers]
                    
                    if values:
                        results[domain][record_type].extend(values)
                        
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception:
                continue
    
    # Also query the main domain
    for record_type in record_types:
        if record_type == 'SRV':
            continue
        try:
            if record_type == 'A':
                for rtype in ['A', 'AAAA']:
                    try:
                        answers = resolver.resolve(target, rtype)
                        values = [r.address for r in answers]
                        if values:
                            results[target][rtype].extend(values)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        continue
            else:
                answers = resolver.resolve(target, record_type)
                if record_type == 'MX':
                    values = [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers]
                elif record_type == 'NS':
                    values = [r.target.to_text().rstrip('.') for r in answers]
                elif record_type == 'TXT':
                    values = [b''.join(r.strings).decode('utf-8', errors='ignore').replace('"', '') for r in answers]
                elif record_type == 'CNAME':
                    values = [r.target.to_text().rstrip('.') for r in answers]
                else:
                    values = [r.to_text() for r in answers]
                
                if values:
                    results[target][record_type].extend(values)
                    
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception:
            continue
    
    return dict(results)