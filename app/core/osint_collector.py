# app/core/osint_collector.py
import requests
import json
import re
from typing import Dict, List, Callable
from urllib.parse import quote

class OSINTCollector:
    """Open Source Intelligence data collector"""
    
    def __init__(self):
        self.timeout = 10
        self.sources = {
            'shodan': self._search_shodan,
            'virustotal': self._search_virustotal,
            'urlvoid': self._search_urlvoid,
            'whois': self._search_whois,
            'dns_dumpster': self._search_dns_dumpster
        }
    
    def gather_intelligence(self, target: str, sources: List[str] = None, 
                          progress_callback: Callable = None) -> Dict:
        """Gather OSINT data from multiple sources"""
        
        if sources is None:
            sources = list(self.sources.keys())
        
        results = {
            'target': target,
            'sources': {},
            'summary': {},
            'findings': []
        }
        
        for source in sources:
            if source in self.sources:
                if progress_callback:
                    progress_callback(f"Searching {source}...")
                
                try:
                    source_results = self.sources[source](target)
                    results['sources'][source] = source_results
                    
                    # Extract key findings
                    if source_results.get('status') == 'success':
                        findings = self._extract_findings(source, source_results)
                        results['findings'].extend(findings)
                        
                except Exception as e:
                    results['sources'][source] = {'status': 'error', 'error': str(e)}
        
        # Generate summary
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _search_shodan(self, target: str) -> Dict:
        """Search Shodan for target information (free tier)"""
        
        try:
            # Get proxy settings
            proxies = {}
            try:
                from app.core.proxy_manager import proxy_manager
                proxies = proxy_manager.get_proxy_dict()
            except ImportError:
                pass
            
            # Use Shodan's free search (limited)
            url = f"https://www.shodan.io/search?query={quote(target)}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            
            response = requests.get(url, headers=headers, timeout=self.timeout, proxies=proxies)
            
            if response.status_code == 200:
                # Basic parsing of Shodan results (simplified)
                content = response.text
                
                # Extract basic information
                ports = re.findall(r'Port (\d+)', content)
                services = re.findall(r'Service: ([^<\n]+)', content)
                
                return {
                    'status': 'success',
                    'ports': list(set(ports[:10])),  # Limit results
                    'services': list(set(services[:10])),
                    'source_url': url
                }
            else:
                return {'status': 'error', 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _search_virustotal(self, target: str) -> Dict:
        """Search VirusTotal for domain information (free tier)"""
        
        try:
            # Get proxy settings
            proxies = {}
            try:
                from app.core.proxy_manager import proxy_manager
                proxies = proxy_manager.get_proxy_dict()
            except ImportError:
                pass
            
            # Use VirusTotal's public interface
            url = f"https://www.virustotal.com/gui/domain/{target}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            
            response = requests.get(url, headers=headers, timeout=self.timeout, proxies=proxies)
            
            if response.status_code == 200:
                content = response.text
                
                # Extract basic reputation info
                malicious_count = len(re.findall(r'malicious', content.lower()))
                suspicious_count = len(re.findall(r'suspicious', content.lower()))
                
                return {
                    'status': 'success',
                    'reputation': {
                        'malicious_detections': malicious_count,
                        'suspicious_detections': suspicious_count,
                        'status': 'clean' if malicious_count == 0 else 'flagged'
                    },
                    'source_url': url
                }
            else:
                return {'status': 'error', 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _search_urlvoid(self, target: str) -> Dict:
        """Search URLVoid for domain reputation"""
        
        try:
            # Get proxy settings
            proxies = {}
            try:
                from app.core.proxy_manager import proxy_manager
                proxies = proxy_manager.get_proxy_dict()
            except ImportError:
                pass
            
            url = f"https://www.urlvoid.com/scan/{target}/"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            
            response = requests.get(url, headers=headers, timeout=self.timeout, proxies=proxies)
            
            if response.status_code == 200:
                content = response.text
                
                # Extract reputation information
                detection_count = len(re.findall(r'detection', content.lower()))
                safety_score = re.search(r'Safety Score: (\d+)', content)
                
                return {
                    'status': 'success',
                    'reputation': {
                        'detections': detection_count,
                        'safety_score': safety_score.group(1) if safety_score else 'unknown'
                    },
                    'source_url': url
                }
            else:
                return {'status': 'error', 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _search_whois(self, target: str) -> Dict:
        """Perform WHOIS lookup"""
        
        try:
            import socket
            
            # Simple WHOIS query
            whois_server = "whois.internic.net"
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((whois_server, 43))
            sock.send(f"{target}\r\n".encode())
            
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            
            whois_data = response.decode('utf-8', errors='ignore')
            
            # Extract key information
            registrar = re.search(r'Registrar: (.+)', whois_data)
            creation_date = re.search(r'Creation Date: (.+)', whois_data)
            expiration_date = re.search(r'Registry Expiry Date: (.+)', whois_data)
            
            return {
                'status': 'success',
                'registrar': registrar.group(1).strip() if registrar else 'unknown',
                'creation_date': creation_date.group(1).strip() if creation_date else 'unknown',
                'expiration_date': expiration_date.group(1).strip() if expiration_date else 'unknown',
                'raw_data': whois_data[:500]  # Truncate for display
            }
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _search_dns_dumpster(self, target: str) -> Dict:
        """Search DNS Dumpster for DNS information"""
        
        try:
            # Get proxy settings
            proxies = {}
            try:
                from app.core.proxy_manager import proxy_manager
                proxies = proxy_manager.get_proxy_dict()
            except ImportError:
                pass
            
            url = "https://dnsdumpster.com/"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            
            # Get CSRF token first
            session = requests.Session()
            response = session.get(url, headers=headers, timeout=self.timeout, proxies=proxies)
            
            if response.status_code == 200:
                # Extract CSRF token
                csrf_token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', response.text)
                
                if csrf_token:
                    # Submit search
                    data = {
                        'csrfmiddlewaretoken': csrf_token.group(1),
                        'targetip': target
                    }
                    
                    search_response = session.post(url, data=data, headers=headers, 
                                                 timeout=self.timeout, proxies=proxies)
                    
                    if search_response.status_code == 200:
                        content = search_response.text
                        
                        # Extract DNS records
                        dns_records = re.findall(r'(\w+\.\w+\.\w+)', content)
                        mx_records = re.findall(r'MX.*?(\w+\.\w+)', content)
                        
                        return {
                            'status': 'success',
                            'dns_records': list(set(dns_records[:20])),
                            'mx_records': list(set(mx_records[:10])),
                            'source_url': url
                        }
            
            return {'status': 'error', 'error': 'Failed to retrieve data'}
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _extract_findings(self, source: str, data: Dict) -> List[Dict]:
        """Extract key findings from source data"""
        
        findings = []
        
        if data.get('status') != 'success':
            return findings
        
        if source == 'shodan':
            if data.get('ports'):
                findings.append({
                    'type': 'open_ports',
                    'source': source,
                    'data': data['ports'],
                    'severity': 'medium'
                })
            if data.get('services'):
                findings.append({
                    'type': 'services',
                    'source': source,
                    'data': data['services'],
                    'severity': 'info'
                })
        
        elif source == 'virustotal':
            reputation = data.get('reputation', {})
            if reputation.get('status') == 'flagged':
                findings.append({
                    'type': 'reputation_issue',
                    'source': source,
                    'data': f"Flagged by {reputation.get('malicious_detections', 0)} engines",
                    'severity': 'high'
                })
        
        elif source == 'whois':
            if data.get('registrar') != 'unknown':
                findings.append({
                    'type': 'domain_info',
                    'source': source,
                    'data': f"Registrar: {data.get('registrar')}",
                    'severity': 'info'
                })
        
        return findings
    
    def _generate_summary(self, results: Dict) -> Dict:
        """Generate summary of OSINT findings"""
        
        summary = {
            'sources_queried': len(results['sources']),
            'successful_sources': len([s for s in results['sources'].values() if s.get('status') == 'success']),
            'total_findings': len(results['findings']),
            'severity_breakdown': {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }
        
        # Count findings by severity
        for finding in results['findings']:
            severity = finding.get('severity', 'info')
            if severity in summary['severity_breakdown']:
                summary['severity_breakdown'][severity] += 1
        
        return summary

# Global instance
osint_collector = OSINTCollector()