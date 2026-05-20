import requests
import subprocess
import json
import re
from urllib.parse import urlparse

class Recon:
    def __init__(self, url, args):
        self.url = url
        self.args = args
        self.domain = urlparse(url).netloc
        self.results = {
            'subdomains': [],
            'technologies': [],
            'open_ports': [],
            'http_headers': {},
            'waf': None
        }
    
    def run(self):
        """Run all reconnaissance modules"""
        self.get_http_headers()
        self.detect_technologies()
        self.detect_waf()
        self.check_subdomains()  # Uses subfinder if available
        
        return self.results
    
    def get_http_headers(self):
        """Get HTTP response headers"""
        try:
            response = requests.get(self.url, timeout=10, 
                                  headers={'User-Agent': 'Mozilla/5.0'})
            self.results['http_headers'] = dict(response.headers)
            
            # Extract server info
            server = response.headers.get('Server', 'Unknown')
            self.results['technologies'].append(f'Server: {server}')
            
        except Exception as e:
            self.results['http_headers'] = {'error': str(e)}
    
    def detect_technologies(self):
        """Simple technology detection via headers and HTML"""
        try:
            response = requests.get(self.url, timeout=10,
                                  headers={'User-Agent': 'Mozilla/5.0'})
            html = response.text.lower()
            
            tech_signatures = {
                'WordPress': ['/wp-content/', '/wp-includes/', 'wordpress'],
                'Joomla': ['/components/', '/modules/', 'joomla'],
                'Drupal': ['drupal', '/sites/default/'],
                'jQuery': ['jquery'],
                'Bootstrap': ['bootstrap'],
                'React': ['react', 'react-dom'],
                'Angular': ['angular', 'ng-'],
                'PHP': ['php', '.php'],
                'ASP.NET': ['asp.net', 'viewstate', '__viewstate'],
                'nginx': ['nginx'],
                'Apache': ['apache'],
                'Cloudflare': ['cloudflare', '__cfduid']
            }
            
            for tech, sigs in tech_signatures.items():
                if any(sig in html or sig in str(response.headers).lower() for sig in sigs):
                    if tech not in self.results['technologies']:
                        self.results['technologies'].append(tech)
            
            # Also check headers
            for header, value in response.headers.items():
                header_lower = header.lower()
                if 'x-powered-by' in header_lower:
                    self.results['technologies'].append(f'X-Powered-By: {value}')
                if 'x-generator' in header_lower:
                    self.results['technologies'].append(f'X-Generator: {value}')
                    
        except Exception:
            pass
    
    def detect_waf(self):
        """Detect Web Application Firewall"""
        try:
            # Send malicious-looking request
            payload = "' OR 1=1 UNION SELECT NULL--"
            response = requests.get(f"{self.url}?id={payload}", timeout=10)
            
            # Check for WAF indicators
            waf_signatures = {
                'Cloudflare': ['cloudflare', '__cfduid', 'cf-ray'],
                'ModSecurity': ['mod_security', 'modsecurity'],
                'AWS WAF': ['awselb', 'aws'],
                'F5 BIG-IP': ['bigip', 'f5'],
                'Akamai': ['akamai', 'akamaighost'],
                'Sucuri': ['sucuri'],
                'Barracuda': ['barracuda'],
                'Imperva': ['imperva', 'incapsula']
            }
            
            response_text = response.text.lower()
            response_headers = str(response.headers).lower()
            
            for waf, sigs in waf_signatures.items():
                if any(sig in response_text or sig in response_headers for sig in sigs):
                    self.results['waf'] = waf
                    return
            
            self.results['waf'] = 'None detected'
            
        except Exception:
            self.results['waf'] = 'Could not determine'
    
    def check_subdomains(self):
        """Check for subdomains using subfinder (Kali tool)"""
        try:
            # Check if subfinder is installed
            result = subprocess.run(['which', 'subfinder'], capture_output=True, text=True)
            if result.returncode == 0:
                print("    [*] Using subfinder for subdomain enumeration...")
                result = subprocess.run(
                    ['subfinder', '-d', self.domain, '-silent'],
                    capture_output=True, text=True, timeout=30
                )
                if result.stdout:
                    subdomains = result.stdout.strip().split('\n')
                    self.results['subdomains'] = subdomains
                    print(f"    [*] Found {len(subdomains)} subdomains")
            else:
                # Fallback: use crt.sh
                print("    [*] subfinder not found, using crt.sh...")
                crt_response = requests.get(
                    f"https://crt.sh/?q=%25.{self.domain}&output=json",
                    timeout=15
                )
                if crt_response.status_code == 200:
                    data = crt_response.json()
                    subdomains = set()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            sub = sub.strip()
                            if sub.endswith(self.domain):
                                subdomains.add(sub)
                    self.results['subdomains'] = list(subdomains)
                    
        except Exception as e:
            self.results['subdomains'] = [f"Error: {str(e)[:50]}"]