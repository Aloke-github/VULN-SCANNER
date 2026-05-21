import requests
from urllib.parse import urljoin
import json
import re

class APIScanner:
    def __init__(self, url, args):
        self.url = url.rstrip('/')
        self.args = args
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}
        if args.cookies:
            for cookie in args.cookies.split(';'):
                if '=' in cookie:
                    key, val = cookie.strip().split('=', 1)
                    self.session.cookies[key] = val
        
        self.results = []
        self.discovered_endpoints = []
    
    def discover_endpoints(self):
        """Discover API endpoints from the page and common patterns"""
        endpoints = []
        
        # Common API base paths to try
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/graphql',
            '/swagger.json', '/swagger.yaml', '/openapi.json', '/api/docs',
            '/api/doc', '/api/swagger', '/api/swagger.json',
            '/api/health', '/api/status', '/api/version',
            '/api/users', '/api/admin', '/api/config', '/api/settings'
        ]
        
        for path in api_paths:
            test_url = urljoin(self.url, path)
            endpoints.append({
                'url': test_url,
                'method': 'GET',
                'type': 'discovery'
            })
        
        return endpoints
    
    def test_bola(self, endpoint):
        """Test for Broken Object Level Authorization (IDOR in API)"""
        # Try accessing other users' data by changing IDs
        id_patterns = [
            ('/users/1', '/users/2', '/users/3'),
            ('/user/1', '/user/2', '/user/3'),
            ('/api/users/1', '/api/users/2', '/api/users/3'),
            ('/account/1', '/account/2', '/account/3'),
            ('/profile/1', '/profile/2', '/profile/3'),
            ('/orders/1', '/orders/2', '/orders/3'),
            ('/invoices/1', '/invoices/2', '/invoices/3'),
        ]
        
        for base_url in [self.url]:
            for pattern in id_patterns:
                for test_path in pattern[1:]:  # Skip the first one (current user)
                    try:
                        # Remove trailing path and replace with test
                        parsed = urlparse(base_url)
                        base = f"{parsed.scheme}://{parsed.netloc}"
                        test_url = urljoin(base, test_path)
                        
                        response = self.session.get(test_url, timeout=5)
                        
                        # If we got a 200 with user data, it might be BOLA
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                if isinstance(data, dict) and ('email' in data or 'username' in data or 'role' in data):
                                    self.results.append({
                                        'url': test_url,
                                        'technique': 'BOLA / IDOR',
                                        'confidence': 'Medium',
                                        'evidence': f"Accessed {test_path} and got user data: {list(data.keys())[:5]}",
                                        'remediation': 'Implement object-level authorization checks'
                                    })
                                    return
                            except:
                                if len(response.text) > 100 and 'user' in response.text.lower():
                                    self.results.append({
                                        'url': test_url,
                                        'technique': 'BOLA / IDOR (Potential)',
                                        'confidence': 'Low',
                                        'evidence': f"Response contains 'user' data at {test_path}",
                                        'remediation': 'Verify authorization controls on object access'
                                    })
                                    return
                    except:
                        continue
    
    def test_excessive_data(self):
        """Test for excessive data exposure in API responses"""
        if not self.discovered_endpoints:
            return
        
        sensitive_patterns = [
            'password', 'secret', 'credit_card', 'ssn', 'dob', 'api_key',
            'apiKey', 'private_key', 'token', 'verificationCode',
            'resetToken', 'accessToken', 'refreshToken'
        ]
        
        for endpoint in self.discovered_endpoints[:10]:  # Test first 10
            try:
                response = self.session.get(endpoint['url'], timeout=5)
                if response.status_code == 200:
                    text = response.text.lower()
                    found_sensitive = [p for p in sensitive_patterns if p in text]
                    if found_sensitive:
                        self.results.append({
                            'url': endpoint['url'],
                            'technique': 'Excessive Data Exposure',
                            'confidence': 'High',
                            'evidence': f"Sensitive fields in response: {', '.join(found_sensitive[:5])}",
                            'remediation': 'Use response filtering/masking for sensitive fields'
                        })
            except:
                continue
    
    def test_rate_limiting(self, endpoint):
        """Test if rate limiting is implemented"""
        if not endpoint['url']:
            return
        
        try:
            # Send 20 rapid requests
            responses = []
            for i in range(20):
                response = self.session.get(endpoint['url'], timeout=3)
                responses.append(response.status_code)
            
            # If all requests succeeded (200) with no 429/429 too many requests
            if all(code == 200 for code in responses):
                self.results.append({
                    'url': endpoint['url'],
                    'technique': 'Missing Rate Limiting',
                    'confidence': 'Medium',
                    'evidence': '20 rapid requests all returned 200 (no 429/429)',
                    'remediation': 'Implement rate limiting (429 Too Many Requests)'
                })
        except:
            pass
    
    def test_mass_assignment(self, endpoint):
        """Test for mass assignment vulnerabilities"""
        if 'api' not in endpoint['url']:
            return
        
        extra_fields = {
            'role': 'admin',
            'isAdmin': True,
            'is_admin': True,
            'privilege': 'admin',
            'verified': True,
            'email_verified': True,
            'balance': 999999,
            'credit': 'unlimited'
        }
        
        for field, value in extra_fields.items():
            try:
                json_data = {field: value}
                response = self.session.post(endpoint['url'], json=json_data, timeout=5)
                
                if response.status_code in [200, 201, 202]:
                    # Check if our extra field was accepted
                    try:
                        resp_data = response.json()
                        if field in str(resp_data):
                            self.results.append({
                                'url': endpoint['url'],
                                'technique': f'Mass Assignment (Field: {field})',
                                'confidence': 'Medium',
                                'evidence': f"Extra field '{field}={value}' was accepted in request",
                                'remediation': 'Use allow-lists for updatable fields'
                            })
                            return
                    except:
                        pass
            except:
                continue
    
    def scan(self):
        """Main API security scan"""
        print("    [*] Discovering API endpoints...")
        
        endpoints = self.discover_endpoints()
        print(f"    [*] Testing {len(endpoints)} discovered endpoints...")
        
        # Test each endpoint
        for endpoint in endpoints:
            try:
                response = self.session.get(endpoint['url'], timeout=5)
                if response.status_code != 404:
                    self.discovered_endpoints.append(endpoint)
                    print(f"    [*] Discovered: {endpoint['url']} ({response.status_code})")
            except:
                continue
        
        if not self.discovered_endpoints:
            print("    [!] No API endpoints discovered")
            return self.results
        
        # Run API-specific tests
        print("    [*] Testing for BOLA/IDOR...")
        for ep in self.discovered_endpoints[:5]:
            self.test_bola(ep)
        
        print("    [*] Testing for excessive data exposure...")
        self.test_excessive_data()
        
        print("    [*] Testing rate limiting...")
        for ep in self.discovered_endpoints[:3]:
            self.test_rate_limiting(ep)
        
        print("    [*] Testing mass assignment...")
        for ep in self.discovered_endpoints[:3]:
            self.test_mass_assignment(ep)
        
        if self.results:
            print(f"    [!] Found {len(self.results)} API vulnerabilities")
        else:
            print("    [+] No API vulnerabilities detected")
        
        return self.results