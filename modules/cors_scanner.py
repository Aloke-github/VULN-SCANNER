import requests
from urllib.parse import urlparse

class CORSScanner:
    def __init__(self, url, args):
        self.url = url.rstrip('/')
        self.args = args
        self.session = requests.Session()
        self.results = []
    
    def test_origin_reflection(self):
        """Test if the server reflects arbitrary origins"""
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            'null',
            'file://',
            'https://evil.' + urlparse(self.url).netloc,
            'https://' + urlparse(self.url).netloc + '.evil.com',
            'http://localhost:8080'
        ]
        
        for origin in test_origins:
            try:
                response = self.session.get(
                    self.url,
                    headers={
                        'Origin': origin,
                        'User-Agent': 'Mozilla/5.0'
                    },
                    timeout=self.args.timeout
                )
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == origin:
                    vuln = {
                        'url': self.url,
                        'technique': 'CORS Misconfiguration - Origin Reflection',
                        'severity': 'Critical' if acac == 'true' else 'High',
                        'evidence': f"ACAO: {acao}, Credentials: {acac}",
                        'detail': f"Reflected origin '{origin}' in Access-Control-Allow-Origin header",
                        'remediation': 'Use a whitelist of allowed origins, not dynamic reflection'
                    }
                    
                    if acac == 'true':
                        vuln['detail'] += ' with credentials enabled - full account takeover possible'
                    
                    self.results.append(vuln)
                    return vuln
                    
            except Exception:
                continue
        
        return None
    
    def test_wildcard_origin(self):
        """Test for wildcard origin with credentials"""
        try:
            response = self.session.get(
                self.url,
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=self.args.timeout
            )
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*' and acac == 'true':
                self.results.append({
                    'url': self.url,
                    'technique': 'CORS Misconfiguration - Wildcard with Credentials',
                    'severity': 'Critical',
                    'evidence': f"ACAO: *, Credentials: true",
                    'detail': 'Wildcard origin (*) with credentials enabled allows any website to read responses',
                    'remediation': 'Remove wildcard when using credentials, specify exact origins'
                })
                return True
        except Exception:
            pass
        
        return False
    
    def test_preflight_bypass(self):
        """Test if preflight requests are properly secured"""
        try:
            # Send OPTIONS request with malicious origin
            response = self.session.options(
                self.url,
                headers={
                    'Origin': 'https://evil.com',
                    'Access-Control-Request-Method': 'GET',
                    'User-Agent': 'Mozilla/5.0'
                },
                timeout=self.args.timeout
            )
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acam = response.headers.get('Access-Control-Allow-Methods', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao:
                self.results.append({
                    'url': self.url,
                    'technique': 'CORS - Preflight Response',
                    'severity': 'Info',
                    'evidence': f"Preflight ACAO: {acao}, Methods: {acam}, Credentials: {acac}",
                    'detail': 'Server responds to preflight requests',
                    'remediation': 'Ensure preflight responses are properly restricted'
                })
        except Exception:
            pass
    
    def test_headers_exposure(self):
        """Check which CORS headers are exposed"""
        try:
            response = self.session.get(self.url, timeout=self.args.timeout)
            
            headers_to_check = {
                'Access-Control-Allow-Origin': 'ACAO',
                'Access-Control-Allow-Credentials': 'ACAC',
                'Access-Control-Allow-Methods': 'ACAM',
                'Access-Control-Allow-Headers': 'ACAH',
                'Access-Control-Expose-Headers': 'ACEH',
                'Access-Control-Max-Age': 'ACMA'
            }
            
            found_headers = {}
            for header, short in headers_to_check.items():
                if header in response.headers:
                    found_headers[short] = response.headers[header]
            
            if found_headers:
                self.results.append({
                    'url': self.url,
                    'technique': 'CORS Headers Present',
                    'severity': 'Info',
                    'evidence': str(found_headers),
                    'detail': f"CORS headers found: {', '.join(found_headers.keys())}",
                    'remediation': 'Verify each CORS header is intentionally set and properly scoped'
                })
                
        except Exception:
            pass
    
    def scan(self):
        """Main CORS scan"""
        print("    [*] Testing CORS configuration...")
        
        # Test 1: Origin reflection
        print("    [*] Testing origin reflection...")
        result = self.test_origin_reflection()
        if result:
            print(f"    [!] {result['severity']}: {result['technique']}")
            print(f"       {result['detail'][:100]}")
        
        # Test 2: Wildcard with credentials
        print("    [*] Testing wildcard origin...")
        self.test_wildcard_origin()
        
        # Test 3: Preflight
        print("    [*] Testing preflight responses...")
        self.test_preflight_bypass()
        
        # Test 4: Header exposure
        self.test_headers_exposure()
        
        if self.results:
            print(f"    [!] Found {len(self.results)} CORS issues")
        else:
            print("    [+] No dangerous CORS misconfigurations detected")
        
        return self.results