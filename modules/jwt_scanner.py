import requests
import re
import base64
import json
from urllib.parse import urlparse
import hashlib
import hmac

class JWTScanner:
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
        
        self.results = {
            'tokens_found': [],
            'vulnerabilities': []
        }
    
    def decode_jwt(self, token):
        """Decode JWT without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None, None, None
            
            # Decode header
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            try:
                header = json.loads(base64.urlsafe_b64decode(header_padded))
            except:
                header = json.loads(base64.b64decode(parts[0] + '=='))
            
            # Decode payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            try:
                payload = json.loads(base64.urlsafe_b64decode(payload_padded))
            except:
                payload = json.loads(base64.b64decode(parts[1] + '=='))
            
            signature = parts[2]
            return header, payload, signature
            
        except Exception as e:
            return None, None, None
    
    def analyze_jwt(self, token, source):
        """Analyze a JWT token for vulnerabilities"""
        header, payload, signature = self.decode_jwt(token)
        
        if not header or not payload:
            return
        
        # Store found token info (truncate sensitive values)
        sanitized_payload = {}
        for k, v in payload.items():
            if k.lower() in ['password', 'secret', 'token', 'key', 'pin', 'cvv']:
                sanitized_payload[k] = '***REDACTED***'
            else:
                sanitized_payload[k] = v
        
        self.results['tokens_found'].append({
            'token': token[:80] + '...',
            'source': source,
            'header': header,
            'payload': sanitized_payload
        })
        
        issues = []
        
        # 1. Check for 'none' algorithm
        alg = header.get('alg', '').lower()
        if alg == 'none':
            issues.append({
                'issue': 'alg=none JWT accepted',
                'severity': 'Critical',
                'detail': 'Server accepts tokens with no signature. Can forge arbitrary tokens.',
                'remediation': 'Reject tokens with alg: none'
            })
        
        # 2. Check for weak algorithm and try common secrets
        if alg in ['hs256', 'hs384', 'hs512']:
            common_secrets = ['secret', 'password', 'key', '123456', 'admin', 
                            'changeme', 'test', 'jwt_secret', 'mysecret', 
                            'supersecret', 'pass', '12345', 'abc123']
            for secret in common_secrets:
                try:
                    msg = token.rsplit('.', 1)[0]
                    if alg == 'hs256':
                        sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
                    elif alg == 'hs384':
                        sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha384).digest()
                    else:
                        sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha512).digest()
                    
                    expected_sig = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
                    if expected_sig == token.rsplit('.', 1)[1]:
                        issues.append({
                            'issue': f'Weak JWT secret detected: "{secret}"',
                            'severity': 'Critical',
                            'detail': f'Token was verified with commonly used secret "{secret}"',
                            'remediation': 'Use a strong, random secret key (256+ bits)'
                        })
                        break
                except:
                    pass
        
        # 3. Check algorithm confusion (RS256 vs HS256)
        if alg == 'rs256':
            issues.append({
                'issue': 'Algorithm confusion potential (RS256)',
                'severity': 'High',
                'detail': 'If public key is known, attacker can change alg to HS256 and sign with public key',
                'remediation': 'Always validate algorithm against expected value, use asymmetric keys correctly'
            })
        
        # 4. Check for sensitive info in payload
        sensitive_keys = ['password', 'secret', 'token', 'api_key', 'apikey', 
                         'credit_card', 'ssn', 'dob', 'pin', 'cvv', 'private']
        for key in sensitive_keys:
            if key in payload or any(key in str(k).lower() for k in payload.keys()):
                issues.append({
                    'issue': f'Sensitive data in JWT payload: "{key}"',
                    'severity': 'High',
                    'detail': f'JWT payload contains potentially sensitive field: {key}',
                    'remediation': 'Never store sensitive data in JWT payload (it is only base64 encoded, not encrypted)'
                })
        
        # 5. Check for expired token or no expiration
        if 'exp' not in payload:
            issues.append({
                'issue': 'JWT has no expiration (exp) claim',
                'severity': 'Medium',
                'detail': 'Token never expires, increasing risk if stolen',
                'remediation': 'Always include exp claim with reasonable expiry time'
            })
        
        # 6. Check for "kid" header injection
        if 'kid' in header:
            kid_value = str(header['kid'])
            if '../' in kid_value or '..\\' in kid_value:
                issues.append({
                    'issue': 'Potential kid path traversal',
                    'severity': 'High',
                    'detail': f'kid header contains path traversal: {kid_value}',
                    'remediation': 'Validate and sanitize kid header, do not use file paths'
                })
            if kid_value.startswith('/'):
                issues.append({
                    'issue': 'Potential kid absolute path injection',
                    'severity': 'Medium',
                    'detail': 'kid header contains absolute path, could read arbitrary files',
                    'remediation': 'Restrict kid to predefined keys only'
                })
        
        # 7. Check for jku header (JWK Set URL)
        if 'jku' in header:
            issues.append({
                'issue': 'JKU header present - potential SSRF/Key injection',
                'severity': 'High',
                'detail': 'Server fetches keys from external URL specified in token',
                'remediation': 'Disable jku header or whitelist allowed URLs'
            })
        
        # 8. Check for jwk embedded key
        if 'jwk' in header:
            issues.append({
                'issue': 'JWK (embedded key) header present',
                'severity': 'Critical',
                'detail': 'Token contains its own key. Attacker can forge tokens with self-generated keys.',
                'remediation': 'Disable jwk header support'
            })
        
        self.results['vulnerabilities'].extend(issues)
    
    def find_tokens_in_response_text(self, response_text, source):
        """Find JWT tokens in a response body string"""
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        tokens = re.findall(jwt_pattern, response_text)
        
        for token in tokens:
            self.analyze_jwt(token, source)
    
    def find_tokens_in_response_object(self, response, source):
        """Find JWT tokens in a full response object"""
        # Check response body
        self.find_tokens_in_response_text(response.text, f'{source} - Body')
        
        # Check Authorization header
        auth_header = response.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            self.analyze_jwt(token, f'{source} - Authorization Header')
        
        # Check Set-Cookie headers
        set_cookie = response.headers.get('Set-Cookie', '')
        if set_cookie:
            for cookie_part in set_cookie.split(';'):
                if '=' in cookie_part:
                    key, val = cookie_part.strip().split('=', 1)
                    if any(pattern in key.lower() for pattern in ['token', 'jwt', 'auth']):
                        if val.startswith('eyJ'):
                            self.analyze_jwt(val, f'{source} - Set-Cookie: {key}')
    
    def scan(self):
        """Main JWT scan"""
        print("    [*] Fetching target and checking for JWT tokens...")
        
        try:
            response = self.session.get(self.url, timeout=self.args.timeout)
        except Exception as e:
            print(f"    [!] Error fetching target: {e}")
            return self.results
        
        # Check response object for tokens
        self.find_tokens_in_response_object(response, 'Main Page')
        
        # Check cookies from session
        for cookie_name, cookie_value in self.session.cookies.items():
            jwt_cookie_patterns = ['token', 'jwt', 'access_token', 'auth', 'session', 'bearer']
            if any(pattern in cookie_name.lower() for pattern in jwt_cookie_patterns):
                if cookie_value.startswith('eyJ'):
                    self.analyze_jwt(cookie_value, f'Cookie: {cookie_name}')
        
        # Check for common authentication endpoints
        auth_endpoints = ['/api/auth', '/api/login', '/api/token', '/auth', '/login', 
                         '/api/v1/auth', '/api/authenticate', '/api/me', '/api/user']
        for endpoint in auth_endpoints:
            try:
                test_url = f"{self.url.rstrip('/')}{endpoint}"
                auth_response = self.session.get(test_url, timeout=5)
                self.find_tokens_in_response_object(auth_response, f'Auth Endpoint: {endpoint}')
            except:
                continue
        
        if self.results['tokens_found']:
            print(f"    [!] Found {len(self.results['tokens_found'])} JWT token(s)")
            for vuln in self.results['vulnerabilities']:
                severity_icon = {'Critical': '🚨', 'High': '🔥', 'Medium': '⚠️'}
                print(f"    {severity_icon.get(vuln['severity'], 'ℹ️')} [{vuln['severity']}] {vuln['issue']}")
        else:
            print("    [+] No JWT tokens detected")
        
        return self.results