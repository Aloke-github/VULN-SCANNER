import requests

class HeadersScanner:
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
    
    # Security headers to check with their descriptions and recommended values
    HEADERS_CHECK = {
        'Strict-Transport-Security': {
            'description': 'Enforces HTTPS connections',
            'recommended': 'max-age=31536000; includeSubDomains',
            'severity': 'High',
            'missing_severity': 'Medium'
        },
        'Content-Security-Policy': {
            'description': 'Prevents XSS and data injection attacks',
            'recommended': "default-src 'self'",
            'severity': 'Critical',
            'missing_severity': 'High'
        },
        'X-Content-Type-Options': {
            'description': 'Prevents MIME type sniffing',
            'recommended': 'nosniff',
            'severity': 'Medium',
            'missing_severity': 'Medium'
        },
        'X-Frame-Options': {
            'description': 'Prevents clickjacking attacks',
            'recommended': 'DENY or SAMEORIGIN',
            'severity': 'Medium',
            'missing_severity': 'Medium'
        },
        'X-XSS-Protection': {
            'description': 'Enables browser XSS filter (deprecated but still useful)',
            'recommended': '1; mode=block',
            'severity': 'Low',
            'missing_severity': 'Low'
        },
        'Referrer-Policy': {
            'description': 'Controls referrer information sent with requests',
            'recommended': 'strict-origin-when-cross-origin',
            'severity': 'Low',
            'missing_severity': 'Low'
        },
        'Permissions-Policy': {
            'description': 'Controls browser features (camera, mic, etc.)',
            'recommended': "camera=(), microphone=(), geolocation=()",
            'severity': 'Low',
            'missing_severity': 'Info'
        },
        'Cache-Control': {
            'description': 'Prevents sensitive data caching',
            'recommended': 'no-store, no-cache, must-revalidate',
            'severity': 'Medium',
            'missing_severity': 'Info'
        },
        'Set-Cookie': {
            'description': 'Should include Secure, HttpOnly, SameSite flags',
            'recommended': 'Secure; HttpOnly; SameSite=Lax',
            'severity': 'High',
            'missing_severity': 'Info'
        },
        'Access-Control-Allow-Origin': {
            'description': 'CORS header - should not be wildcard with credentials',
            'recommended': 'Specific origins only',
            'severity': 'High',
            'missing_severity': 'Info'
        }
    }
    
    def check_headers(self, response):
        """Check all security headers"""
        headers = response.headers
        
        for header, info in self.HEADERS_CHECK.items():
            if header in headers:
                value = headers[header]
                
                # Check for weak configurations
                if header == 'Strict-Transport-Security':
                    if 'max-age=0' in value:
                        self.results.append({
                            'header': header,
                            'technique': f'Weak {header}',
                            'severity': 'High',
                            'evidence': value,
                            'detail': 'HSTS max-age is 0 (disables HSTS)',
                            'remediation': f"Set: {info['recommended']}"
                        })
                    elif 'max-age' in value:
                        # Check if max-age is too short
                        import re
                        match = re.search(r'max-age=(\d+)', value)
                        if match and int(match.group(1)) < 31536000:
                            self.results.append({
                                'header': header,
                                'technique': f'Weak {header}',
                                'severity': 'Low',
                                'evidence': value,
                                'detail': f'HSTS max-age is {match.group(1)} (recommended: 31536000)',
                                'remediation': f"Set: {info['recommended']}"
                            })
                    else:
                        # Just report it's present
                        self.results.append({
                            'header': header,
                            'technique': f'{header} Present',
                            'severity': 'Info',
                            'evidence': value,
                            'detail': f"{info['description']}",
                            'remediation': 'Header is present - good'
                        })
                
                elif header == 'X-Frame-Options':
                    if value.upper() not in ['DENY', 'SAMEORIGIN']:
                        self.results.append({
                            'header': header,
                            'technique': f'Weak {header}',
                            'severity': 'Medium',
                            'evidence': value,
                            'detail': 'Allow-from is deprecated and may not protect against clickjacking',
                            'remediation': f"Use: {info['recommended']}"
                        })
                    else:
                        self.results.append({
                            'header': header,
                            'technique': f'{header} Present',
                            'severity': 'Info',
                            'evidence': value,
                            'detail': 'Protects against clickjacking',
                            'remediation': 'Header is properly set'
                        })
                
                elif header == 'Content-Security-Policy':
                    # Check for common CSP weaknesses
                    weaknesses = []
                    if "'unsafe-inline'" in value:
                        weaknesses.append('unsafe-inline')
                    if "'unsafe-eval'" in value:
                        weaknesses.append('unsafe-eval')
                    if value.count('*') > 2:
                        weaknesses.append('wildcard sources')
                    if "http://" in value:
                        weaknesses.append('HTTP sources allowed')
                    
                    if weaknesses:
                        self.results.append({
                            'header': header,
                            'technique': f'Weak {header}',
                            'severity': 'High',
                            'evidence': f"Weaknesses: {', '.join(weaknesses)}",
                            'detail': f"CSP allows: {', '.join(weaknesses)}",
                            'remediation': f"Remove {', '.join(weaknesses)} from CSP policy"
                        })
                    else:
                        self.results.append({
                            'header': header,
                            'technique': f'{header} Present',
                            'severity': 'Info',
                            'evidence': value[:80],
                            'detail': 'CSP is configured',
                            'remediation': 'Verify CSP policy is restrictive enough'
                        })
                
                elif header == 'Set-Cookie':
                    # Check cookie flags
                    missing_flags = []
                    if 'Secure' not in value:
                        missing_flags.append('Secure')
                    if 'HttpOnly' not in value:
                        missing_flags.append('HttpOnly')
                    if 'SameSite' not in value:
                        missing_flags.append('SameSite')
                    
                    if missing_flags:
                        self.results.append({
                            'header': header,
                            'technique': f'Insecure Cookie - Missing {", ".join(missing_flags)}',
                            'severity': 'High',
                            'evidence': value[:80],
                            'detail': f"Cookie missing flags: {', '.join(missing_flags)}",
                            'remediation': f"Add: {', '.join(missing_flags)} to cookie"
                        })
                
                else:
                    # Generic present
                    self.results.append({
                        'header': header,
                        'technique': f'{header} Present',
                        'severity': 'Info',
                        'evidence': value[:60],
                        'detail': info['description'],
                        'remediation': 'Verify header value is correct'
                    })
            else:
                # Header is missing
                self.results.append({
                    'header': header,
                    'technique': f'Missing {header}',
                    'severity': info['missing_severity'],
                    'evidence': 'Header not found',
                    'detail': f"{info['description']} - Not configured",
                    'remediation': f"Add header: {header}: {info['recommended']}"
                })
    
    def check_server_info(self, response):
        """Check for information disclosure via server headers"""
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
                       'X-Drupal-Cache', 'X-Generator', 'X-Varnish', 'Via',
                       'X-Backend-Server', 'X-Cache', 'X-Served-By']
        
        for header in info_headers:
            if header in response.headers:
                value = response.headers[header]
                # If it exposes detailed version info, flag it
                if any(c.isdigit() for c in value):
                    self.results.append({
                        'header': header,
                        'technique': f'Information Disclosure - {header}',
                        'severity': 'Low',
                        'evidence': f"{header}: {value}",
                        'detail': f'Server reveals version information: {value}',
                        'remediation': 'Remove or obfuscate server version headers'
                    })
    
    def scan(self):
        """Main security headers scan"""
        print("    [*] Checking HTTP security headers...")
        
        try:
            response = self.session.get(self.url, timeout=self.args.timeout)
        except Exception as e:
            print(f"    [!] Error fetching target: {e}")
            return self.results
        
        # Run checks
        self.check_headers(response)
        self.check_server_info(response)
        
        # Calculate score
        score = 0
        max_score = len(self.HEADERS_CHECK)
        present_count = sum(1 for r in self.results if r['header'] in self.HEADERS_CHECK and 'Present' in r['technique'])
        score = int((present_count / max_score) * 100) if max_score > 0 else 0
        
        # Print results
        print(f"    [*] Security Headers Score: {score}/100")
        
        if score < 50:
            print(f"    [!] Poor security headers configuration!")
        elif score < 80:
            print(f"    [*] Moderate security headers")
        else:
            print(f"    [+] Good security headers")
        
        # Print missing/weak headers
        critical_issues = [r for r in self.results if r.get('severity') in ['Critical', 'High'] and 'Present' not in r['technique']]
        if critical_issues:
            print(f"    [!] Missing/Weak critical headers:")
            for issue in critical_issues:
                print(f"       {issue['header']}: {issue['detail'][:80]}")
        
        return self.results