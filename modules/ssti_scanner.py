import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import time


class SSTIScanner:
    def __init__(self, url, args, session=None):
        self.url = url.rstrip('/')
        self.args = args
        self.session = session if session else requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        })

        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}

        self.results = []

    SSTI_PAYLOADS = {
        'Jinja2 (Python/Django)': [
            '{{7*7}}',
            '{{7*\'7\'}}',
        ],
        'Twig (PHP/Symfony)': [
            '{{7*7}}',
        ],
        'FreeMarker (Java)': [
            '${7*7}',
        ],
        'Velocity (Java)': [
            '#set($x=7*7)$x',
        ],
        'Smarty (PHP)': [
            '{$7*7}',
        ],
        'Jade/Pug (Node.js)': [
            '#{7*7}',
        ],
        'ERB (Ruby/Rails)': [
            '<%= 7*7 %>',
        ]
    }

    def find_vectors(self):
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

            # If no vectors found, add common ones
            if not vectors:
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
        for engine, payloads in self.SSTI_PAYLOADS.items():
            for payload in payloads:
                try:
                    test_params = {vector['param']: payload}

                    if vector.get('method') == 'POST':
                        response = self.session.post(vector['url'], data=test_params,
                                                     timeout=self.args.timeout)
                    else:
                        response = self.session.get(vector['url'], params=test_params,
                                                    timeout=self.args.timeout)

                    resp_text = response.text

                    # ============================================================
                    # CRITICAL FALSE POSITIVE CHECK
                    # If the payload syntax ({{, ${, #{, etc.) appears literally in
                    # the response, the template was NOT evaluated — it's reflection
                    # ============================================================

                    # Check if literal template markers appear in response
                    markers_in_response = []
                    for marker in ['{{', '}}', '${', '{$', '#{', '#set', '<%', '%>']:
                        if marker in resp_text and marker in payload:
                            markers_in_response.append(marker)

                    if markers_in_response:
                        # Template syntax was literally reflected — NOT SSTI!
                        continue

                    # ============================================================
                    # REAL SSTI CHECK 1: 7*7 = 49
                    # If the math was evaluated, we should see "49" in response
                    # WITHOUT seeing "{{7*7}}" or "${7*7}" literally
                    # ============================================================
                    if '7*7' in payload and '49' in resp_text:
                        # Verify the original payload text is NOT in response
                        payload_clean = payload.replace('{', '').replace('}', '')
                        payload_clean = payload_clean.replace('$', '').replace('#', '')
                        payload_clean = payload_clean.replace('<%', '').replace('%>', '')

                        # Make sure our payload text isn't literally reflected
                        if '7*7' not in resp_text.replace('49', ''):
                            self.results.append({
                                'url': vector['url'],
                                'param': vector['param'],
                                'technique': f'SSTI - {engine} (Math Eval)',
                                'payload': payload,
                                'severity': 'Critical',
                                'evidence': f'Template evaluated: 7*7 = 49',
                                'remediation': 'Never render user input as templates. Use output encoding.'
                            })
                            return True

                    # ============================================================
                    # REAL SSTI CHECK 2: 7*'7' = 7777777 (string multiplication)
                    # ============================================================
                    if "7*'7'" in payload and '7777777' in resp_text:
                        if "7*'7'" not in resp_text:
                            self.results.append({
                                'url': vector['url'],
                                'param': vector['param'],
                                'technique': f'SSTI - {engine} (String Mult)',
                                'payload': payload,
                                'severity': 'Critical',
                                'evidence': f'String multiplication: 7*\'7\' = 7777777',
                                'remediation': 'Never render user input as templates.'
                            })
                            return True

                    # ============================================================
                    # REAL SSTI CHECK 3: $x from #set($x=7*7)$x (Velocity)
                    # The response should contain "49" from the variable, not "#set(...)"
                    # ============================================================
                    if '#set($x=7*7)$x' in payload and '49' in resp_text:
                        if '#set($x=7*7)$x' not in resp_text:
                            self.results.append({
                                'url': vector['url'],
                                'param': vector['param'],
                                'technique': 'SSTI - Velocity (Java)',
                                'payload': payload,
                                'severity': 'Critical',
                                'evidence': 'Velocity variable evaluated: $x = 49',
                                'remediation': 'Never render user input as templates.'
                            })
                            return True

                except Exception:
                    continue

        return False

    def scan(self):
        print("    [*] Finding template injection vectors...")

        vectors = self.find_vectors()
        if not vectors:
            print("    [!] No SSTI vectors found")
            return self.results

        total_payloads = sum(len(p) for p in self.SSTI_PAYLOADS.values())
        print(f"    [*] Testing {len(vectors)} vectors with {total_payloads} payloads...")
        print(f"    [*] Testing engines: {', '.join(self.SSTI_PAYLOADS.keys())}")

        for vector in vectors:
            if self.test_ssti(vector):
                print(f"    🚨 SSTI Found! {self.results[-1]['technique']}")

        if self.results:
            print(f"\n    [!] Found {len(self.results)} SSTI vulnerabilities!")
        else:
            print("    [+] No template injection vulnerabilities detected")

        return self.results