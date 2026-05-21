import requests
import re
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
from bs4 import BeautifulSoup


class IDORScanner:
    def __init__(self, url, args, session=None):
        self.url = url.rstrip('/')
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

        # CSRF tokens to EXCLUDE from IDOR testing
        self.CSRF_EXCLUDE = [
            'user_token', 'csrf_token', 'csrf', 'csrftoken', 'token',
            '_token', 'authenticity_token', 'csrfmiddlewaretoken',
            '__csrf_token__', 'nonce', '_wpnonce', 'wpnonce',
            'xsrf_token', 'xsrf', '__requestverificationtoken',
            'form_build_id', 'form_id', 'form_token',
            'session_token', 'sid', 'jsessionid', 'phpsessid',
            'login', 'submit', 'send', 'action', 'cmd',
            'password', 'passwd', 'secret'
        ]

    def _is_csrf_or_auth_token(self, param_name):
        """Check if a parameter name looks like a CSRF/security token to exclude."""
        param_lower = param_name.lower()
        for exclude in self.CSRF_EXCLUDE:
            if param_lower == exclude or param_lower.endswith('_' + exclude):
                return True
            # Check for partial matches like 'token' in 'user_token'
            if exclude in ['token', 'csrf', 'nonce', 'xsrf', 'session']:
                if exclude in param_lower:
                    return True
        return False

    def find_id_parameters(self):
        id_params = set()

        # Legitimate ID parameter names (NOT CSRF tokens)
        id_names = [
            'id', 'uid', 'uuid', 'guid',
            'user_id', 'userId', 'account_id', 'accountId',
            'profile_id', 'profileId', 'customer_id', 'customerId',
            'order_id', 'orderId', 'invoice_id', 'invoiceId',
            'transaction_id', 'transactionId', 'document_id', 'documentId',
            'file_id', 'fileId', 'product_id', 'productId',
            'item_id', 'itemId', 'article_id', 'articleId',
            'post_id', 'postId', 'comment_id', 'commentId',
            'message_id', 'messageId', 'ticket_id', 'ticketId',
            'slug', 'reference', 'ref',
            'loan_id', 'loanId', 'payment_id', 'paymentId',
            'role_id', 'roleId', 'group_id', 'groupId',
            'org_id', 'orgId', 'company_id', 'companyId',
            'student_id', 'studentId', 'employee_id', 'employeeId',
        ]

        # Check URL parameters
        parsed = urlparse(self.url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key = param.split('=')[0]
                    if self._is_csrf_or_auth_token(key):
                        continue
                    if any(id_name in key.lower() for id_name in id_names):
                        id_params.add(key)

        # Check page content for links with ID parameters
        try:
            response = self.session.get(self.url, timeout=self.args.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', href=True):
                href = link['href']
                if '?' in href:
                    query = href.split('?')[1] if '?' in href else ''
                    for param in query.split('&'):
                        if '=' in param:
                            key = param.split('=')[0]
                            if self._is_csrf_or_auth_token(key):
                                continue
                            if any(id_name in key.lower() for id_name in id_names):
                                id_params.add(key)

            # Check forms
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input'):
                    name = input_tag.get('name', '')
                    if self._is_csrf_or_auth_token(name):
                        continue
                    if any(id_name in name.lower() for id_name in id_names):
                        id_params.add(name)

        except Exception:
            pass

        return list(id_params)

    def test_idor(self, param_name):
        """Test for IDOR by manipulating ID values"""
        test_values = ['1', '2', '3', '0', '999999999', '-1', 'admin', 'null']

        for value in test_values:
            try:
                parsed = urlparse(self.url)
                if parsed.query:
                    new_params = []
                    for p in parsed.query.split('&'):
                        if '=' in p:
                            key, val = p.split('=', 1)
                            if key == param_name:
                                new_params.append(f"{key}={value}")
                            else:
                                new_params.append(p)
                    new_query = '&'.join(new_params)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                else:
                    test_url = f"{self.url}?{param_name}={value}"

                response = self.session.get(test_url, timeout=self.args.timeout)

                if response.status_code == 200:
                    user_indicators = ['email', 'username', 'profile', 'account',
                                     'ssn', 'credit', 'address', 'phone', 'role',
                                     'admin', 'settings', 'private', 'salary',
                                     'balance', 'ssn', 'dob', 'birthday']

                    resp_lower = response.text.lower()
                    found_indicators = [i for i in user_indicators if i in resp_lower]

                    if found_indicators and len(response.text) > 500:
                        self.results.append({
                            'url': test_url[:120],
                            'param': param_name,
                            'test_value': value,
                            'technique': 'IDOR - Direct Object Reference',
                            'confidence': 'Medium',
                            'evidence': f"Accessed with {param_name}={value}, indicators: {', '.join(found_indicators[:3])}",
                            'remediation': f"Implement proper authorization checks for parameter '{param_name}'"
                        })
                        return

            except Exception:
                continue

    def scan(self):
        print("    [*] Finding ID parameters...")

        id_params = self.find_id_parameters()

        if not id_params:
            print("    [*] No ID parameters found in URL, checking common patterns...")
            # Common IDOR parameters (EXCLUDING CSRF tokens)
            id_params = ['id', 'user_id', 'uid', 'uuid', 'account_id']
        else:
            # Final filter — exclude any CSRF-like params
            id_params = [p for p in id_params if not self._is_csrf_or_auth_token(p)]
            print(f"    [*] Found potential ID parameters: {', '.join(id_params)}")

        if not id_params:
            print("    [*] No suitable ID parameters found for testing")
            print("    [+] No IDOR vulnerabilities detected")
            return self.results

        print(f"    [*] Testing {len(id_params)} potential ID parameters...")

        for param in id_params:
            print(f"    [*] Testing parameter: {param}")
            self.test_idor(param)

        if self.results:
            print(f"\n    [!] Found {len(self.results)} potential IDOR vulnerabilities")
            for r in self.results:
                print(f"       {r['technique']} - {r['param']}={r.get('test_value', '?')}")
        else:
            print("    [+] No obvious IDOR vulnerabilities detected")

        return self.results