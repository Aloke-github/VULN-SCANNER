import requests
import re
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup

class IDORScanner:
    def __init__(self, url, args):
        self.url = url.rstrip('/')
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
        
        self.results = []
    
    def find_id_parameters(self):
        """Find parameters that might contain IDs"""
        id_params = set()
        
        # Common ID parameter names
        id_names = [
            'id', 'uid', 'user_id', 'userId', 'userid', 'account_id', 'accountId',
            'profile_id', 'profileId', 'customer_id', 'customerId', 'client_id', 'clientId',
            'order_id', 'orderId', 'invoice_id', 'invoiceId', 'transaction_id', 'transactionId',
            'document_id', 'documentId', 'file_id', 'fileId', 'product_id', 'productId',
            'item_id', 'itemId', 'article_id', 'articleId', 'post_id', 'postId',
            'comment_id', 'commentId', 'message_id', 'messageId', 'ticket_id', 'ticketId',
            'uuid', 'guid', 'token', 'hash', 'slug', 'reference', 'ref',
            'loan_id', 'loanId', 'payment_id', 'paymentId', 'subscription_id',
            'role_id', 'roleId', 'group_id', 'groupId', 'team_id', 'teamId',
            'org_id', 'orgId', 'company_id', 'companyId'
        ]
        
        # Check URL parameters
        parsed = urlparse(self.url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key = param.split('=')[0]
                    if any(id_name in key.lower() for id_name in ['id', 'uid', 'uuid', 'guid', 'token']):
                        id_params.add(key)
        
        # Check the page for links with ID parameters
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
                            if any(id_name in key.lower() for id_name in id_names):
                                id_params.add(key)
            
            # Also check forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if '?' in action:
                    query = action.split('?')[1]
                    for param in query.split('&'):
                        if '=' in param:
                            key = param.split('=')[0]
                            if any(id_name in key.lower() for id_name in id_names):
                                id_params.add(key)
                
                for input_tag in form.find_all('input'):
                    name = input_tag.get('name', '')
                    if any(id_name in name.lower() for id_name in id_names):
                        id_params.add(name)
        
        except Exception:
            pass
        
        return list(id_params)
    
    def test_idor(self, param_name):
        """Test for IDOR by manipulating ID values"""
        vulnerabilities = []
        
        # Test value modifications
        test_values = [
            # Increment/decrement
            ('1', '2', '3'),  # Sequential IDs
            # UUID pattern
            ('00000000-0000-0000-0000-000000000000',),
            ('11111111-1111-1111-1111-111111111111',),
            ('ffffffff-ffff-ffff-ffff-ffffffffffff',),
            # Numeric extremes
            ('0',),
            ('999999999',),
            ('-1',),
            # Common patterns
            ('admin',),
            ('test',),
            ('null',),
            ('undefined',),
            ('true',),
            ('false',),
            ('1 OR 1=1',),  # SQLi attempt on ID
            ('../../../etc/passwd',),  # Path traversal on ID
        ]
        
        for values in test_values:
            for value in values:
                try:
                    # Replace parameter value
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
                        from urllib.parse import urlunparse
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))
                    else:
                        test_url = f"{self.url}?{param_name}={value}"
                    
                    response = self.session.get(test_url, timeout=self.args.timeout)
                    
                    # Check if we got different data
                    if response.status_code == 200:
                        # Look for indicators of user data
                        user_indicators = ['email', 'username', 'profile', 'account',
                                         'ssn', 'credit', 'address', 'phone', 'role',
                                         'admin', 'settings', 'private']
                        
                        resp_lower = response.text.lower()
                        found_indicators = [i for i in user_indicators if i in resp_lower]
                        
                        if found_indicators:
                            # Check if response is sizeable (not just an error page)
                            if len(response.text) > 500:
                                vulnerabilities.append({
                                    'url': test_url[:120],
                                    'param': param_name,
                                    'original_value': values[0] if values else '',
                                    'test_value': value,
                                    'technique': 'IDOR - Direct Object Reference',
                                    'confidence': 'Medium',
                                    'evidence': f"Accessed with {param_name}={value}, found {len(found_indicators)} user data indicators",
                                    'remediation': f"Implement proper authorization checks for parameter '{param_name}'"
                                })
                                return vulnerabilities
                
                except Exception:
                    continue
        
        return vulnerabilities
    
    def test_numeric_idor(self, param_name):
        """Test IDOR by enumerating numeric IDs"""
        # Just do a quick test with sequential IDs
        for test_id in [1, 2, 3, 100, 1000, 9999]:
            try:
                parsed = urlparse(self.url)
                if parsed.query:
                    new_params = []
                    for p in parsed.query.split('&'):
                        if '=' in p:
                            key, val = p.split('=', 1)
                            if key == param_name:
                                new_params.append(f"{key}={test_id}")
                            else:
                                new_params.append(p)
                    new_query = '&'.join(new_params)
                    from urllib.parse import urlunparse
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                else:
                    test_url = f"{self.url}?{param_name}={test_id}"
                
                response = self.session.get(test_url, timeout=3)
                
                # If we get a different response for different IDs, it might be IDOR
                # This is a simplified check - real IDOR testing needs baseline comparison
                if response.status_code == 200 and len(response.text) > 200:
                    if 'not found' not in response.text.lower() and 'error' not in response.text.lower():
                        return [{
                            'url': test_url[:120],
                            'param': param_name,
                            'technique': 'IDOR - Numeric Enumeration',
                            'confidence': 'Low',
                            'evidence': f"Accessed resource with ID={test_id} successfully",
                            'remediation': f"Implement authorization checks for parameter '{param_name}'"
                        }]
            except Exception:
                continue
        
        return []
    
    def scan(self):
        """Main IDOR scan"""
        print("    [*] Finding ID parameters...")
        
        id_params = self.find_id_parameters()
        
        if not id_params:
            print("    [*] No ID parameters found in URL, checking common patterns...")
            # Try common parameters
            id_params = ['id', 'user_id', 'uid', 'token', 'uuid']
        
        print(f"    [*] Testing {len(id_params)} potential ID parameters...")
        
        for param in id_params:
            print(f"    [*] Testing parameter: {param}")
            
            # Test direct IDOR
            results = self.test_idor(param)
            if results:
                self.results.extend(results)
                for r in results:
                    print(f"    [!] {r['technique']} - {r['param']}={r.get('test_value', '?')}")
            
            # Test numeric enumeration
            if not results:
                results = self.test_numeric_idor(param)
                if results:
                    self.results.extend(results)
        
        if self.results:
            print(f"\n    [!] Found {len(self.results)} potential IDOR vulnerabilities")
        else:
            print("    [+] No obvious IDOR vulnerabilities detected")
        
        return self.results