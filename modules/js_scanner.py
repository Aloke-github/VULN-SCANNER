import requests
import re
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class JSScanner:
    def __init__(self, url, args):
        self.url = url.rstrip('/')
        self.args = args
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        })
        
        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}
        
        self.results = {
            'endpoints': [],
            'secrets': [],
            'js_files': []
        }
    
    def extract_js_files(self, html):
        """Extract all JavaScript file URLs from HTML"""
        js_files = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        # Script tags with src
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = urljoin(self.url, src)
            js_files.add(full_url)
        
        # Inline scripts
        for script in soup.find_all('script'):
            if script.string:
                # Find URLs in inline JS
                urls = re.findall(r'(?:src|url|href|location)\s*=\s*["\']([^"\']+)["\']', script.string)
                for url in urls:
                    if url.endswith('.js'):
                        full_url = urljoin(self.url, url)
                        js_files.add(full_url)
        
        # Source maps
        sourcemaps = re.findall(r'sourceMappingURL=([^\s"\']+)', html)
        for sm in sourcemaps:
            full_url = urljoin(self.url, sm)
            js_files.add(full_url)
        
        return list(js_files)
    
    # Patterns to find API endpoints in JS
    ENDPOINT_PATTERNS = [
        # REST patterns
        r'["\']/(?:api|rest|v1|v2|v3|v4)/[a-zA-Z0-9_/{}:?=&.-]+["\']',
        r'["\']/api/[a-zA-Z0-9_/.-]+["\']',
        r'["\']/rest/[a-zA-Z0-9_/.-]+["\']',
        r'["\']/graphql["\']',
        r'["\']/auth/[a-zA-Z0-9_/.-]+["\']',
        r'["\']/login["\']',
        r'["\']/logout["\']',
        r'["\']/register["\']',
        r'["\']/user[s]?/[a-zA-Z0-9_/.-]*["\']',
        r'["\']/admin/[a-zA-Z0-9_/.-]*["\']',
        
        # Ajax/Fetch calls
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
        r'\$\.(?:get|post|ajax)\(["\']([^"\']+)["\']',
        r'XMLHttpRequest\.open\(["\'][A-Z]*["\'],\s*["\']([^"\']+)["\']',
        
        # WebSocket
        r'new WebSocket\(["\'](wss?://[^"\']+)["\']',
        
        # Route definitions (React/Vue/Angular)
        r'path:\s*["\']([^"\']+)["\']',
        r'route:\s*["\']([^"\']+)["\']',
        r'url:\s*["\']([^"\']+)["\']',
        r'endpoint:\s*["\']([^"\']+)["\']',
    ]
    
    # Patterns to find secrets/keys in JS
    SECRET_PATTERNS = [
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
        (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', 'JWT Token'),
        (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
        (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', 'Google OAuth Key'),
        (r'(?i)firebase.*?api[Kk]ey["\'\s=:]+["\']([^"\']+)["\']', 'Firebase API Key'),
        (r'(?i)gh[pousr]_[A-Za-z0-9_]{36,}', 'GitHub Token'),
        (r'xox[baprs]-[0-9a-z\-]{10,}', 'Slack Token'),
        (r'(?:sk_test|pk_test|sk_live|pk_live)_[0-9a-zA-Z]{24,}', 'Stripe Key'),
        (r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}', 'SendGrid Key'),
        (r'(?i)(?:password|passwd|pwd|secret|api_key|apikey)\s*[:=]\s*["\'][^"\']{8,}["\']', 'Potential Credential'),
    ]
    
    def scan_js_file(self, js_url):
        """Scan a single JS file for endpoints and secrets"""
        try:
            response = self.session.get(js_url, timeout=10)
            if response.status_code != 200:
                return
            
            js_content = response.text
            file_results = {
                'url': js_url,
                'endpoints': [],
                'secrets': []
            }
            
            # Extract endpoints
            for pattern in self.ENDPOINT_PATTERNS:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    # Clean up the match
                    endpoint = match.strip('"\'')
                    if endpoint not in file_results['endpoints']:
                        file_results['endpoints'].append(endpoint)
            
            # Extract secrets
            for pattern, secret_type in self.SECRET_PATTERNS:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    # Handle regex groups (some patterns return tuples)
                    if isinstance(match, tuple):
                        match = match[0]
                    file_results['secrets'].append({
                        'type': secret_type,
                        'value': str(match)[:60]
                    })
            
            if file_results['endpoints'] or file_results['secrets']:
                self.results['js_files'].append(file_results)
                self.results['endpoints'].extend(file_results['endpoints'])
                self.results['secrets'].extend(file_results['secrets'])
                
                print(f"    [*] {js_url.split('/')[-1][:40]}")
                if file_results['endpoints']:
                    print(f"       Endpoints: {len(file_results['endpoints'])}")
                    for ep in file_results['endpoints'][:5]:
                        print(f"         - {ep}")
                    if len(file_results['endpoints']) > 5:
                        print(f"         ... and {len(file_results['endpoints'])-5} more")
                if file_results['secrets']:
                    print(f"       Secrets: {len(file_results['secrets'])}")
                    for sec in file_results['secrets'][:3]:
                        print(f"         🔑 {sec['type']}: {sec['value'][:40]}")
                        
        except Exception as e:
            print(f"    [!] Error scanning {js_url}: {e}")
    
    def scan(self):
        """Main JS scan"""
        print("    [*] Fetching main page...")
        
        try:
            response = self.session.get(self.url, timeout=10)
            html = response.text
        except Exception as e:
            print(f"    [!] Error: {e}")
            return self.results
        
        # Extract JS files from main page
        print("    [*] Extracting JavaScript files...")
        js_files = self.extract_js_files(html)
        print(f"    [*] Found {len(js_files)} JavaScript file(s)")
        
        # Scan each JS file
        print("    [*] Scanning JS files for endpoints and secrets...")
        for js_url in js_files:
            self.scan_js_file(js_url)
        
        # Also scan the main HTML for inline endpoints
        print("    [*] Scanning inline scripts...")
        soup = BeautifulSoup(html, 'html.parser')
        for script in soup.find_all('script'):
            if script.string:
                for pattern in self.ENDPOINT_PATTERNS:
                    matches = re.findall(pattern, script.string)
                    for match in matches:
                        endpoint = match.strip('"\'')
                        if endpoint not in self.results['endpoints']:
                            self.results['endpoints'].append(endpoint)
        
        # Print summary
        print(f"\n    [📊] JS Analysis Complete:")
        print(f"       📄 JS Files Scanned: {len(js_files)}")
        print(f"       🔗 Endpoints Found: {len(self.results['endpoints'])}")
        print(f"       🔑 Secrets Found: {len(self.results['secrets'])}")
        
        if self.results['secrets']:
            print(f"    🚨 Exposed secrets detected!")
            for sec in self.results['secrets'][:5]:
                print(f"       🔑 {sec['type']}: {sec['value'][:40]}...")
        
        return self.results