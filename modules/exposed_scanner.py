import requests
from urllib.parse import urljoin
import hashlib

class ExposedScanner:
    def __init__(self, url, args):
        self.url = url.rstrip('/')
        self.args = args
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        })
        
        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}
        
        self.wordlist = self.load_wordlist()
        self.results = {
            'findings': {},
            'summary': []
        }
        
        # Store the baseline homepage hash to detect false positives
        self.baseline_content_hash = None
        self.baseline_content_length = None
    
    def load_wordlist(self):
        """Load sensitive files wordlist"""
        wordlist_file = 'wordlists/sensitive_files.txt'
        try:
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            return [
                '.git/config', '.git/HEAD', '.git/index', '.gitignore',
                '.env', '.env.example', '.env.production',
                'config.php', 'wp-config.php', 'settings.py',
                'backup.zip', 'backup.sql', 'database.sql', 'dump.sql',
                'admin/', 'admin.php',
                'error.log', 'access.log', 'debug.log',
                'robots.txt', 'sitemap.xml', 'security.txt',
                '.htaccess', '.htpasswd',
                'package.json', 'composer.json', 'requirements.txt',
                'phpinfo.php', 'info.php', 'test.php',
                'shell.php', 'cmd.php',
                'credentials.json', 'secret.json',
                'Dockerfile', 'docker-compose.yml',
                'terraform.tfstate', 'kubeconfig',
            ]
    
    def get_baseline(self):
        """Fetch the homepage and store its hash/length for false positive detection"""
        try:
            response = self.session.get(self.url, timeout=10)
            self.baseline_content_length = len(response.content)
            # Use content hash of first 5000 bytes (enough to identify the SPA shell)
            self.baseline_content_hash = hashlib.md5(response.content[:5000]).hexdigest()
            print(f"    [*] Baseline: {self.baseline_content_length} bytes, hash: {self.baseline_content_hash[:8]}")
            return True
        except Exception as e:
            print(f"    [!] Could not fetch baseline: {e}")
            return False
    
    def is_false_positive(self, response, path):
        """Detect if a 200 response is a false positive (SPA catch-all)"""
        content_length = len(response.content)
        content_type = response.headers.get('Content-Type', '')
        
        # 1. Content length matches the homepage baseline exactly? Definitely false positive
        if self.baseline_content_length and content_length == self.baseline_content_length:
            content_hash = hashlib.md5(response.content[:5000]).hexdigest()
            if content_hash == self.baseline_content_hash:
                return True  # Same content as homepage = SPA catch-all
        
        # 2. Check if content length is within 1% of baseline (often SPA pages differ by a byte or two)
        if self.baseline_content_length:
            if abs(content_length - self.baseline_content_length) < 50:
                return True  # Close enough to homepage to be a false positive
        
        # 3. Small files are almost always real (robots.txt, security.txt, etc.)
        if content_length < 500:
            return False  # These are genuine findings
        
        # 4. HTML pages that are not the expected file type are false positives
        #    A .git/config file should NOT be HTML
        is_html = 'text/html' in content_type
        expected_file_types = {
            '.git': ['application/octet-stream', 'text/plain'],
            '.env': ['application/octet-stream', 'text/plain'],
            '.sql': ['application/octet-stream', 'text/plain', 'application/sql'],
            '.zip': ['application/zip', 'application/octet-stream'],
            '.gz': ['application/gzip', 'application/octet-stream'],
            '.json': ['application/json', 'text/plain'],
            '.yml': ['text/plain', 'application/x-yaml', 'text/yaml'],
            '.yaml': ['text/plain', 'application/x-yaml', 'text/yaml'],
            '.xml': ['application/xml', 'text/xml', 'text/plain'],
            '.log': ['text/plain', 'application/octet-stream'],
            '.php': ['text/plain', 'application/x-php'],
            '.py': ['text/plain', 'application/octet-stream'],
            '.md': ['text/markdown', 'text/plain'],
            '.txt': ['text/plain'],
        }
        
        # Check if the file extension suggests it should NOT be HTML
        for ext, valid_types in expected_file_types.items():
            if path.endswith(ext) or ('/' + ext) in path:
                if is_html and not any(vt in content_type for vt in valid_types):
                    return True  # A .env file that returns HTML is a false positive
        
        # 5. If it's large HTML content and not a known text file, it's the SPA
        if is_html and content_length > 2000:
            # Check for SPA indicators in the HTML
            content_lower = response.text.lower()
            spa_keywords = ['<app-root', '<app-root>', 'id="app"', 'id="root"', 
                          '<script src="', 'main.js', 'polyfills', 'runtime.js',
                          'styles.css', 'vendor.js']
            if any(kw in content_lower for kw in spa_keywords):
                return True  # This is the SPA shell, not a real exposed file
        
        return False
    
    def categorize_finding(self, path):
        """Categorize the type of exposed file"""
        categories = {
            '.git': 'Git Repository Exposure',
            '.env': 'Environment File Exposure',
            '.aws': 'AWS Credentials Exposure',
            'backup': 'Backup File Exposure',
            '.sql': 'Database Dump Exposure',
            'config': 'Configuration File Exposure',
            'wp-config': 'WordPress Configuration Exposure',
            'admin': 'Admin Panel Exposure',
            'api': 'API Endpoint Exposure',
            'swagger': 'API Documentation Exposure',
            'graphql': 'GraphQL Endpoint Exposure',
            'log': 'Log File Exposure',
            '.svn': 'SVN Repository Exposure',
            '.idea': 'IDE Project File Exposure',
            'robots.txt': 'Robots.txt Exposure',
            '.htaccess': '.htaccess Exposure',
            'phpinfo': 'PHP Info Exposure',
            'shell': 'Web Shell Found!',
            'composer': 'Composer File Exposure',
            'credentials': 'Credentials File Exposure',
            'kube': 'Kubernetes Config Exposure',
            'terraform': 'Terraform State Exposure',
        }
        
        for key, category in categories.items():
            if key in path.lower():
                return category
        
        return 'Sensitive File Exposure'
    
    def get_severity(self, category, path, content_length):
        """Determine severity of finding"""
        # Very small files (< 100 bytes) are less likely to be real sensitive data
        # unless they're specific known files
        if content_length < 10:
            return 'low'
        
        if any(x in path.lower() for x in ['.git', 'shell.', 'backdoor']):
            return 'critical'
        if any(x in path.lower() for x in ['.env', 'credential', '.aws', 
                                            'wp-config', 'backup.sql', 
                                            'database.sql', 'dump.sql',
                                            '.kube', 'kubeconfig']):
            return 'high'
        if any(x in path.lower() for x in ['log', 'phpinfo', 'admin', 
                                            'config.php', '.htaccess',
                                            'credentials.json']):
            return 'medium'
        return 'info'
    
    def scan(self):
        """Check for exposed files"""
        print(f"    [*] Loading {len(self.wordlist)} paths to check...")
        print(f"    [*] Base URL: {self.url}")
        
        # First, get the baseline homepage content
        print("    [*] Fetching baseline homepage for false positive detection...")
        if not self.get_baseline():
            print("    [!] Warning: Running without false positive detection")
        
        findings = {}
        
        for i, path in enumerate(self.wordlist):
            if '*' in path:
                continue
                
            test_url = urljoin(self.url + '/', path)
            
            try:
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 201, 204]:
                    content_length = len(response.content)
                    
                    # 🧠 FALSE POSITIVE DETECTION
                    if self.is_false_positive(response, path):
                        continue  # Skip this - it's the SPA shell
                    
                    category = self.categorize_finding(path)
                    severity = self.get_severity(category, path, content_length)
                    
                    if category not in findings:
                        findings[category] = []
                    
                    findings[category].append({
                        'url': test_url,
                        'status': response.status_code,
                        'size': content_length,
                        'severity': severity
                    })
                    
                    severity_icon = {'critical': '🚨', 'high': '🔥', 'medium': '⚠️', 'low': '🔍', 'info': 'ℹ️'}
                    print(f"    {severity_icon.get(severity, '👁️')} [{severity.upper()}] {category}: {test_url[:90]}")
                    
                    # Show preview for small text files
                    if content_length < 500 and content_length > 0 and response.text:
                        preview = response.text[:200].replace('\n', '\\n')
                        print(f"       Preview: {preview}")
                
                elif response.status_code in [301, 302, 307, 308]:
                    if path.endswith('/'):
                        redirect_url = response.headers.get('Location', '')
                        if redirect_url and 'login' not in redirect_url.lower():
                            if 'Directory Listing' not in findings:
                                findings['Directory Listing'] = []
                            findings['Directory Listing'].append({
                                'url': test_url,
                                'redirects_to': redirect_url,
                                'status': response.status_code
                            })
                            print(f"    ℹ️ Directory exists: {test_url} -> {redirect_url}")
                
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except Exception:
                continue
        
        self.results['findings'] = findings
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for category, items in findings.items():
            for item in items:
                sev = item.get('severity', 'info')
                if sev in severity_counts:
                    severity_counts[sev] += 1
        
        self.results['summary'] = severity_counts
        
        if findings:
            total = sum(severity_counts.values())
            print(f"\n    [📊] Found {total} genuine exposures:")
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                if severity_counts[sev] > 0:
                    icon = {'critical': '🚨', 'high': '🔥', 'medium': '⚠️', 'low': '🔍', 'info': 'ℹ️'}
                    print(f"       {icon[sev]} {sev.upper()}: {severity_counts[sev]}")
        else:
            print("    [+] No genuine exposed files detected")
        
        return self.results