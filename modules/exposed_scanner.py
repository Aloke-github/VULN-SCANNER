import requests
from urllib.parse import urljoin
import os

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
    
    def load_wordlist(self):
        """Load sensitive files wordlist"""
        wordlist_file = 'wordlists/sensitive_files.txt'
        try:
            with open(wordlist_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            # Extensive default list
            return [
                # Git exposure
                '.git/config',
                '.git/HEAD',
                '.git/index',
                '.git/logs/HEAD',
                '.git/objects/',
                '.gitignore',
                
                # Source code & config
                '.env',
                '.env.example',
                '.env.production',
                'config.php',
                'config.php.bak',
                'config.php.old',
                'config.php~',
                'config.inc',
                'configuration.php',
                'wp-config.php',
                'wp-config.php.bak',
                'settings.py',
                'database.yml',
                '.aws/credentials',
                '.aws/config',
                '.gitlab-ci.yml',
                'Jenkinsfile',
                'Dockerfile',
                'docker-compose.yml',
                'Makefile',
                
                # Backup files
                'backup.zip',
                'backup.tar.gz',
                'backup.sql',
                'db_backup.sql',
                'database.sql',
                'dump.sql',
                'export.sql',
                'site.zip',
                'site.tar.gz',
                'www.zip',
                'web.zip',
                
                # Sensitive endpoints
                'admin/',
                'admin.php',
                'administrator/',
                'api/',
                'api/v1/',
                'api/docs',
                'swagger.json',
                'swagger.yaml',
                'openapi.json',
                'graphql',
                'graphiql',
                
                # Log files
                'error.log',
                'access.log',
                'debug.log',
                'wp-content/debug.log',
                'storage/logs/laravel.log',
                'var/log/system.log',
                'var/log/exception.log',
                
                # Version control
                '.svn/entries',
                '.svn/wc.db',
                '.hg/',
                '.bzr/',
                'CVS/Root',
                
                # IDE files
                '.idea/workspace.xml',
                '.project',
                '.sublime-workspace',
                '*.swp',
                
                # CI/CD
                '.circleci/config.yml',
                '.travis.yml',
                'azure-pipelines.yml',
                '.drone.yml',
                
                # Security files
                'robots.txt',
                'sitemap.xml',
                'crossdomain.xml',
                'clientaccesspolicy.xml',
                'security.txt',
                '.well-known/security.txt',
                '.htaccess',
                '.htpasswd',
                
                # Lambda / Serverless
                'serverless.yml',
                'serverless.env.yml',
                'template.yaml',
                'samconfig.toml',
                
                # Package files
                'package.json',
                'composer.json',
                'composer.lock',
                'yarn.lock',
                'Gemfile',
                'Gemfile.lock',
                'Pipfile',
                'requirements.txt',
                
                # Test files
                'phpinfo.php',
                'info.php',
                'test.php',
                'test.html',
                'debug.php',
                
                # Web shells (checking for existing shells)
                'shell.php',
                'cmd.php',
                'c99.php',
                'r57.php',
                
                # API keys
                'credentials.json',
                'service-account.json',
                'google.json',
                'firebase.json',
                'key.json',
                'secret.json',
                
                # Kubernetes
                'kubeconfig',
                '.kube/config',
                'charts/',
                'values.yaml',
                
                # Terraform
                'terraform.tfstate',
                'terraform.tfvars',
                '.terraform/',
                
                # Ansible
                'ansible.cfg',
                'hosts.ini',
                'playbook.yml',
            ]
    
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
    
    def is_false_positive(self, response_text, content_type, content_length, path):
        """
        Detect if a 200 response is actually a SPA catch-all or custom 404 page.
        This is the key fix for Juice Shop and similar SPAs.
        """
        content_lower = response_text.lower()
        
        # 1. Check if it's an HTML page (real sensitive files are rarely HTML)
        is_html = 'text/html' in content_type
        has_doctype = '<!DOCTYPE' in response_text[:200] or '<!doctype' in response_text[:200]
        has_html_tag = '<html' in response_text[:200]
        
        # 2. Check for SPA/framework indicators
        spa_indicators = ['ng-app', 'ng-version', 'reactroot', 'react-root', 
                         '__nuxt', '__vue', 'vue-app', 'sapper', 'ember-']
        has_spa_indicator = any(ind in content_lower for ind in spa_indicators)
        
        # 3. Check for 404/page not found language
        error_phrases = ['not found', '404', 'page not found', 'oops', 
                        'something went wrong', 'error', 'redirecting',
                        'the page you requested', 'could not be found',
                        'we couldn\'t find', 'looks like you\'re lost']
        has_error_text = any(phrase in content_lower for phrase in error_phrases)
        
        # 4. Check for JavaScript bundles (SPAs serve the same index.html for all routes)
        has_js_bundle = 'bundle.js' in content_lower or 'chunk.js' in content_lower or 'app.js' in content_lower
        has_css_bundle = 'bundle.css' in content_lower or 'style.css' in content_lower or 'app.css' in content_lower
        
        # 5. Check content length against a typical SPA index page
        is_large_html = content_length > 2000 and is_html
        
        # Decision logic:
        # If it's a large HTML page with SPA indicators, it's the app shell (false positive)
        if is_html and has_spa_indicator and is_large_html:
            return True
        
        # If it has HTML structure AND error text, it's a custom 404 page
        if is_html and (has_doctype or has_html_tag) and has_error_text:
            return True
        
        # If it has JS/CSS bundles and HTML, it's the SPA index.html
        if (has_js_bundle or has_css_bundle) and (has_doctype or has_html_tag):
            return True
        
        # If it's a very large HTML page (>10KB) with no obvious file content, skip
        if content_length > 10000 and is_html and has_doctype:
            # But keep critical findings like .git even if large
            critical_paths = ['.git', 'shell.', 'backdoor', 'webshell']
            if not any(cp in path.lower() for cp in critical_paths):
                return True
        
        return False
    
    def get_severity(self, category, path):
        """Determine severity of finding"""
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
        print(f"    [*] Checking {len(self.wordlist)} paths for exposure...")
        print(f"    [*] Base URL: {self.url}")
        
        findings = {}
        
        for i, path in enumerate(self.wordlist):
            # Handle wildcard paths (skip *.swp pattern matching for now)
            if '*' in path:
                continue
                
            test_url = urljoin(self.url + '/', path)
            
            try:
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 201, 204]:
                    category = self.categorize_finding(path)
                    content_type = response.headers.get('Content-Type', '')
                    content_length = len(response.content)
                    
                    # 🧠 FALSE POSITIVE DETECTION
                    if self.is_false_positive(response.text, content_type, content_length, path):
                        # Skip this - it's the SPA/app shell, not a real exposed file
                        continue
                    
                    severity = self.get_severity(category, path)
                    
                    if category not in findings:
                        findings[category] = []
                    
                    findings[category].append({
                        'url': test_url,
                        'status': response.status_code,
                        'size': content_length,
                        'severity': severity
                    })
                    
                    # Print immediately with appropriate icon
                    severity_icon = {'critical': '🚨', 'high': '🔥', 'medium': '⚠️', 'info': 'ℹ️'}
                    print(f"    {severity_icon.get(severity, '👁️')} [{severity.upper()}] {category}: {test_url[:90]}")
                    
                    # Show preview for small text files
                    if content_length < 500 and content_length > 0 and response.text:
                        preview = response.text[:200].replace('\n', '\\n')
                        print(f"       Preview: {preview}")
                
                elif response.status_code in [301, 302, 307, 308]:
                    # Directory redirect might indicate it exists
                    if path.endswith('/') and response.status_code in [301, 302]:
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
        
        # Generate summary with severity counts
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'info': 0}
        for category, items in findings.items():
            for item in items:
                sev = item.get('severity', 'info')
                if sev in severity_counts:
                    severity_counts[sev] += 1
        
        self.results['summary'] = severity_counts
        
        # Print summary
        if findings:
            print(f"\n    [📊] Exposure Summary:")
            for sev in ['critical', 'high', 'medium', 'info']:
                if severity_counts[sev] > 0:
                    icon = {'critical': '🚨', 'high': '🔥', 'medium': '⚠️', 'info': 'ℹ️'}
                    print(f"       {icon[sev]} {sev.upper()}: {severity_counts[sev]}")
        
        return self.results