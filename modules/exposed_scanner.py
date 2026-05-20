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
            with open(wordlist_file, 'r') as f:
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
    
    def scan(self):
        """Check for exposed files"""
        print(f"    [*] Checking {len(self.wordlist)} paths for exposure...")
        print(f"    [*] Base URL: {self.url}")
        
        findings = {}
        
        for i, path in enumerate(self.wordlist):
            test_url = urljoin(self.url + '/', path)
            
            try:
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 201, 204]:
                    category = self.categorize_finding(path)
                    
                    if category not in findings:
                        findings[category] = []
                    
                    # Determine severity
                    severity = 'info'
                    if 'git' in path.lower() or 'shell' in path.lower():
                        severity = 'critical'
                    elif 'env' in path.lower() or 'credential' in path.lower() or 'aws' in path.lower():
                        severity = 'high'
                    elif 'backup' in path.lower() or 'sql' in path.lower() or 'config' in path.lower():
                        severity = 'high'
                    elif 'log' in path.lower() or 'phpinfo' in path.lower():
                        severity = 'medium'
                    
                    findings[category].append({
                        'url': test_url,
                        'status': response.status_code,
                        'size': len(response.content),
                        'severity': severity
                    })
                    
                    # Print immediately
                    severity_icon = {'critical': '🚨', 'high': '🔥', 'medium': '⚠️', 'info': 'ℹ️'}
                    print(f"    {severity_icon.get(severity, '👁️')} [{severity.upper()}] {category}: {test_url[:90]}")
                    
                    # If it's a small text file, show preview
                    if len(response.text) < 500 and response.text:
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
        
        # Generate summary
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'info': 0}
        for category, items in findings.items():
            for item in items:
                sev = item.get('severity', 'info')
                if sev in severity_counts:
                    severity_counts[sev] += 1
        
        self.results['summary'] = severity_counts
        
        return self.results