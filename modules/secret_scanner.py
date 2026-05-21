import requests
import re
import json
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

class SecretScanner:
    def __init__(self, url, args):
        self.url = url.rstrip('/')
        self.args = args
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        })
        
        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}
        
        self.results = []
        self.discovered_urls = []
    
    def extract_js_urls(self, html, base_url):
        """Extract JavaScript file URLs from HTML"""
        js_urls = set()
        soup = BeautifulSoup(html, 'html.parser')
        
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                full_url = urljoin(base_url, src)
                js_urls.add(full_url)
        
        for script in soup.find_all('script'):
            if script.string:
                js_urls_inline = re.findall(r'(?:src|url|href)=["\']([^"\']+\.js[^"\']*)["\']', script.string)
                for url in js_urls_inline:
                    full_url = urljoin(base_url, url)
                    js_urls.add(full_url)
        
        return list(js_urls)
    
    def extract_sourcemap_urls(self, html):
        """Extract source map URLs (can reveal full source code)"""
        sourcemaps = re.findall(r'sourceMappingURL=([^\s"\']+)', html)
        return [urljoin(self.url, sm) for sm in sourcemaps]
    
    SECRET_PATTERNS = {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
        'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
        'Google OAuth Key': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'Firebase URL': r'[^"\'\s]+\.firebaseio\.com[^"\'\s]*',
        'Firebase API Key': r"(?i)firebase.*?api[kK]ey[\"'\s=:]+[\"']([^\"']+)[\"']",
        'GitHub Token': r'(?i)gh[pousr]_[A-Za-z0-9_]{36,}',
        'GitHub Old Token': r'[0-9a-f]{40}(?![0-9a-f])',
        'GitLab Token': r'glpat-[0-9a-zA-Z\-_]{20,}',
        'Slack Token': r'xox[baprs]-[0-9a-z\-]{10,}',
        'Slack Webhook': r'https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+',
        'Discord Webhook': r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',
        'Telegram Token': r'[0-9]{8,10}:[A-Za-z0-9_-]{35}',
        'JWT Token': r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        'JWT in Code': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        'Private Key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        'Heroku API Key': r"[hH][eE][rR][oO][kK][uU].*?[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        'Mailgun API Key': r'key-[0-9a-f]{32}',
        'Twilio API Key': r'SK[0-9a-fA-F]{32}',
        'SendGrid API Key': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
        'Stripe Test Key': r'(?:sk_test|pk_test)_[0-9a-zA-Z]{24,}',
        'Stripe Live Key': r'(?:sk_live|pk_live)_[0-9a-zA-Z]{24,}',
        'Square Access Token': r'sq0atp-[0-9A-Za-z\-_]{22}',
        'Square OAuth Secret': r'sq0csp-[0-9A-Za-z\-_]{43}',
        'Facebook App Secret': r'[0-9a-f]{32}(?![0-9a-f])',
        'Twitter API Key': r"(?i)twitter.*?api[kK]ey[\"'\s=:]+[\"']?([0-9a-zA-Z]{18,25})[\"']?",
        'Twitter API Secret': r"(?i)twitter.*?api[Ss]ecret[\"'\s=:]+[\"']?([0-9a-zA-Z]{35,50})[\"']?",
        'Generic API Key': r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|apiSecret)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
        'Password in Code': r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']',
        'Database URL': r'(?i)(?:mysql|postgres|mongodb|redis|elasticsearch)://[^\s"\']+',
        'MongoDB Connection String': r'mongodb(?:\+srv)?://[^\s"\']+',
        'SSH Key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
        'PEM Certificate': r'-----BEGIN CERTIFICATE-----',
        'Google Service Account': r'type":\s*"service_account"',
        'Docker Config': r'{"auths":\s*{',
        '.npmrc _auth': r'_auth\s*=\s*[A-Za-z0-9+/=]{20,}',
        'SonarQube Token': r'squ_[0-9a-f]{40}',
        'GCP Access Token': r'ya29\.[0-9A-Za-z\-_]+',
        'Azure Storage Key': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
        'NuGet API Key': r"(?i)nuget.*?api[kK]ey[\"'\s=:]+[\"']?([0-9a-f]{32})[\"']?",
        'Docker Hub Password': r"(?i)docker.*?password[\"'\s=:]+[\"']?([^\"']+)[\"']?",
        'NPM Token': r'npm_[A-Za-z0-9]{36}',
        'Pypi Token': r'pypi-[A-Za-z0-9]{40}',
        'Jenkins API Token': r'[0-9a-f]{32}',
        'Base64 Encoded (High Entropy)': r'(?:[A-Za-z0-9+/]{40,}={0,2})',
    }
    
    def scan_text_for_secrets(self, text, source_url, context=''):
        """Scan text content for secrets"""
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            try:
                matches = re.findall(pattern, text)
            except re.error as e:
                print(f"    [!] Regex error in {secret_type}: {e} - skipping")
                continue
            for match in matches:
                if self.is_false_positive(match, secret_type):
                    continue
                    
                self.results.append({
                    'url': source_url,
                    'secret_type': secret_type,
                    'confidence': 'High' if len(str(match)) > 20 else 'Medium',
                    'evidence': f"{secret_type}: {str(match)[:50]}...",
                    'context': context[:100] if context else '',
                    'remediation': f'Rotate the exposed {secret_type} immediately and remove from source code/files'
                })
                return
    
    def is_false_positive(self, match, secret_type):
        """Filter out common false positives"""
        match_str = str(match).lower()
        
        false_positives = [
            'example', 'placeholder', 'your_', 'xxx', 'test', 'changeme',
            '123456', 'deadbeef', '000000', 'aaaaaa', 'abcdef',
            'your-api-key', 'your_secret', 'api_key_here'
        ]
        
        for fp in false_positives:
            if fp in match_str:
                return True
        
        if len(match_str) < 10:
            return True
        
        return False
    
    def scan(self):
        """Main secret scan"""
        print("    [*] Scanning for exposed secrets...")
        
        try:
            response = self.session.get(self.url, timeout=10)
            html = response.text
        except Exception as e:
            print(f"    [!] Error fetching target: {e}")
            return self.results
        
        print("    [*] Scanning main page...")
        self.scan_text_for_secrets(html, self.url, 'Main page HTML')
        
        print("    [*] Extracting JavaScript files...")
        js_urls = self.extract_js_urls(html, self.url)
        sourcemaps = self.extract_sourcemap_urls(html)
        
        all_js = js_urls + sourcemaps
        print(f"    [*] Found {len(js_urls)} JS files, {len(sourcemaps)} sourcemaps")
        
        for js_url in all_js[:20]:
            try:
                js_response = self.session.get(js_url, timeout=10)
                print(f"    [*] Scanning: {js_url.split('/')[-1][:40]} ({len(js_response.content)} bytes)")
                self.scan_text_for_secrets(js_response.text, js_url, 'JavaScript file')
            except Exception:
                continue
        
        config_files = [
            '/.env', '/.env.example', '/.env.production', '/.env.local',
            '/config.js', '/config.json', '/app.config.js',
            '/wp-config.php', '/settings.py',
            '/package.json', '/composer.json', '/composer.lock',
            '/credentials.json', '/key.json', '/secret.json',
        ]
        
        print("    [*] Checking config files...")
        for config_path in config_files:
            config_url = urljoin(self.url, config_path)
            try:
                config_response = self.session.get(config_url, timeout=5)
                if config_response.status_code == 200 and len(config_response.text) > 10:
                    print(f"    [*] Scanning: {config_path}")
                    self.scan_text_for_secrets(config_response.text, config_url, 'Config file')
            except:
                continue
        
        if self.results:
            print(f"\n    [!] Found {len(self.results)} exposed secrets/keys:")
            for secret in self.results[:10]:
                print(f"    [{secret['secret_type']}] at {secret['url'][:70]}")
                print(f"       {secret['evidence'][:80]}")
            if len(self.results) > 10:
                print(f"       ... and {len(self.results) - 10} more")
        else:
            print("    [+] No exposed secrets detected")
        
        return self.results