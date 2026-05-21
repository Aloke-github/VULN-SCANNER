import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import os

class UploadScanner:
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
        self.upload_endpoints = []
    
    def find_upload_endpoints(self):
        """Find file upload endpoints"""
        endpoints = []
        
        try:
            response = self.session.get(self.url, timeout=self.args.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find forms with file inputs
            for form in soup.find_all('form'):
                has_file = False
                for input_tag in form.find_all('input'):
                    if input_tag.get('type') == 'file':
                        has_file = True
                        break
                
                if has_file:
                    action = form.get('action', '')
                    action = urljoin(self.url, action) if action else self.url
                    method = form.get('method', 'post').lower()
                    
                    endpoints.append({
                        'url': action,
                        'method': method,
                        'source': 'form'
                    })
            
            # Common upload endpoints to try
            common_uploads = [
                '/upload', '/uploads', '/file/upload', '/api/upload',
                '/api/file', '/api/files', '/images/upload',
                '/admin/upload', '/media/upload', '/attachments/upload',
                '/profile/avatar', '/profile/picture',
                '/import', '/import/upload', '/api/import',
                '/documents', '/documents/upload',
                '/api/v1/upload', '/rest/upload'
            ]
            
            for path in common_uploads:
                test_url = urljoin(self.url, path)
                # Check if endpoint exists (responds to OPTIONS or POST)
                try:
                    options_resp = self.session.options(test_url, timeout=3)
                    if options_resp.status_code != 404:
                        endpoints.append({
                            'url': test_url,
                            'method': 'POST',
                            'source': 'discovery'
                        })
                except:
                    pass
                    
        except Exception:
            pass
        
        return endpoints
    
    def create_test_file(self, content, extension):
        """Create a test file in memory (returns tuple of (filename, content, mime_type))"""
        test_files = {
            'php': ('test.php', '<?php echo "file_upload_test"; ?>', 'application/x-php'),
            'phtml': ('test.phtml', '<?php echo "file_upload_test"; ?>', 'text/html'),
            'php3': ('test.php3', '<?php echo "file_upload_test"; ?>', 'text/plain'),
            'php4': ('test.php4', '<?php echo "file_upload_test"; ?>', 'text/plain'),
            'php5': ('test.php5', '<?php echo "file_upload_test"; ?>', 'text/plain'),
            'shtml': ('test.shtml', '<!--#echo var="DOCUMENT_ROOT" -->', 'text/html'),
            'pht': ('test.pht', '<?php echo "file_upload_test"; ?>', 'text/plain'),
            'cgi': ('test.cgi', '#!/usr/bin/perl\nprint "test\n";', 'application/x-perl'),
            'pl': ('test.pl', '#!/usr/bin/perl\nprint "test\n";', 'application/x-perl'),
            'asp': ('test.asp', '<% Response.Write("test") %>', 'text/plain'),
            'aspx': ('test.aspx', '<%@ Page Language="C#" %><%= "test" %>', 'text/plain'),
            'jsp': ('test.jsp', '<%= "test" %>', 'text/plain'),
            'war': ('test.war', 'PK', 'application/zip'),
            'jar': ('test.jar', 'PK', 'application/java-archive'),
            'svg': ('test.svg', '<?xml version="1.0"?><svg onload="alert(1)"/>', 'image/svg+xml'),
            'html': ('test.html', '<script>alert("upload_xss")</script>', 'text/html'),
            'htm': ('test.htm', '<script>alert("upload_xss")</script>', 'text/html'),
            'json': ('test.json', '{"malicious": true}', 'application/json'),
            'xml': ('test.xml', '<?xml version="1.0"?><root><script>alert(1)</script></root>', 'application/xml'),
            'exe': ('test.exe', 'MZ', 'application/octet-stream'),
            'php.jpg': ('test.php.jpg', '<?php echo "double_ext_test"; ?>', 'image/jpeg'),
            'php.png': ('test.php.png', '<?php echo "double_ext_test"; ?>', 'image/png'),
            'php.gif': ('test.php.gif', 'GIF89a<?php echo "gif_header_test"; ?>', 'image/gif'),
        }
        
        if extension in test_files:
            return test_files[extension]
        return None
    
    def test_upload_endpoint(self, endpoint):
        """Test an upload endpoint with malicious files"""
        # Test file types that could be dangerous
        test_extensions = [
            'php', 'phtml', 'php3', 'php4', 'php5', 'shtml', 'pht',
            'asp', 'aspx', 'jsp', 'cgi', 'pl',
            'html', 'htm', 'svg', 'xml', 'json',
            'exe', 'war',
            'php.jpg', 'php.png', 'php.gif'  # Double extension bypass
        ]
        
        for ext in test_extensions:
            file_data = self.create_test_file(None, ext)
            if not file_data:
                continue
            
            filename, content, mime = file_data
            
            try:
                # Try as multipart form data
                files = {'file': (filename, content, mime)}
                try:
                    response = self.session.post(
                        endpoint['url'],
                        files=files,
                        timeout=self.args.timeout,
                        allow_redirects=True
                    )
                except:
                    # Try alternate field names
                    for field_name in ['file', 'upload', 'image', 'avatar', 'document', 'attachment']:
                        files = {field_name: (filename, content, mime)}
                        try:
                            response = self.session.post(
                                endpoint['url'],
                                files=files,
                                timeout=self.args.timeout,
                                allow_redirects=True
                            )
                            break
                        except:
                            continue
                    else:
                        continue  # No field name worked
                
                # Check if upload succeeded
                if response.status_code in [200, 201, 202, 302]:
                    indicators = {
                        'PHP upload': ['test.php', '.php'],
                        'Web shell': ['<?php', '<%', '<%=', '<%@'],
                        'Upload success': [filename],
                        'file_upload_test': ['file_upload_test'],  # Our PHP test string
                    }
                    
                    response_text = response.text.lower()
                    
                    for vuln_type, patterns in indicators.items():
                        if any(p.lower() in response_text for p in patterns):
                            self.results.append({
                                'url': endpoint['url'],
                                'technique': f'Unrestricted File Upload - {ext}',
                                'severity': 'Critical',
                                'evidence': f"Uploaded {filename} (ext: {ext}) was accepted",
                                'detail': f'Server accepted dangerous file type: .{ext}',
                                'remediation': 'Validate file extension against allow-list, check MIME type server-side, store files outside webroot'
                            })
                            
                            # Check if we can access the uploaded file
                            if 'file_upload_test' in response_text:
                                self.results.append({
                                    'url': endpoint['url'],
                                    'technique': f'Uploaded File Accessible - Code Execution',
                                    'severity': 'Critical',
                                    'evidence': 'Uploaded PHP content was executed by the server',
                                    'detail': f'File {filename} was executed, confirming code execution',
                                    'remediation': 'Store uploads in non-executable directory'
                                })
                            return
                
                # Check response for path disclosure
                if response.status_code in [200, 201] and 'path' in response.text.lower():
                    import re
                    paths = re.findall(r'(?:/[\w./-]+)+', response.text)
                    if paths:
                        self.results.append({
                            'url': endpoint['url'],
                            'technique': 'Upload Path Disclosure',
                            'severity': 'Medium',
                            'evidence': f"Path revealed: {paths[0]}",
                            'detail': 'Upload response reveals file storage path',
                            'remediation': 'Do not reveal upload paths in responses'
                        })
                
            except Exception:
                continue
    
    def scan(self):
        """Main file upload scan"""
        print("    [*] Finding upload endpoints...")
        
        self.upload_endpoints = self.find_upload_endpoints()
        if not self.upload_endpoints:
            print("    [*] No upload endpoints found via form discovery, trying common paths...")
            # Already tried common paths in find_upload_endpoints
            if not self.upload_endpoints:
                print("    [!] No upload endpoints found")
                return self.results
        
        print(f"    [*] Found {len(self.upload_endpoints)} potential upload endpoint(s)")
        print(f"    [*] Testing dangerous file types: php, asp, jsp, html, svg, etc.")
        
        for endpoint in self.upload_endpoints:
            print(f"    [*] Testing: {endpoint['url']}")
            self.test_upload_endpoint(endpoint)
        
        if self.results:
            print(f"\n    🚨 Found {len(self.results)} file upload vulnerabilities!")
            for r in self.results:
                print(f"    🚨 [{r['severity']}] {r['technique']}")
                print(f"       {r['detail'][:80]}")
        else:
            print("    [+] Upload endpoints appear secure (no dangerous file types accepted)")
        
        return self.results