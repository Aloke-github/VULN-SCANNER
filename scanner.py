#!/usr/bin/env python3
"""
Web Vulnerability Scanner CLI v2.0
For authorized penetration testing only.
Compatible with Kali Linux / Windows 11
"""

import argparse
import sys
import os
import json
from datetime import datetime
from urllib.parse import urljoin

# Add modules directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.xss_scanner import XSScanner
from modules.sqli_scanner import SQLiScanner
from modules.recon import Recon
from modules.reporter import Reporter
from modules.cmdi_scanner import CMDIScanner
from modules.lfi_scanner import LFIScanner
from modules.exposed_scanner import ExposedScanner
from modules.jwt_scanner import JWTScanner

BANNER = r"""
╔══════════════════════════════════════════════════════╗
║              Web Vulnerability Scanner                ║
║                     v2.0                              ║
║   Modules: XSS | SQLi | CMDi | LFI | Recon | JWT    ║
║          Exposed Files & Configuration                ║
╚══════════════════════════════════════════════════════╝
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description='Web Vulnerability Scanner v2.0 - Authorized pentesting only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -u https://target.com --all
  python scanner.py -u https://target.com --xss --sqli -o html
  python scanner.py -f urls.txt --all --threads 20
        """
    )

    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-f', '--file', help='File containing list of URLs')
    parser.add_argument('--all', action='store_true', help='Enable ALL modules')
    parser.add_argument('--xss', action='store_true', help='XSS scanning')
    parser.add_argument('--sqli', action='store_true', help='SQL injection scanning')
    parser.add_argument('--cmdi', action='store_true', help='Command injection scanning')
    parser.add_argument('--lfi', action='store_true', help='LFI/RFI scanning')
    parser.add_argument('--exposed', action='store_true', help='Exposed files scanning')
    parser.add_argument('--jwt', action='store_true', help='JWT token analysis')
    parser.add_argument('--recon', action='store_true', help='Reconnaissance')
    parser.add_argument('--deep', action='store_true', help='Deep scan')
    parser.add_argument('--threads', type=int, default=5, help='Threads (default: 5)')
    parser.add_argument('-o', '--output', choices=['terminal', 'json', 'html'],
                        default='terminal', help='Output format')
    parser.add_argument('--proxy', help='Proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--cookies', help='Cookies (format: "key1=val1; key2=val2")')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds')
    parser.add_argument('--no-banner', action='store_true', help='Suppress banner')

    # Extended module flags
    parser.add_argument('--api', action='store_true', help='API security testing')
    parser.add_argument('--cors', action='store_true', help='CORS misconfiguration testing')
    parser.add_argument('--ssrf', action='store_true', help='SSRF testing')
    parser.add_argument('--secrets', action='store_true', help='Secret/key detection in JS/HTML')
    parser.add_argument('--graphql', action='store_true', help='GraphQL security testing')
    parser.add_argument('--headers', action='store_true', help='Security headers audit')
    parser.add_argument('--ssti', action='store_true', help='SSTI testing')
    parser.add_argument('--upload', action='store_true', help='File upload vulnerability testing')
    parser.add_argument('--js', action='store_true', help='JavaScript endpoint/secret extraction')
    parser.add_argument('--idor', action='store_true', help='IDOR testing')

    # DVWA / login support
    parser.add_argument('--login-url', help='Login page URL (for authenticated scanning)')
    parser.add_argument('--login-user', help='Username for login', default='admin')
    parser.add_argument('--login-pass', help='Password for login', default='password')

    return parser.parse_args()


def load_urls(file_path):
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url
                    urls.append(url)
        print(f"[+] Loaded {len(urls)} targets from {file_path}")
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        sys.exit(1)
    return urls


def setup_modules(args):
    if args.all:
        return {
            'xss': True, 'sqli': True, 'cmdi': True, 'lfi': True,
            'exposed': True, 'jwt': True, 'recon': True,
            'api': True, 'cors': True, 'ssrf': True, 'secrets': True,
            'graphql': True, 'headers': True, 'ssti': True, 'upload': True,
            'js': True, 'idor': True
        }

    modules = {
        'xss': args.xss, 'sqli': args.sqli, 'cmdi': args.cmdi,
        'lfi': args.lfi, 'exposed': args.exposed, 'jwt': args.jwt,
        'recon': args.recon,
        'api': args.api, 'cors': args.cors, 'ssrf': args.ssrf,
        'secrets': args.secrets, 'graphql': args.graphql,
        'headers': args.headers, 'ssti': args.ssti, 'upload': args.upload,
        'js': args.js, 'idor': args.idor
    }

    if not any(modules.values()):
        print("[*] No modules specified, enabling all")
        for key in modules:
            modules[key] = True

    return modules


def dvwa_login(url, args):
    """
    Handle DVWA login and CSRF token extraction.
    Returns a requests.Session that is logged in.
    """
    import requests as req
    from bs4 import BeautifulSoup

    session = req.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
    })
    if args.proxy:
        session.proxies = {'http': args.proxy, 'https': args.proxy}

    login_url = args.login_url if args.login_url else urljoin(url, 'login.php')

    print(f"    [*] Attempting DVWA login at {login_url}...")

    try:
        # Step 1: Get login page to extract CSRF token
        r = session.get(login_url, timeout=args.timeout)
        soup = BeautifulSoup(r.text, 'html.parser')
        token_input = soup.find('input', {'name': 'user_token'})
        csrf_token = token_input.get('value', '') if token_input else ''

        # Step 2: Post login with credentials + CSRF token
        login_data = {
            'username': args.login_user,
            'password': args.login_pass,
            'Login': 'Login',
            'user_token': csrf_token
        }
        r2 = session.post(login_url, data=login_data, timeout=args.timeout)

        # Step 3: Set security level to LOW
        security_url = urljoin(url, 'security.php')
        r3 = session.get(security_url, timeout=args.timeout)
        soup2 = BeautifulSoup(r3.text, 'html.parser')
        token_input2 = soup2.find('input', {'name': 'user_token'})
        csrf_token2 = token_input2.get('value', '') if token_input2 else ''

        session.post(security_url, data={
            'security': 'low',
            'seclev_submit': 'Submit',
            'user_token': csrf_token2
        }, timeout=args.timeout)

        # Verify login
        verify = session.get(url, timeout=args.timeout)
        if 'Login' not in verify.text or 'Please login' not in verify.text:
            print(f"    [*] Login successful (security = low)")
            return session
        else:
            print(f"    [!] Login may have failed, continuing anyway...")
            return session

    except Exception as e:
        print(f"    [!] Login error: {e}")
        return session


def count_vulnerabilities(results):
    """Count total vulnerabilities across all modules."""
    total = 0
    for key in ['xss', 'sqli', 'cmdi', 'lfi', 'ssrf', 'ssti', 'idor']:
        if isinstance(results.get(key), list):
            total += len(results[key])
    for key in ['jwt', 'api', 'cors', 'graphql', 'headers', 'upload', 'js']:
        if isinstance(results.get(key), list):
            total += len(results[key])
    for key in ['exposed', 'secrets', 'recon']:
        v = results.get(key, {})
        if isinstance(v, dict):
            for sub_key in v:
                if isinstance(v[sub_key], list):
                    total += len(v[sub_key])
    return total


def scan_single_target(url, args, modules):
    results = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'xss': [], 'sqli': [], 'cmdi': [], 'lfi': [],
        'exposed': {}, 'jwt': {}, 'recon': {},
        'summary': {'total_vulnerabilities': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    }

    print(f"\n{'='*60}")
    print(f"[*] Target: {url}")
    print(f"{'='*60}")

    # --- DVWA login handler ---
    session = None
    if args.login_url or 'dvwa' in url.lower() or '127.0.0.1' in url:
        session = dvwa_login(url, args)

    if modules['recon']:
        print("\n[📡] Running Reconnaissance...")
        recon = Recon(url, args)
        results['recon'] = recon.run()

    if modules['exposed']:
        print("\n[🔍] Scanning for Exposed Files...")
        exposed_scanner = ExposedScanner(url, args)
        results['exposed'] = exposed_scanner.scan()

    if modules['xss']:
        print("\n[💉] Testing for XSS...")
        xss_scanner = XSScanner(url, args, session=session)
        results['xss'] = xss_scanner.scan()
        if results['xss']:
            for v in results['xss'][:5]:
                print(f"     [!] XSS: {v['url'][:80]}")

    if modules['sqli']:
        print("\n[🗄️] Testing for SQL Injection...")
        sqli_scanner = SQLiScanner(url, args, session=session)
        results['sqli'] = sqli_scanner.scan()
        if results['sqli']:
            for v in results['sqli'][:5]:
                print(f"     [!] SQLi: {v['url'][:80]}")

    if modules['cmdi']:
        print("\n[⌨️] Testing for Command Injection...")
        cmdi_scanner = CMDIScanner(url, args, session=session)
        results['cmdi'] = cmdi_scanner.scan()

    if modules['lfi']:
        print("\n[📂] Testing for LFI/RFI...")
        lfi_scanner = LFIScanner(url, args)
        results['lfi'] = lfi_scanner.scan()

    if modules['jwt']:
        print("\n[🔐] Analyzing JWT Tokens...")
        jwt_scanner = JWTScanner(url, args)
        results['jwt'] = jwt_scanner.scan()

    # Extended modules
    if modules.get('api'):
        print("\n[🔌] Testing API Security...")
        from modules.api_scanner import APIScanner
        api_scanner = APIScanner(url, args)
        results['api'] = api_scanner.scan()

    if modules.get('cors'):
        print("\n[🌐] Testing CORS Configuration...")
        from modules.cors_scanner import CORSScanner
        cors_scanner = CORSScanner(url, args)
        results['cors'] = cors_scanner.scan()

    if modules.get('ssrf'):
        print("\n[🌍] Testing SSRF...")
        from modules.ssrf_scanner import SSRFScanner
        ssrf_scanner = SSRFScanner(url, args, session=session)
        results['ssrf'] = ssrf_scanner.scan()

    if modules.get('secrets'):
        print("\n[🔑] Scanning for Exposed Secrets...")
        from modules.secret_scanner import SecretScanner
        secret_scanner = SecretScanner(url, args)
        results['secrets'] = secret_scanner.scan()

    if modules.get('graphql'):
        print("\n[📊] Testing GraphQL...")
        from modules.graphql_scanner import GraphQLScanner
        graphql_scanner = GraphQLScanner(url, args)
        results['graphql'] = graphql_scanner.scan()

    if modules.get('headers'):
        print("\n[🛡️] Checking Security Headers...")
        from modules.headers_scanner import HeadersScanner
        headers_scanner = HeadersScanner(url, args)
        results['headers'] = headers_scanner.scan()

    if modules.get('ssti'):
        print("\n[📝] Testing SSTI...")
        from modules.ssti_scanner import SSTIScanner
        ssti_scanner = SSTIScanner(url, args, session=session)
        results['ssti'] = ssti_scanner.scan()

    if modules.get('upload'):
        print("\n[📎] Testing File Upload...")
        from modules.upload_scanner import UploadScanner
        upload_scanner = UploadScanner(url, args)
        results['upload'] = upload_scanner.scan()

    if modules.get('js'):
        print("\n[📜] Analyzing JavaScript...")
        from modules.js_scanner import JSScanner
        js_scanner = JSScanner(url, args)
        results['js'] = js_scanner.scan()

    if modules.get('idor'):
        print("\n[🎯] Testing IDOR...")
        from modules.idor_scanner import IDORScanner
        idor_scanner = IDORScanner(url, args, session=session)
        results['idor'] = idor_scanner.scan()

    # Summary - proper counting across ALL modules
    total_vulns = count_vulnerabilities(results)
    results['summary']['total_vulnerabilities'] = total_vulns
    results['summary']['high'] = len(results['xss']) + len(results['sqli'])
    results['summary']['medium'] = len(results['cmdi']) + len(results.get('lfi', []))

    return results


def main():
    args = parse_args()

    if not args.no_banner:
        print(BANNER)

    targets = []
    if args.url:
        url = args.url if args.url.startswith(('http://', 'https://')) else 'https://' + args.url
        targets.append(url)
    elif args.file:
        targets = load_urls(args.file)
    else:
        print("[!] Use -u URL or -f FILE")
        sys.exit(1)

    modules = setup_modules(args)
    active = [k for k, v in modules.items() if v]
    print(f"\n[*] Modules: {', '.join(active)}")
    print(f"[*] Targets: {len(targets)}")

    all_results = []
    for target in targets:
        result = scan_single_target(target, args, modules)
        all_results.append(result)

    reporter = Reporter(args.output)
    report_file = reporter.generate(all_results, args)

    total_vulns = sum(r['summary']['total_vulnerabilities'] for r in all_results)
    print(f"\n{'='*60}")
    print(f"[+] Scan Complete!")
    print(f"[+] Vulnerabilities found: {total_vulns}")
    print(f"[+] Report: {report_file}")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()