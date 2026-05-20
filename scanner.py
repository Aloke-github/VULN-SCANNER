#!/usr/bin/env python3
"""
Web Vulnerability Scanner CLI for Kali Linux
For authorized penetration testing only.
Author: Your Name
Version: 2.0 - Added CMDi, LFI, Exposed Files, JWT analysis
"""

import argparse
import sys
import os
import json
from datetime import datetime
from modules.xss_scanner import XSScanner
from modules.sqli_scanner import SQLiScanner
from modules.recon import Recon
from modules.reporter import Reporter
from modules.cmdi_scanner import CMDIScanner        # NEW
from modules.lfi_scanner import LFIScanner          # NEW
from modules.exposed_scanner import ExposedScanner  # NEW
from modules.jwt_scanner import JWTScanner          # NEW

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
  # Full scan with all modules
  python3 scanner.py -u https://target.com --all

  # Specific modules
  python3 scanner.py -u https://target.com --xss --sqli --cmdi
  python3 scanner.py -u https://target.com --exposed --lfi --jwt

  # Deep scan with recon
  python3 scanner.py -u https://target.com --all --deep -o html

  # Scan from file with 20 threads
  python3 scanner.py -f urls.txt --all --threads 20

  # Use with Burp Suite
  python3 scanner.py -u https://target.com --all --proxy http://127.0.0.1:8080
        """
    )
    
    parser.add_argument('-u', '--url', help='Target URL (single target)')
    parser.add_argument('-f', '--file', help='File containing list of URLs')
    
    # Module flags
    parser.add_argument('--all', action='store_true', help='Enable ALL scan modules')
    parser.add_argument('--xss', action='store_true', help='Enable XSS scanning')
    parser.add_argument('--sqli', action='store_true', help='Enable SQL injection scanning')
    parser.add_argument('--cmdi', action='store_true', help='Enable Command injection scanning')
    parser.add_argument('--lfi', action='store_true', help='Enable LFI/RFI scanning')
    parser.add_argument('--exposed', action='store_true', help='Enable exposed files scanning (.git, backups, configs)')
    parser.add_argument('--jwt', action='store_true', help='Enable JWT token analysis')
    parser.add_argument('--recon', action='store_true', help='Enable reconnaissance')
    
    # Scan options
    parser.add_argument('--deep', action='store_true', help='Deep scan (crawl more endpoints)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('-o', '--output', choices=['terminal', 'json', 'html'], 
                       default='terminal', help='Output format')
    parser.add_argument('--proxy', help='Proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--cookies', help='Session cookies (format: "key1=val1; key2=val2")')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--headers', help='Custom headers (format: "Header1: val1|Header2: val2")')
    parser.add_argument('--no-banner', action='store_true', help='Suppress the banner')
    
    return parser.parse_args()

def load_urls(file_path):
    urls = []
    try:
        with open(file_path, 'r') as f:
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
    """Determine which modules to run based on flags"""
    if args.all:
        return {
            'xss': True,
            'sqli': True,
            'cmdi': True,
            'lfi': True,
            'exposed': True,
            'jwt': True,
            'recon': True
        }
    
    # If no specific flags, enable all
    modules = {
        'xss': args.xss,
        'sqli': args.sqli,
        'cmdi': args.cmdi,
        'lfi': args.lfi,
        'exposed': args.exposed,
        'jwt': args.jwt,
        'recon': args.recon
    }
    
    if not any(modules.values()):
        print("[*] No modules specified, enabling all")
        for key in modules:
            modules[key] = True
    
    return modules

def scan_single_target(url, args, modules):
    """Run all enabled modules against a single target"""
    results = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'xss': [],
        'sqli': [],
        'cmdi': [],
        'lfi': [],
        'exposed': {},
        'jwt': {},
        'recon': {},
        'summary': {
            'total_vulnerabilities': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
    }
    
    print(f"\n{'='*60}")
    print(f"[*] Target: {url}")
    print(f"{'='*60}")
    
    # Track findings count for summary
    findings_count = 0
    
    # 1. Reconnaissance
    if modules['recon']:
        print("\n[📡] Running Reconnaissance...")
        recon = Recon(url, args)
        results['recon'] = recon.run()
        findings_count += len(results['recon'].get('subdomains', []))
        print(f"     [+] Subdomains: {len(results['recon'].get('subdomains', []))}")
        print(f"     [+] Technologies: {', '.join(results['recon'].get('technologies', ['Unknown'])[:5])}")
        print(f"     [+] WAF: {results['recon'].get('waf', 'Unknown')}")
    
    # 2. Exposed Files Scan (fast, run early)
    if modules['exposed']:
        print("\n[🔍] Scanning for Exposed Files & Configurations...")
        exposed_scanner = ExposedScanner(url, args)
        results['exposed'] = exposed_scanner.scan()
        if results['exposed'].get('findings'):
            for finding_type, urls in results['exposed']['findings'].items():
                if urls:
                    print(f"     [!] {finding_type}: {len(urls)} found!")
                    for u in urls[:3]:
                        print(f"         - {u}")
                    if len(urls) > 3:
                        print(f"         ... and {len(urls)-3} more")
        else:
            print("     [+] No exposed sensitive files detected")
        findings_count += len(results['exposed'].get('findings', {}))
    
    # 3. XSS Scan
    if modules['xss']:
        print("\n[💉] Testing for XSS Vulnerabilities...")
        xss_scanner = XSScanner(url, args)
        xss_results = xss_scanner.scan()
        results['xss'] = xss_results
        if xss_results:
            for v in xss_results[:5]:
                print(f"     [!] {v.get('type','XSS')}: {v['url'][:80]}")
                print(f"         Payload: {v['payload'][:60]}")
        else:
            print("     [+] No XSS vulnerabilities detected")
        findings_count += len(xss_results)
    
    # 4. SQL Injection Scan
    if modules['sqli']:
        print("\n[🗄️] Testing for SQL Injection...")
        sqli_scanner = SQLiScanner(url, args)
        sqli_results = sqli_scanner.scan()
        results['sqli'] = sqli_results
        if sqli_results:
            for v in sqli_results[:5]:
                print(f"     [!] {v.get('technique','SQLi')}: {v['url'][:80]}")
                print(f"         Payload: {v['payload'][:60]}")
        else:
            print("     [+] No SQL injection vulnerabilities detected")
        findings_count += len(sqli_results)
    
    # 5. Command Injection Scan
    if modules['cmdi']:
        print("\n[⌨️] Testing for Command Injection...")
        cmdi_scanner = CMDIScanner(url, args)
        cmdi_results = cmdi_scanner.scan()
        results['cmdi'] = cmdi_results
        if cmdi_results:
            for v in cmdi_results[:5]:
                print(f"     [!] CMDi: {v['url'][:80]}")
                print(f"         Payload: {v['payload'][:60]}")
                print(f"         Evidence: {v.get('evidence', 'Command executed')[:80]}")
        else:
            print("     [+] No command injection vulnerabilities detected")
        findings_count += len(cmdi_results)
    
    # 6. LFI/RFI Scan
    if modules['lfi']:
        print("\n[📂] Testing for LFI/RFI...")
        lfi_scanner = LFIScanner(url, args)
        lfi_results = lfi_scanner.scan()
        results['lfi'] = lfi_results
        if lfi_results:
            for v in lfi_results[:5]:
                print(f"     [!] {v.get('type','LFI')}: {v['url'][:80]}")
                print(f"         Payload: {v['payload'][:60]}")
        else:
            print("     [+] No LFI/RFI vulnerabilities detected")
        findings_count += len(lfi_results)
    
    # 7. JWT Analysis
    if modules['jwt']:
        print("\n[🔐] Analyzing JWT Tokens...")
        jwt_scanner = JWTScanner(url, args)
        jwt_results = jwt_scanner.scan()
        results['jwt'] = jwt_results
        if jwt_results.get('tokens_found'):
            print(f"     [!] JWT tokens found: {len(jwt_results['tokens_found'])}")
            for token_info in jwt_results.get('vulnerabilities', []):
                print(f"     [!] {token_info.get('issue', 'Issue detected')}")
        else:
            print("     [+] No JWT tokens detected or all secure")
        findings_count += len(jwt_results.get('vulnerabilities', []))
    
    # Calculate summary
    vuln_types = ['xss', 'sqli', 'cmdi', 'lfi']
    for vt in vuln_types:
        results['summary']['total_vulnerabilities'] += len(results[vt])
    results['summary']['total_vulnerabilities'] += len(jwt_results.get('vulnerabilities', []))
    
    # Severity classification (simplified)
    results['summary']['high'] = len(results['xss']) + len(results['sqli'])
    results['summary']['medium'] = len(results['cmdi']) + len(results.get('lfi', []))
    results['summary']['info'] = findings_count - results['summary']['high'] - results['summary']['medium']
    
    return results

def main():
    args = parse_args()
    
    if not args.no_banner:
        print(BANNER)
    
    # Get multiple targets
    targets = []
    if args.url:
        url = args.url if args.url.startswith(('http://', 'https://')) else 'https://' + args.url
        targets.append(url)
    elif args.file:
        targets = load_urls(args.file)
    else:
        print("[!] Please provide a URL (-u) or a file (-f)")
        sys.exit(1)
    
    # Setup modules
    modules = setup_modules(args)
    
    active_modules = [k for k, v in modules.items() if v]
    print(f"\n[*] Active modules: {', '.join(active_modules)}")
    print(f"[*] Targets: {len(targets)}")
    print(f"[*] Threads: {args.threads}")
    
    # Scan targets sequentially (parallelism can be added later)
    all_results = []
    for target in targets:
        result = scan_single_target(target, args, modules)
        all_results.append(result)
    
    # Generate report
    reporter = Reporter(args.output)
    report_file = reporter.generate(all_results, args)
    
    # Print final summary
    total_vulns = sum(r['summary']['total_vulnerabilities'] for r in all_results)
    print(f"\n{'='*60}")
    print(f"[+] Scan Complete!")
    print(f"[+] Total targets scanned: {len(targets)}")
    print(f"[+] Total vulnerabilities found: {total_vulns}")
    print(f"[+] Report saved to: {report_file}")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()