#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              الـمـسـح الـضـعـف الـعـربـي                        ║
║              ARABI KATHA VULNERABILITY SCANNER v3.0             ║
║                                                                  ║
║   ╔═══╗╔═══╗╔═══╗╔═══╗╔═══╗╔═══╗╔═══╗╔═══╗╔═══╗╔═══╗           ║
║   ║ ا ║║ ل ║║ م ║║ س ║║ ح ║║   ║║ ض ║║ ع ║║ ف ║║ ي ║           ║
║   ╚═══╝╚═══╝╚═══╝╚═══╝╚═══╝╚═══╝╚═══╝╚═══╝╚═══╝╚═══╝           ║
║                                                                  ║
║   🏮 Scanner of the Thousand and One Vulnerabilities 🏮          ║
║                                                                  ║
║   👤  الـحـاكـر: @alok.t.r                                     ║
║   🗡️  For Authorized Penetration Testing Only                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import json
import time
from datetime import datetime
from urllib.parse import urlparse, urlunparse

# Add modules directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─── ARABI KATHA THEME UI ─────────────────────────────────────────

class ArabiKathaUI:
    """Arabian Nights themed terminal UI with gold, crimson and mystical colors"""
    
    # ANSI Color Codes - Arabian Nights Palette
    GOLD = '\033[38;5;214m'        # Gold / Sand
    CRIMSON = '\033[38;5;196m'     # Crimson / Red
    DARK_RED = '\033[38;5;88m'     # Dark Red
    ROYAL_BLUE = '\033[38;5;21m'   # Royal Blue (midnight sky)
    TEAL = '\033[38;5;37m'         # Teal (Arabian Sea)
    PURPLE = '\033[38;5;129m'      # Purple (royalty)
    MAGENTA = '\033[38;5;164m'     # Magenta
    ORANGE = '\033[38;5;208m'      # Orange (desert sunset)
    WHITE = '\033[38;5;255m'       # White
    CREAM = '\033[38;5;230m'       # Cream / Parchment
    BROWN = '\033[38;5;94m'        # Brown / Earth
    DARK_BG = '\033[48;5;0m'       # Black background
    
    # Text Formatting
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    RESET = '\033[0m'
    
    # Arabian Icons
    ICONS = {
        'lamp': '🏮',
        'sword': '🗡️',
        'shield': '🛡️',
        'camel': '🐪',
        'star': '⭐',
        'crescent': '🌙',
        'sun': '☀️',
        'desert': '🏜️',
        'mosque': '🕌',
        'gem': '💎',
        'scroll': '📜',
        'dagger': '🔪',
        'skull': '💀',
        'fire': '🔥',
        'snake': '🐍',
        'scorpion': '🦂',
        'genie': '🧞',
        'carpet': '🪄',
        'tent': '⛺',
        'palm': '🌴',
        'critical': '☠️',
        'high': '🔥',
        'medium': '🗡️',
        'low': '🔍',
        'info': '📜',
        'success': '⭐',
        'error': '☠️',
        'warning': '⚠️',
        'target': '🎯',
        'scan': '🔮',
        'key': '🔑',
        'lock': '🔐',
        'bug': '🦂',
        'terminal': '📜',
        'globe': '🌍',
        'folder': '📜',
        'document': '📜',
        'chain': '⚔️',
        'gear': '⚙️',
        'rocket': '🧞',
        'alien': '👽'
    }
    
    # Arabic decorative borders
    BORDER_TOP = '╔══════════════════════════════════════════════════════════════════╗'
    BORDER_MID = '╠══════════════════════════════════════════════════════════════════╣'
    BORDER_BOT = '╚══════════════════════════════════════════════════════════════════╝'
    LINE = '─' * 70
    
    @staticmethod
    def banner():
        """Display the ARABI KATHA main banner"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        banner = f"""
{ArabiKathaUI.DARK_RED}{ArabiKathaUI.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║              ◈  الـمـسـح الـضـعـف الـعـربـي  ◈                  ║
║           ARABI KATHA VULNERABILITY SCANNER v3.0                ║
║                                                                  ║
║    {ArabiKathaUI.GOLD}◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈{ArabiKathaUI.DARK_RED}   ║
║    {ArabiKathaUI.GOLD}                                                        {ArabiKathaUI.DARK_RED}   ║
║    {ArabiKathaUI.GOLD}   ا   ل   م   س   ح      ض   ع   ف      ع   ر   ب   ي   {ArabiKathaUI.DARK_RED}   ║
║    {ArabiKathaUI.GOLD}                                                        {ArabiKathaUI.DARK_RED}   ║
║    {ArabiKathaUI.GOLD}◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈{ArabiKathaUI.DARK_RED}   ║
║                                                                  ║
║   🏮  Scanner of the Thousand and One Vulnerabilities  🏮      ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝{ArabiKathaUI.RESET}

{ArabiKathaUI.GOLD}{ArabiKathaUI.BOLD}   👤  الـحـاكـر: @alok.t.r                                     {ArabiKathaUI.RESET}
{ArabiKathaUI.CRIMSON}   🗡️  For Authorized Penetration Testing Only                  {ArabiKathaUI.RESET}
{ArabiKathaUI.CREAM}   🏮  Modules: XSS | SQLi | CMDi | LFI | Recon | JWT | API     {ArabiKathaUI.RESET}
{ArabiKathaUI.PURPLE}       CORS | SSRF | Secrets | GraphQL | Headers | SSTI              {ArabiKathaUI.RESET}
{ArabiKathaUI.TEAL}       Upload | JS Analysis | IDOR | Exposed Files                     {ArabiKathaUI.RESET}
{ArabiKathaUI.CREAM}   {ArabiKathaUI.DIM}🌙  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                                {ArabiKathaUI.RESET}
{ArabiKathaUI.CRIMSON}{'─'*70}{ArabiKathaUI.RESET}
"""
        print(banner)
    
    @staticmethod
    def print_status(message, icon='🏮'):
        """Print a status message with Arabian icon"""
        print(f"{ArabiKathaUI.TEAL}[{datetime.now().strftime('%H:%M:%S')}]{ArabiKathaUI.RESET} {icon} {message}")
    
    @staticmethod
    def print_success(message):
        """Print a success message in gold"""
        print(f"{ArabiKathaUI.GOLD}{ArabiKathaUI.BOLD}    ⭐ {message}{ArabiKathaUI.RESET}")
    
    @staticmethod
    def print_error(message):
        """Print an error message in crimson"""
        print(f"{ArabiKathaUI.CRIMSON}{ArabiKathaUI.BOLD}    ☠️  {message}{ArabiKathaUI.RESET}")
    
    @staticmethod
    def print_warning(message):
        """Print a warning message in orange"""
        print(f"{ArabiKathaUI.ORANGE}{ArabiKathaUI.BOLD}    ⚠️  {message}{ArabiKathaUI.RESET}")
    
    @staticmethod
    def print_finding(severity, category, message):
        """Print a finding with Arabian-themed severity coloring"""
        colors = {
            'critical': ArabiKathaUI.CRIMSON,
            'high': ArabiKathaUI.ORANGE,
            'medium': ArabiKathaUI.PURPLE,
            'low': ArabiKathaUI.TEAL,
            'info': ArabiKathaUI.CREAM
        }
        icons = {
            'critical': '☠️ ',
            'high': '🔥',
            'medium': '🗡️ ',
            'low': '🔍',
            'info': '📜'
        }
        color = colors.get(severity.lower(), ArabiKathaUI.WHITE)
        icon = icons.get(severity.lower(), '•')
        print(f"    {color}{icon} [{severity.upper()}] {category}: {message}{ArabiKathaUI.RESET}")
    
    @staticmethod
    def print_header(title, icon='🏮'):
        """Print a section header with Arabian decorative border"""
        print(f"\n{ArabiKathaUI.CRIMSON}{ArabiKathaUI.BOLD}{'═'*60}{ArabiKathaUI.RESET}")
        print(f"    {icon} {ArabiKathaUI.GOLD}{ArabiKathaUI.BOLD}{title}{ArabiKathaUI.RESET}")
        print(f"{ArabiKathaUI.CRIMSON}{ArabiKathaUI.BOLD}{'═'*60}{ArabiKathaUI.RESET}")
    
    @staticmethod
    def print_arabic_divider():
        """Print an Arabic decorative divider"""
        print(f"{ArabiKathaUI.GOLD}◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈{ArabiKathaUI.RESET}")
    
    @staticmethod
    def print_table(headers, rows):
        """Print a formatted table"""
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Print headers
        header_line = '  '.join(f"{ArabiKathaUI.BOLD}{h:<{w}}{ArabiKathaUI.RESET}" for h, w in zip(headers, col_widths))
        print(f"    {header_line}")
        print(f"    {'─' * (sum(col_widths) + (len(headers)-1)*2)}")
        
        # Print rows
        for row in rows:
            line = '  '.join(f"{str(c):<{w}}" for c, w in zip(row, col_widths))
            print(f"    {line}")
    
    @staticmethod
    def summary_box(data):
        """Print an Arabian Nights summary box"""
        print(f"\n{ArabiKathaUI.GOLD}{ArabiKathaUI.BOLD}{'═'*60}{ArabiKathaUI.RESET}")
        print(f"{ArabiKathaUI.GOLD}    🏮 SUMMARY OF THE SCAN - خـلاصـة الـمـسـح{ArabiKathaUI.RESET}")
        print(f"{ArabiKathaUI.GOLD}{'═'*60}{ArabiKathaUI.RESET}")
        
        for key, value in data.items():
            color = ArabiKathaUI.CREAM
            if 'critical' in key.lower():
                color = ArabiKathaUI.CRIMSON
            elif 'high' in key.lower():
                color = ArabiKathaUI.ORANGE
            elif 'medium' in key.lower():
                color = ArabiKathaUI.PURPLE
            elif 'success' in key.lower() or 'complete' in key.lower():
                color = ArabiKathaUI.GOLD
            
            print(f"    {color}{key}: {value}{ArabiKathaUI.RESET}")
        
        print(f"{ArabiKathaUI.GOLD}{'═'*60}{ArabiKathaUI.RESET}")

# ─── IMPORTS ──────────────────────────────────────────────────────

from modules.xss_scanner import XSScanner
from modules.sqli_scanner import SQLiScanner
from modules.recon import Recon
from modules.reporter import Reporter
from modules.cmdi_scanner import CMDIScanner
from modules.lfi_scanner import LFIScanner
from modules.exposed_scanner import ExposedScanner
from modules.jwt_scanner import JWTScanner

# ─── ARGUMENT PARSER ──────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description=f'{ArabiKathaUI.CRIMSON}ARABI KATHA Vulnerability Scanner - @alok.t.r{ArabiKathaUI.RESET}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{ArabiKathaUI.GOLD}═══════════════════════════════════════════════════════════════════{ArabiKathaUI.RESET}
{ArabiKathaUI.GOLD}  🏮 EXAMPLES - أمـثـلـة{ArabiKathaUI.RESET}
{ArabiKathaUI.GOLD}═══════════════════════════════════════════════════════════════════{ArabiKathaUI.RESET}

{ArabiKathaUI.TEAL}  python3 scanner.py -u https://target.com --all{ArabiKathaUI.RESET}
{ArabiKathaUI.TEAL}  python3 scanner.py -u https://target.com --xss --sqli --api -o html{ArabiKathaUI.RESET}
{ArabiKathaUI.TEAL}  python3 scanner.py -f urls.txt --all --threads 20 -o json{ArabiKathaUI.RESET}
{ArabiKathaUI.TEAL}  python3 scanner.py -u http://localhost:3000 --ssrf --secrets{ArabiKathaUI.RESET}

{ArabiKathaUI.ORANGE}═══════════════════════════════════════════════════════════════════{ArabiKathaUI.RESET}
{ArabiKathaUI.ORANGE}  🗡️  MODULES - الـوحـدات{ArabiKathaUI.RESET}
{ArabiKathaUI.ORANGE}═══════════════════════════════════════════════════════════════════{ArabiKathaUI.RESET}

{ArabiKathaUI.GOLD}  Core:{ArabiKathaUI.RESET} {ArabiKathaUI.CREAM}xss, sqli, cmdi, lfi, recon, jwt, exposed{ArabiKathaUI.RESET}
{ArabiKathaUI.PURPLE}  Advanced:{ArabiKathaUI.RESET} {ArabiKathaUI.CREAM}api, cors, ssrf, secrets, graphql, headers{ArabiKathaUI.RESET}
{ArabiKathaUI.TEAL}  Latest:{ArabiKathaUI.RESET} {ArabiKathaUI.CREAM}ssti, upload, js, idor{ArabiKathaUI.RESET}

{ArabiKathaUI.CRIMSON}═══════════════════════════════════════════════════════════════════{ArabiKathaUI.RESET}
{ArabiKathaUI.CRIMSON}  👤  Author: @alok.t.r | For Authorized Testing Only{ArabiKathaUI.RESET}
{ArabiKathaUI.CRIMSON}═══════════════════════════════════════════════════════════════════{ArabiKathaUI.RESET}
        """
    )
    
    # Target
    target_group = parser.add_argument_group(f'{ArabiKathaUI.GOLD}🎯 Target Options{ArabiKathaUI.RESET}')
    target_group.add_argument('-u', '--url', help='Target URL (single target)')
    target_group.add_argument('-f', '--file', help='File containing list of URLs')
    
    # Module flags - Core
    core_group = parser.add_argument_group(f'{ArabiKathaUI.GREEN}⚔️ Core Modules{ArabiKathaUI.RESET}')
    core_group.add_argument('--all', action='store_true', help='Enable ALL modules')
    core_group.add_argument('--xss', action='store_true', help='XSS (Reflected, Stored, DOM, Blind)')
    core_group.add_argument('--sqli', action='store_true', help='SQL Injection (Error, Blind, Time, NoSQL)')
    core_group.add_argument('--cmdi', action='store_true', help='Command Injection')
    core_group.add_argument('--lfi', action='store_true', help='LFI/RFI')
    core_group.add_argument('--exposed', action='store_true', help='Exposed Files (.git, .env, backups)')
    core_group.add_argument('--jwt', action='store_true', help='JWT Analysis (alg=none, weak secret)')
    core_group.add_argument('--recon', action='store_true', help='Reconnaissance (subdomains, tech, WAF)')
    
    # Module flags - Advanced
    adv_group = parser.add_argument_group(f'{ArabiKathaUI.PURPLE}🪄 Advanced Modules{ArabiKathaUI.RESET}')
    adv_group.add_argument('--api', action='store_true', help='API Security (BOLA, Rate Limit, Mass Assignment)')
    adv_group.add_argument('--cors', action='store_true', help='CORS Misconfiguration')
    adv_group.add_argument('--ssrf', action='store_true', help='SSRF (Cloud Metadata, Internal Network)')
    adv_group.add_argument('--secrets', action='store_true', help='Secret Detection (Keys, Tokens in JS/Config)')
    adv_group.add_argument('--graphql', action='store_true', help='GraphQL (Introspection, Schema Disclosure)')
    adv_group.add_argument('--headers', action='store_true', help='Security Headers Audit (CSP, HSTS, XFO)')
    
    # Module flags - Latest
    latest_group = parser.add_argument_group(f'{ArabiKathaUI.TEAL}🧞 Latest Modules{ArabiKathaUI.RESET}')
    latest_group.add_argument('--ssti', action='store_true', help='SSTI (Jinja2, Twig, FreeMarker, ERB)')
    latest_group.add_argument('--upload', action='store_true', help='File Upload (Dangerous Extensions)')
    latest_group.add_argument('--js', action='store_true', help='JS Analysis (Endpoint/Secret Extraction)')
    latest_group.add_argument('--idor', action='store_true', help='IDOR (Insecure Direct Object Reference)')
    
    # Scan options
    opt_group = parser.add_argument_group(f'{ArabiKathaUI.TEAL}⚙️ Scan Options{ArabiKathaUI.RESET}')
    opt_group.add_argument('--deep', action='store_true', help='Deep scan (crawl more endpoints)')
    opt_group.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    opt_group.add_argument('-o', '--output', choices=['terminal', 'json', 'html'], 
                       default='terminal', help='Output format')
    opt_group.add_argument('--proxy', help='Proxy (e.g., http://127.0.0.1:8080)')
    opt_group.add_argument('--cookies', help='Cookies (format: "key1=val1; key2=val2")')
    opt_group.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    opt_group.add_argument('--headers-file', help='Custom headers file')
    opt_group.add_argument('--no-banner', action='store_true', help='Suppress the banner')
    opt_group.add_argument('--quiet', action='store_true', help='Quiet mode (minimal output)')
    
    return parser.parse_args()

# ─── UTILITY FUNCTIONS ────────────────────────────────────────────

def load_urls(file_path):
    """Load URLs from a file"""
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    if not url.startswith(('http://', 'https://')):
                        url = 'https://' + url
                    urls.append(url)
        ArabiKathaUI.print_success(f"Loaded {len(urls)} targets from {file_path}")
    except FileNotFoundError:
        ArabiKathaUI.print_error(f"File not found: {file_path}")
        sys.exit(1)
    return urls

def setup_modules(args):
    """Determine which modules to run based on flags"""
    # All modules dictionary
    all_modules = {
        'xss': True, 'sqli': True, 'cmdi': True, 'lfi': True,
        'exposed': True, 'jwt': True, 'recon': True,
        'api': True, 'cors': True, 'ssrf': True, 'secrets': True,
        'graphql': True, 'headers': True, 'ssti': True, 'upload': True,
        'js': True, 'idor': True
    }
    
    if args.all:
        return all_modules
    
    # Map args to module names
    module_map = {
        'xss': args.xss, 'sqli': args.sqli, 'cmdi': args.cmdi,
        'lfi': args.lfi, 'exposed': args.exposed, 'jwt': args.jwt,
        'recon': args.recon,
        'api': args.api, 'cors': args.cors, 'ssrf': args.ssrf,
        'secrets': args.secrets, 'graphql': args.graphql,
        'headers': args.headers, 'ssti': args.ssti, 'upload': args.upload,
        'js': args.js, 'idor': args.idor
    }
    
    modules = {}
    for key, val in module_map.items():
        modules[key] = val
    
    # If no specific flags, enable all
    if not any(modules.values()):
        if not args.quiet:
            ArabiKathaUI.print_warning("No modules specified, enabling ALL modules")
        return all_modules
    
    return modules

def scan_single_target(url, args, modules):
    """Run all enabled modules against a single target"""
    ui = ArabiKathaUI
    
    results = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'xss': [], 'sqli': [], 'cmdi': [], 'lfi': [],
        'exposed': {}, 'jwt': {}, 'recon': {},
        'api': [], 'cors': [], 'ssrf': [], 'secrets': {},
        'graphql': [], 'headers': [], 'ssti': [], 'upload': [],
        'js': {}, 'idor': [],
        'summary': {
            'total_vulnerabilities': 0,
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
        }
    }
    
    # Target header
    print(f"\n{ui.CRIMSON}{ui.BOLD}{'═'*60}{ui.RESET}")
    print(f"{ui.ICONS['target']} {ui.GOLD}{ui.BOLD}TARGET - الهـدف: {url}{ui.RESET}")
    print(f"{ui.ICONS['scroll']} {ui.CREAM}Authorized by: @alok.t.r{ui.RESET}")
    print(f"{ui.ICONS['crescent']} {ui.TEAL}Started - بـدأ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{ui.RESET}")
    print(f"{ui.CRIMSON}{ui.BOLD}{'═'*60}{ui.RESET}")
    
    findings_count = 0
    
    # ─── 1. RECONNAISSANCE ─────────────────────────────────────
    if modules['recon']:
        ui.print_header("Reconnaissance - الاستطلاع", ui.ICONS['scan'])
        try:
            recon = Recon(url, args)
            results['recon'] = recon.run()
            if results['recon'].get('subdomains'):
                ui.print_success(f"Subdomains - النطاقات: {len(results['recon']['subdomains'])}")
            if results['recon'].get('technologies'):
                ui.print_success(f"Technologies - التقنيات: {', '.join(results['recon']['technologies'][:5])}")
            ui.print_success(f"WAF - جدار الحماية: {results['recon'].get('waf', 'Unknown')}")
        except Exception as e:
            ui.print_error(f"Recon failed: {e}")
    
    # ─── 2. EXPOSED FILES ─────────────────────────────────────
    if modules['exposed']:
        ui.print_header("Exposed Files - الملفات المكشوفة", ui.ICONS['folder'])
        try:
            exposed_scanner = ExposedScanner(url, args)
            results['exposed'] = exposed_scanner.scan()
            if results['exposed'].get('findings'):
                for cat, items in results['exposed']['findings'].items():
                    if items:
                        sev = items[0].get('severity', 'info')
                        ui.print_finding(sev, cat, f"{len(items)} found")
                        findings_count += len(items)
        except Exception as e:
            ui.print_error(f"Exposed files scan failed: {e}")
    
    # ─── 3. XSS ──────────────────────────────────────────────
    if modules['xss']:
        ui.print_header("Cross-Site Scripting (XSS)", ui.ICONS['bug'])
        try:
            xss_scanner = XSScanner(url, args)
            results['xss'] = xss_scanner.scan()
            if results['xss']:
                for v in results['xss'][:5]:
                    ui.print_finding('high', v.get('type', 'XSS'), f"Payload: {v['payload'][:50]}")
                findings_count += len(results['xss'])
            else:
                ui.print_success("No XSS vulnerabilities detected")
        except Exception as e:
            ui.print_error(f"XSS scan failed: {e}")
    
    # ─── 4. SQL INJECTION ────────────────────────────────────
    if modules['sqli']:
        ui.print_header("SQL & NoSQL Injection - حقن SQL", ui.ICONS['fire'])
        try:
            sqli_scanner = SQLiScanner(url, args)
            results['sqli'] = sqli_scanner.scan()
            if results['sqli']:
                for v in results['sqli'][:5]:
                    ui.print_finding('critical', v.get('technique', 'SQLi'), f"Param: {v.get('param', '?')}")
                findings_count += len(results['sqli'])
            else:
                ui.print_success("No SQL injection vulnerabilities detected")
        except Exception as e:
            ui.print_error(f"SQLi scan failed: {e}")
    
    # ─── 5. COMMAND INJECTION ────────────────────────────────
    if modules['cmdi']:
        ui.print_header("Command Injection - حقن الأوامر", ui.ICONS['terminal'])
        try:
            cmdi_scanner = CMDIScanner(url, args)
            results['cmdi'] = cmdi_scanner.scan()
            if results['cmdi']:
                for v in results['cmdi'][:3]:
                    ui.print_finding('critical', 'CMDi', f"Evidence: {v.get('evidence', '')[:60]}")
                findings_count += len(results['cmdi'])
            else:
                ui.print_success("No command injection detected")
        except Exception as e:
            ui.print_error(f"CMDi scan failed: {e}")
    
    # ─── 6. LFI/RFI ──────────────────────────────────────────
    if modules['lfi']:
        ui.print_header("File Inclusion (LFI/RFI) - تضمين الملفات", ui.ICONS['folder'])
        try:
            lfi_scanner = LFIScanner(url, args)
            results['lfi'] = lfi_scanner.scan()
            if results['lfi']:
                for v in results['lfi'][:3]:
                    ui.print_finding('high', v.get('type', 'LFI'), f"Payload: {v['payload'][:50]}")
                findings_count += len(results['lfi'])
            else:
                ui.print_success("No LFI/RFI detected")
        except Exception as e:
            ui.print_error(f"LFI scan failed: {e}")
    
    # ─── 7. JWT ANALYSIS ─────────────────────────────────────
    if modules['jwt']:
        ui.print_header("JWT Token Analysis - تحليل الرموز", ui.ICONS['lock'])
        try:
            jwt_scanner = JWTScanner(url, args)
            results['jwt'] = jwt_scanner.scan()
            if results['jwt'].get('vulnerabilities'):
                for v in results['jwt']['vulnerabilities'][:3]:
                    ui.print_finding(v['severity'], v['issue'], '')
                findings_count += len(results['jwt']['vulnerabilities'])
        except Exception as e:
            ui.print_error(f"JWT scan failed: {e}")
    
    # ─── 8. API SECURITY ─────────────────────────────────────
    if modules['api']:
        ui.print_header("API Security - أمن API", ui.ICONS['chain'])
        try:
            import importlib
            api_module = importlib.import_module('modules.api_scanner')
            api_scanner = api_module.APIScanner(url, args)
            results['api'] = api_scanner.scan()
            if results['api']:
                for v in results['api'][:5]:
                    ui.print_finding('medium', v['technique'], v.get('evidence', '')[:60])
                findings_count += len(results['api'])
        except Exception as e:
            ui.print_error(f"API scan failed: {e}")
    
    # ─── 9. CORS ─────────────────────────────────────────────
    if modules['cors']:
        ui.print_header("CORS Misconfiguration - تكوين CORS", ui.ICONS['globe'])
        try:
            import importlib
            cors_module = importlib.import_module('modules.cors_scanner')
            cors_scanner = cors_module.CORSScanner(url, args)
            results['cors'] = cors_scanner.scan()
            if results['cors']:
                for v in results['cors'][:3]:
                    ui.print_finding(v.get('severity', 'info'), v['technique'], v.get('evidence', '')[:60])
                findings_count += len(results['cors'])
        except Exception as e:
            ui.print_error(f"CORS scan failed: {e}")
    
    # ─── 10. SSRF ────────────────────────────────────────────
    if modules['ssrf']:
        ui.print_header("Server-Side Request Forgery (SSRF)", ui.ICONS['globe'])
        try:
            import importlib
            ssrf_module = importlib.import_module('modules.ssrf_scanner')
            ssrf_scanner = ssrf_module.SSRFScanner(url, args)
            results['ssrf'] = ssrf_scanner.scan()
            if results['ssrf']:
                for v in results['ssrf'][:3]:
                    ui.print_finding('high', v['technique'], v.get('payload', '')[:60])
                findings_count += len(results['ssrf'])
        except Exception as e:
            ui.print_error(f"SSRF scan failed: {e}")
    
    # ─── 11. SECRET DETECTION ────────────────────────────────
    if modules['secrets']:
        ui.print_header("Secret Detection - كشف الأسرار", ui.ICONS['key'])
        try:
            import importlib
            secret_module = importlib.import_module('modules.secret_scanner')
            secret_scanner = secret_module.SecretScanner(url, args)
            results['secrets'] = secret_scanner.scan()
            if results['secrets']:
                for v in results['secrets'][:5]:
                    ui.print_finding('critical', v['secret_type'], v.get('evidence', '')[:60])
                findings_count += len(results['secrets'])
        except Exception as e:
            ui.print_error(f"Secret scan failed: {e}")
    
    # ─── 12. GRAPHQL ─────────────────────────────────────────
    if modules['graphql']:
        ui.print_header("GraphQL Security - أمن GraphQL", ui.ICONS['document'])
        try:
            import importlib
            graphql_module = importlib.import_module('modules.graphql_scanner')
            graphql_scanner = graphql_module.GraphQLScanner(url, args)
            results['graphql'] = graphql_scanner.scan()
            if results['graphql']:
                for v in results['graphql']:
                    ui.print_finding(v.get('severity', 'info'), v['technique'], v.get('evidence', '')[:60])
                findings_count += len(results['graphql'])
        except Exception as e:
            ui.print_error(f"GraphQL scan failed: {e}")
    
    # ─── 13. SECURITY HEADERS ────────────────────────────────
    if modules['headers']:
        ui.print_header("Security Headers - ترويسات الأمان", ui.ICONS['shield'])
        try:
            import importlib
            headers_module = importlib.import_module('modules.headers_scanner')
            headers_scanner = headers_module.HeadersScanner(url, args)
            results['headers'] = headers_scanner.scan()
            if results['headers']:
                critical_missing = [r for r in results['headers'] if 'Missing' in r['technique'] and r.get('severity') in ['High', 'Critical']]
                if critical_missing:
                    for h in critical_missing[:5]:
                        ui.print_finding(h['severity'], f"Missing {h['header']}", h.get('detail', '')[:60])
                findings_count += len(results['headers'])
        except Exception as e:
            ui.print_error(f"Headers scan failed: {e}")
    
    # ─── 14. SSTI ────────────────────────────────────────────
    if modules['ssti']:
        ui.print_header("Server-Side Template Injection (SSTI)", ui.ICONS['alien'])
        try:
            import importlib
            ssti_module = importlib.import_module('modules.ssti_scanner')
            ssti_scanner = ssti_module.SSTIScanner(url, args)
            results['ssti'] = ssti_scanner.scan()
            if results['ssti']:
                for v in results['ssti'][:3]:
                    ui.print_finding('critical', v['technique'], f"Payload: {v['payload'][:40]}")
                findings_count += len(results['ssti'])
        except Exception as e:
            ui.print_error(f"SSTI scan failed: {e}")
    
    # ─── 15. FILE UPLOAD ─────────────────────────────────────
    if modules['upload']:
        ui.print_header("File Upload - رفع الملفات", ui.ICONS['document'])
        try:
            import importlib
            upload_module = importlib.import_module('modules.upload_scanner')
            upload_scanner = upload_module.UploadScanner(url, args)
            results['upload'] = upload_scanner.scan()
            if results['upload']:
                for v in results['upload'][:3]:
                    ui.print_finding('critical', v['technique'], v.get('detail', '')[:60])
                findings_count += len(results['upload'])
        except Exception as e:
            ui.print_error(f"Upload scan failed: {e}")
    
    # ─── 16. JS ANALYSIS ─────────────────────────────────────
    if modules['js']:
        ui.print_header("JavaScript Analysis - تحليل JS", ui.ICONS['terminal'])
        try:
            import importlib
            js_module = importlib.import_module('modules.js_scanner')
            js_scanner = js_module.JSScanner(url, args)
            results['js'] = js_scanner.scan()
            if results['js'].get('secrets'):
                for sec in results['js']['secrets'][:5]:
                    ui.print_finding('high', f"Secret: {sec['type']}", sec['value'][:40])
                findings_count += len(results['js']['secrets'])
            if results['js'].get('endpoints'):
                ui.print_success(f"Extracted {len(results['js']['endpoints'])} endpoints from JS")
        except Exception as e:
            ui.print_error(f"JS analysis failed: {e}")
    
    # ─── 17. IDOR ────────────────────────────────────────────
    if modules['idor']:
        ui.print_header("IDOR - المرجع المباشر غير الآمن", ui.ICONS['target'])
        try:
            import importlib
            idor_module = importlib.import_module('modules.idor_scanner')
            idor_scanner = idor_module.IDORScanner(url, args)
            results['idor'] = idor_scanner.scan()
            if results['idor']:
                for v in results['idor'][:3]:
                    ui.print_finding('high', v['technique'], f"Param: {v.get('param', '?')}")
                findings_count += len(results['idor'])
        except Exception as e:
            ui.print_error(f"IDOR scan failed: {e}")
    
    # ─── SUMMARY ─────────────────────────────────────────────
    vuln_types = ['xss', 'sqli', 'cmdi', 'lfi']
    total = 0
    for vt in vuln_types:
        total += len(results[vt])
    total += len(results.get('api', []))
    total += len(results.get('cors', []))
    total += len(results.get('ssrf', []))
    total += len(results.get('graphql', []))
    total += len(results.get('ssti', []))
    total += len(results.get('upload', []))
    total += len(results.get('idor', []))
    total += len(results.get('jwt', {}).get('vulnerabilities', []))
    total += len(results.get('secrets', []))
    total += len(results.get('js', {}).get('secrets', []))
    
    results['summary']['total_vulnerabilities'] = total
    results['summary']['high'] = len(results['xss']) + len(results['sqli'])
    results['summary']['medium'] = len(results['cmdi']) + len(results.get('lfi', []))
    
    return results

# ─── MAIN ─────────────────────────────────────────────────────────

def main():
    args = parse_args()
    ui = ArabiKathaUI
    
    # Display banner
    if not args.no_banner and not args.quiet:
        ui.banner()
    
    # Load targets
    targets = []
    if args.url:
        url = args.url if args.url.startswith(('http://', 'https://')) else 'https://' + args.url
        targets.append(url)
    elif args.file:
        targets = load_urls(args.file)
    else:
        ui.print_error("Please provide a URL (-u) or a file (-f)")
        print(f"\n{ui.TEAL}Usage examples - أمثلة الاستخدام:{ui.RESET}")
        print(f"  python3 scanner.py -u https://target.com --all")
        print(f"  python3 scanner.py -u http://localhost:3000 --xss --sqli --api")
        print(f"  python3 scanner.py -f urls.txt --all -o html")
        sys.exit(1)
    
    # Setup modules
    modules = setup_modules(args)
    active_modules = [k for k, v in modules.items() if v]
    
    if not args.quiet:
        print(f"\n{ui.GOLD}{ui.BOLD}⚔️  ACTIVE MODULES - الـوحـدات الـنـشـطـة:{ui.RESET}")
        cols = 4
        for i in range(0, len(active_modules), cols):
            chunk = active_modules[i:i+cols]
            print(f"  {ui.CREAM}{' | '.join(f'{m:>10}' for m in chunk)}{ui.RESET}")
        
        print(f"\n{ui.CREAM}👤 Authorized Pentest by @alok.t.r{ui.RESET}")
        print(f"{ui.ORANGE}🎯 Targets: {len(targets)} | Threads: {args.threads}{ui.RESET}")
        ui.print_arabic_divider()
    
    # Scan all targets
    start_time = time.time()
    all_results = []
    
    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n{ui.ORANGE}{ui.BOLD}[{i}/{len(targets)}] Scanning target {i} of {len(targets)}{ui.RESET}")
        
        result = scan_single_target(target, args, modules)
        all_results.append(result)
    
    # Generate report
    reporter = Reporter(args.output)
    report_file = reporter.generate(all_results, args)
    
    # Final statistics
    elapsed = time.time() - start_time
    total_vulns = sum(r['summary']['total_vulnerabilities'] for r in all_results)
    
    print(f"\n{ui.GOLD}{ui.BOLD}{'═'*60}{ui.RESET}")
    print(f"{ui.GOLD}{ui.BOLD}   🏮 SCAN COMPLETE - تـم الـمـسـح!{ui.RESET}")
    print(f"{ui.GOLD}{ui.BOLD}{'═'*60}{ui.RESET}")
    print(f"{ui.CREAM}   👤 Authorized by: @alok.t.r{ui.RESET}")
    print(f"{ui.TEAL}   🎯 Targets scanned - تم مسح: {len(targets)}{ui.RESET}")
    print(f"{ui.CRIMSON}   ☠️  Vulnerabilities found - وجدت: {total_vulns}{ui.RESET}")
    print(f"{ui.PURPLE}   ⏱️  Time elapsed - استغرق: {elapsed:.2f}s{ui.RESET}")
    print(f"{ui.GOLD}   📄 Report saved to - حفظ التقرير: {report_file}{ui.RESET}")
    print(f"{ui.GOLD}{ui.BOLD}{'═'*60}{ui.RESET}")
    print(f"{ui.CRIMSON}{ui.BOLD}   🗡️  For Authorized Penetration Testing Only{ui.RESET}")
    print(f"{ui.GOLD}{ui.BOLD}   🏮  ARABI KATHA SCANNER - by @alok.t.r{ui.RESET}")
    print(f"{ui.CRIMSON}{ui.BOLD}{'═'*60}{ui.RESET}\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{ArabiKathaUI.CRIMSON}{ArabiKathaUI.BOLD}\n[!] Scan interrupted by user - توقف المسح{self.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{ArabiKathaUI.CRIMSON}{ArabiKathaUI.BOLD}[!] Fatal error - خطأ: {e}{ArabiKathaUI.RESET}")
        sys.exit(1)