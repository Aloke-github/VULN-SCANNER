#!/bin/bash
# Vuln Scanner v2.0 - Kali Linux Setup Script

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║     Web Vulnerability Scanner v2.0        ║"
echo "║           Setup Script for Kali           ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script needs root for installing packages."
   echo "    Run: sudo ./setup.sh"
   exit 1
fi

echo "[+] Updating package lists..."
apt-get update -qq

echo "[+] Installing Python dependencies..."
pip3 install -r requirements.txt 2>/dev/null || pip install -r requirements.txt

echo "[+] Installing/updating Kali tools..."
KALI_TOOLS=(
    "subfinder"
    "nmap"
    "ffuf"
    "gobuster"
    "curl"
    "jq"
    "git"
)

for tool in "${KALI_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo "[*] Installing $tool..."
        apt-get install -y "$tool" 2>/dev/null || echo "    Skipping $tool (not in repos)"
    else
        echo "[+] $tool is already installed"
    fi
done

# Install additional tools for enhanced scanning
echo "[+] Checking for optional tools..."
if ! command -v nuclei &> /dev/null; then
    echo "[*] Installing nuclei..."
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || \
    echo "    nuclei installation skipped (install Go if needed)"
fi

if ! command -v httpx &> /dev/null; then
    echo "[*] Installing httpx..."
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || \
    echo "    httpx installation skipped"
fi

if ! command -v katana &> /dev/null; then
    echo "[*] Installing katana..."
    go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || \
    echo "    katana installation skipped"
fi

# Make scanner.py executable
chmod +x scanner.py

# Create directories if they don't exist
mkdir -p reports
mkdir -p payloads
mkdir -p wordlists

echo ""
echo "[+] Setup complete!"
echo ""
echo "Quick start:"
echo "  python3 scanner.py -u https://target.com --all"
echo "  python3 scanner.py -u https://target.com --xss --sqli -o html"
echo "  python3 scanner.py -f urls.txt --all --threads 20"
echo ""
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
    # New module flags
    parser.add_argument('--api', action='store_true', help='API security testing (BOLA, rate limiting)')
    parser.add_argument('--cors', action='store_true', help='CORS misconfiguration testing')
    parser.add_argument('--ssrf', action='store_true', help='SSRF testing')
    parser.add_argument('--secrets', action='store_true', help='Secret/key detection in JS/HTML')
    parser.add_argument('--graphql', action='store_true', help='GraphQL security testing')
    parser.add_argument('--headers', action='store_true', help='Security headers audit')
    parser.add_argument('--ssti', action='store_true', help='SSTI testing')
    parser.add_argument('--upload', action='store_true', help='File upload vulnerability testing')
    parser.add_argument('--js', action='store_true', help='JavaScript endpoint/secret extraction')
    parser.add_argument('--idor', action='store_true', help='IDOR testing')