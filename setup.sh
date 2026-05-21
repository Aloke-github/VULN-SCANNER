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