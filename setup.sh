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
# Kali uses externally-managed Python environments - use pipx or venv
if command -v pipx &> /dev/null; then
    echo "[*] Using pipx for Python package installation..."
    pipx install -r requirements.txt 2>/dev/null || \
    echo "    [!] pipx install failed, trying alternative method..."
fi

# Fallback: create a virtual environment
echo "[*] Creating Python virtual environment..."
python3 -m venv venv 2>/dev/null
if [ -f "venv/bin/pip" ]; then
    echo "[*] Installing packages in virtual environment..."
    venv/bin/pip install -r requirements.txt -q 2>/dev/null
    echo "[+] Virtual environment ready. Use: source venv/bin/activate"
else
    echo "[!] venv creation failed. Trying pip with --break-system-packages..."
    pip3 install -r requirements.txt --break-system-packages -q 2>/dev/null || \
    echo "    [!] Install failed. Run: pip3 install -r requirements.txt --break-system-packages"
fi

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