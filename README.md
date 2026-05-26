

> **Scanner of the Thousand and One Vulnerabilities**  
> 👤 **Author:** @alok.t.r

---

## 🎯 Features

| Category | Modules | Description |
|----------|---------|-------------|
| **Core** | ✅ XSS | Reflected, Stored, DOM-based, Blind XSS |
| | ✅ SQLi | Error-based, Blind, Time-based, NoSQL Injection |
| | ✅ CMDi | Blind, Time-based, Error-based Command Injection |
| | ✅ LFI/RFI | Path Traversal, PHP Wrappers, Null Byte |
| | ✅ Recon | Subdomain Enumeration, Tech Detection, WAF Detection |
| | ✅ JWT | Weak Secret, alg=none, KID Injection, JWK/JKU |
| | ✅ Exposed | .git, .env, Backups, Configs, Shells, Logs |
| **Advanced** | ✅ API | BOLA, Rate Limiting, Mass Assignment, Excessive Data |
| | ✅ CORS | Origin Reflection, Wildcard + Credentials, Preflight |
| | ✅ SSRF | Cloud Metadata, Internal Network, File Protocol |
| | ✅ Secrets | AWS Keys, JWT, API Keys, Passwords in JS/Config |
| | ✅ GraphQL | Introspection, Schema Disclosure, Unauthorized Queries |
| | ✅ Headers | CSP, HSTS, XFO, Cookies, Server Info Disclosure |
| **Latest** | ✅ SSTI | Jinja2, Twig, FreeMarker, ERB, Velocity, Smarty |
| | ✅ Upload | Dangerous Extensions, Double Extensions, SVG XSS |
| | ✅ JS Analysis | Endpoint Extraction, Secret Discovery in JavaScript |
| | ✅ IDOR | Sequential IDs, Parameter Manipulation, UUID Testing |

---

## 📦 Installation

### Kali Linux / Debian-based

```bash
# Clone the repository
git clone https://github.com/yourusername/arabi-katha-scanner.git
cd arabi-katha-scanner

# Run setup (as root)
chmod +x setup.sh
sudo bash setup.sh



#Manual Installation

# Install Python dependencies
pip3 install requests beautifulsoup4

# Install Kali tools (optional but recommended)
sudo apt-get install subfinder nmap ffuf gobuster curl jq

# Make scanner executable
chmod +x scanner.py
