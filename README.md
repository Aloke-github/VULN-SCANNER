## Modules Overview

| Module | Flag | Detection Methods |
|--------|------|-------------------|
| XSS | `--xss` | Reflected, Stored, DOM-based, Form/URL parameter injection |
| SQLi | `--sqli` | Error-based, Time-based blind, UNION-based, Form/URL parameter |
| CMDi | `--cmdi` | Time-based blind, Error-based, Output reflection, File read |
| LFI/RFI | `--lfi` | Path traversal, PHP wrappers, Null byte, Error leakage |
| Exposed Files | `--exposed` | .git, .env, backups, configs, shells, logs, 200+ paths |
| JWT | `--jwt` | Weak secret, alg=none, KID injection, JWK/JKU, Sensitive data |
| Recon | `--recon` | Subdomains (subfinder/crt.sh), Tech detection, WAF detection
# VULN-SCANNER
Modular vulnerability scanner for Kali Linux with CMDi, JWT, LFI and exposed file detection modules.
