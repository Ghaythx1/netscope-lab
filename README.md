# 🔬 NetScope Lab v2.0 Pro

**NetScope Lab** is a modern, enterprise-grade Cybersecurity Reconnaissance, Network Mapping, and Vulnerability Assessment Platform.

It offers both an interactive **Nmap-driven scanner** and a **Fast Native Python Socket Scanner & Banner Grabber** that works cross-platform (Windows, Linux, macOS) without requiring root or external binaries.

---

## 🚀 What's New in v2.0

- ⚡ **Fast Native Socket Scanner:** Pure Python multi-threaded port scanner and banner grabber (no Nmap or root privileges required).
- 🌐 **Interactive Network Topology Map:** Live SVG constellation map showing the subnet gateway, host nodes, color-coded risk rings, and port counts.
- 🛡️ **Threat Intelligence & CVE Correlation:** Automatic CVE advisory lookup (e.g. Apache Path Traversal, OpenSSH, SambaCry, EternalBlue) with CVSS v3 severity scores.
- 🎯 **MITRE ATT&CK Matrix Mapping:** Findings mapped to enterprise MITRE ATT&CK techniques (T1190, T1021, T1040, T1046, etc.).
- 🏆 **Security Posture Scorecard:** Dynamic 0–100 security score and letter grades (A+, A, B, C, D, F) with concrete remediation action counts.
- 🧮 **CIDR & Subnet Calculator:** Subnet mask, wildcard mask, usable IP ranges, broadcast calculation, and 1-click subnet scanning.
- 🌐 **Web Security & Headers Recon:** Probes HTTP/HTTPS endpoints for missing security headers (`HSTS`, `CSP`, `X-Frame-Options`, `nosniff`), software banners, and TLS protocols.
- 📝 **Markdown & Executive Reports:** Export print-ready Markdown assessment writeups and executive JSON metric summaries.

---

## 🛠️ Installation & Running

### Requirements
- Python 3.9+
- Optional: `nmap` (if you want to use the Nmap engine)

### Setup
```bash
# Clone or navigate to the repository
cd project1

# Create and activate virtual environment
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the platform
python run.py
```

Then open your browser at **http://127.0.0.1:5000**.

---

## 🌟 Available Core Modules

### 1. ⚡ Fast Native Scanner (`/fast-scan`)
- Multithreaded TCP port scanner written purely in Python.
- Presets: Top 20 Critical, Top 35 Common, Web services, Database ports, or custom ranges.
- Grabs service banners from HTTP, SSH, FTP, SMTP, MySQL.
- Resolves CIDR blocks (up to /24) and hostnames.

### 2. 🎯 Nmap Live Scanner (`/scan`)
- Full integration with Nmap binary.
- Modes: Ping Sweep, Quick Scan, SYN Stealth, Service Detection, Full Scan, Aggressive Scan, Vulnerability Scripts (NSE), UDP.
- Real-time phase progress and estimated completion time.

### 3. 🌐 Interactive Network Topology (`/topology`)
- Real-time animated diagram of the scanned subnet.
- Node inspection panel displaying live host status, open ports, and risk levels.

### 4. 🛡️ Threat Intelligence & CVEs (`/threat-intel`)
- Correlates discovered service versions with critical CVE databases.
- Displays CVSS scores, exploitability status, and step-by-step remediation advice.

### 5. 🧮 Subnet & CIDR Calculator (`/cidr-calc`)
- Calculate network address, usable host ranges, binary masks, and network scopes (RFC1918 Private, Global WAN, Loopback).
- Direct button to scan the calculated range with Fast Scanner.

### 6. 🌐 Web Security Recon (`/web-recon`)
- Audits HTTP and HTTPS services on any port.
- Evaluates essential security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`).
- Inspects TLS ciphers, version, and server disclosure banners.

### 7. 📋 Multi-Format Exporting (`/reports`)
- **HTML Report:** Styled standalone report for offline viewing.
- **Markdown (.md):** GitHub-flavored assessment report for pentest writeups.
- **JSON Report:** Complete structured data for CI/CD or pipeline integration.
- **CSV Inventory:** Port-by-port spreadsheet for asset tracking.
- **Executive Metrics:** High-level posture scorecard and critical items.

---

## 🧪 Testing

Run the comprehensive test suite with 90+ tests:

```bash
python -m pytest -v
```

---

## ⚖️ Legal Disclaimer
*NetScope Lab is designed strictly for authorized security assessments, network inventory, and educational laboratory research. Scanning systems without explicit authorization is illegal. Use responsibly.*
