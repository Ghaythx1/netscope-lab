# Changelog

All notable changes to the **NetScope Lab** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-10-20

### 🚀 Major Feature Release — NetScope Lab v2.0 Pro

#### Added
- **⚡ Native Fast Socket Scanner (`FastSocketScanner`):**
  - High-speed, multi-threaded TCP port scanner and service banner grabber written in pure Python.
  - Zero external binary requirements (runs on Windows, Linux, and macOS without needing Nmap or raw-packet root privileges).
  - Built-in banner grabbing for HTTP/HTTPS headers, SSH version banners, FTP greetings, SMTP banners, and MySQL handshakes.
  - Preset profiles: Top 20 Critical, Top 35 Common, Web endpoints, Database ports, and custom ranges.
  - Subnet CIDR expansion up to `/24`.
  - Added dedicated UI view `/fast-scan` and REST endpoint `/api/fast-scan`.

- **🌐 Interactive Network Topology Visualizer (`/topology`):**
  - Dynamic, real-time SVG network topology canvas depicting Subnet Gateway and live host constellation.
  - Animated risk indicator nodes (Critical/High in Red, Medium in Amber, Low/Safe in Emerald Green).
  - Interactive Host Inspector modal displaying live status, open port pills, and direct host drilldown links.

- **🛡️ Threat Intelligence & CVE Correlation Engine (`ThreatCorrelator`):**
  - Automated CVE correlation mapping detected software versions and service banners to known vulnerability advisories.
  - Pre-mapped vulnerabilities including Apache Path Traversal (CVE-2021-41773, CVE-2021-42013), ProFTPD mod_copy (CVE-2015-3306), EternalBlue SMBv1 (CVE-2017-0144), SambaCry (CVE-2017-7494), OpenSSH User Enumeration, and Heartbleed.
  - Standardized CVSS v3 severity ratings and exploitability status.
  - Actionable remediation blueprints for each advisory.
  - Dedicated UI view `/threat-intel`.

- **🎯 MITRE ATT&CK Matrix Alignment:**
  - Findings and risk rules are explicitly mapped to MITRE ATT&CK enterprise techniques (e.g., T1190, T1021, T1040, T1046, T1611).

- **🏆 Dynamic Security Posture Scorecard:**
  - Computes an overall network security score (0–100) and letter grades (A+, A, B, C, D, F) with weighted severity deductions.
  - Highlights prioritized action items and required remediation counts.

- **🧮 CIDR & Subnet Intelligence Calculator (`/cidr-calc`):**
  - Comprehensive subnet calculation engine: Network address, broadcast, netmask, wildcard mask, and usable host scopes.
  - Automatic IP classification (RFC 1918 Private, Global Internet WAN, Loopback, Link-Local).
  - Binary netmask representation and 1-click "Launch Fast Scan on this Subnet" integration.

- **🌐 Web Security & HTTP Headers Reconnaissance (`/web-recon`):**
  - Probes HTTP and HTTPS ports for essential security headers: `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
  - Detects software disclosures in `Server` and `X-Powered-By` headers.
  - Evaluates TLS/SSL connection version, cipher suites, and encryption bit strength.

- **📝 Advanced Exporting Capabilities:**
  - New GitHub-flavored Markdown (`.md`) export formatted for security assessment reports.
  - New Executive JSON Scorecard export for management reporting.

- **🧪 Comprehensive Test Suite:**
  - Added `tests/test_v2_features.py` covering socket scanning, CVE matching, subnet math, web recon, and routes.
  - Total test suite expanded to 94 tests with 100% pass rate.

#### Changed
- Upgraded `RiskEngine` with 15+ new enterprise security rules (Redis unauthenticated access, MongoDB, Docker API 2375, Kubernetes 6443, WinRM, Memcached, Elasticsearch).
- Modernized dark cyber UI with new navigation items, glowing status badges, and `v2.0 Pro` theme accents.
- Fixed variable scoping bug in `ReportExporter.to_html`.

---

## [1.0.0] - 2026-10-20

### 🔬 Initial Release — NetScope Lab v1.0.0

#### Added
- **Live Nmap Scanner:**
  - Background execution wrapper for Nmap commands with live phase progress, ETA calculation, and cancellation support.
  - Supported scan profiles: Ping Sweep, Quick Scan, SYN Stealth, Service Detection, Full Scan, Aggressive Scan, Vulnerability Scripts (NSE), and UDP.
- **XML & JSON Parsing:**
  - Secure defusedxml parser for Nmap XML output.
  - JSON parser for structured scan files.
  - Scan result merging support.
- **Risk Analysis Engine:**
  - Initial rule-based evaluation of exposed common services (Telnet, FTP, SMB, RDP, SSH, SNMP, VNC).
  - Transparent limitation notices on findings.
- **Scan History & Persistence:**
  - SQLite snapshot database in `instance/`.
  - Scan snapshot comparison (added hosts, removed hosts, changed services, newly opened ports).
- **Web Dashboard:**
  - Host inventory with search and state filtering.
  - Individual host detail view with port/service inspect.
  - Export to HTML, JSON, and CSV inventory.
