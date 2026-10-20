"""
NetScope Lab v2.0 — Enterprise Risk Engine & Threat Correlation.

Evaluates hosts and ports against transparent, configurable security rules.
Each rule explains what it checks, evidence found, MITRE ATT&CK techniques,
CVSS severity mapping, and actionable remediation blueprints.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from netscope_lab.models.scan_data import HostInfo, PortInfo, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A single finding produced by a risk rule."""
    rule_id: str
    rule_name: str
    severity: str  # "critical", "high", "medium", "low", "info"
    description: str
    evidence: str
    limitation: str
    host_ip: str = ""
    port: int | None = None
    protocol: str = ""
    service: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    mitre_attack: str = ""
    remediation: str = ""

    @property
    def severity_order(self) -> int:
        return {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }.get(self.severity.lower(), 5)


@dataclass
class RiskRule:
    """A configurable risk detection rule."""
    rule_id: str
    name: str
    description: str
    severity: str
    limitation: str
    enabled: bool = True
    cve_id: str = ""
    cvss_score: float = 0.0
    mitre_attack: str = ""
    remediation: str = ""
    # Matching criteria
    ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)


# Expanded Rule Set for NetScope Lab v2.0
DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "EXPOSED_TELNET",
        "name": "Telnet Service Detected",
        "description": "Telnet transmits data including credentials in plaintext. "
                       "If this service is intentionally exposed, ensure it is migrated to SSH.",
        "severity": "high",
        "limitation": "Detection is based on port/service identification only.",
        "cve_id": "",
        "cvss_score": 7.5,
        "mitre_attack": "T1040 - Network Sniffing",
        "remediation": "Disable Telnet daemon and migrate management access to OpenSSH.",
        "ports": [23],
        "services": ["telnet"],
    },
    {
        "rule_id": "EXPOSED_FTP",
        "name": "FTP Service Detected",
        "description": "FTP transmits credentials in plaintext without TLS. Consider using SFTP or FTPS instead.",
        "severity": "medium",
        "limitation": "FTP may be configured with TLS (FTPS) which mitigates cleartext risks.",
        "cve_id": "",
        "cvss_score": 5.3,
        "mitre_attack": "T1040 - Network Sniffing",
        "remediation": "Enforce FTPS or transition file transfers to SFTP (Port 22). Disable anonymous login.",
        "ports": [21],
        "services": ["ftp"],
    },
    {
        "rule_id": "EXPOSED_SMB",
        "name": "SMB/CIFS Service Exposed",
        "description": "SMB services exposed to untrusted networks present severe attack surface. "
                       "Historically leveraged by ransomware (WannaCry, NotPetya) and worms.",
        "severity": "high",
        "limitation": "Patch level cannot be determined from port scan alone. Modern SMB3 with encryption may be secure.",
        "cve_id": "CVE-2017-0144",
        "cvss_score": 9.8,
        "mitre_attack": "T1210 - Exploitation of Remote Services",
        "remediation": "Block TCP port 445 at firewall boundaries. Disable SMBv1 and enforce SMB signing/encryption.",
        "ports": [445, 139],
        "services": ["microsoft-ds", "netbios-ssn"],
    },
    {
        "rule_id": "EXPOSED_RDP",
        "name": "RDP Service Detected",
        "description": "Remote Desktop Protocol exposed to networks is heavily targeted by credential stuffing and brute-force.",
        "severity": "medium",
        "limitation": "RDP may be protected by Network Level Authentication (NLA) or MFA.",
        "cve_id": "CVE-2019-0708",
        "cvss_score": 8.1,
        "mitre_attack": "T1021.001 - Remote Desktop Protocol",
        "remediation": "Place RDP behind a VPN, enforce NLA, enable MFA, and limit access via IP whitelisting.",
        "ports": [3389],
        "services": ["ms-wbt-server"],
    },
    {
        "rule_id": "EXPOSED_SSH",
        "name": "SSH Service Detected",
        "description": "SSH is secure by design, but exposure to untrusted networks increases brute-force attack surface.",
        "severity": "low",
        "limitation": "SSH with key-based authentication and fail2ban is safe. Finding is informational.",
        "cve_id": "",
        "cvss_score": 3.7,
        "mitre_attack": "T1021.004 - SSH",
        "remediation": "Disable root SSH login, enforce public key authentication, and use Fail2ban or rate-limiting.",
        "ports": [22],
        "services": ["ssh"],
    },
    {
        "rule_id": "EXPOSED_DATABASE",
        "name": "Database Service Exposed",
        "description": "Direct database port exposure to untrusted networks may allow unauthorized data exfiltration.",
        "severity": "high",
        "limitation": "Database may enforce strong authentication and SSL.",
        "cve_id": "",
        "cvss_score": 8.5,
        "mitre_attack": "T1190 - Exploit Public-Facing Application",
        "remediation": "Bind database to 127.0.0.1 or internal VPC only. Never expose database ports to public WAN.",
        "ports": [3306, 5432, 1433, 1521],
        "services": ["mysql", "postgresql", "ms-sql-s", "oracle"],
    },
    {
        "rule_id": "EXPOSED_REDIS",
        "name": "Redis In-Memory Store Exposed",
        "description": "Redis instances often run without authentication by default, allowing remote attackers to write keys or achieve RCE.",
        "severity": "critical",
        "limitation": "The Redis instance may have requirepass configured.",
        "cve_id": "CVE-2022-0543",
        "cvss_score": 9.8,
        "mitre_attack": "T1059 - Command and Scripting Interpreter",
        "remediation": "Bind Redis to 127.0.0.1, enable protected-mode, set a strong requirepass in redis.conf.",
        "ports": [6379],
        "services": ["redis"],
    },
    {
        "rule_id": "EXPOSED_MONGODB",
        "name": "MongoDB Database Exposed",
        "description": "MongoDB instance exposed to the network. Misconfigured instances may allow unauthorized read/write access.",
        "severity": "high",
        "limitation": "Authentication and TLS might be properly enabled.",
        "cve_id": "",
        "cvss_score": 8.2,
        "mitre_attack": "T1190 - Exploit Public-Facing Application",
        "remediation": "Enable authorization in mongod.conf, configure firewall rules, and avoid public exposure.",
        "ports": [27017],
        "services": ["mongodb"],
    },
    {
        "rule_id": "EXPOSED_ELASTICSEARCH",
        "name": "Elasticsearch Cluster API Exposed",
        "description": "Elasticsearch REST API exposed. Without security features enabled, indices and clusters can be read or erased.",
        "severity": "high",
        "limitation": "Elasticsearch may have X-Pack / OpenSearch security enabled.",
        "cve_id": "CVE-2015-1427",
        "cvss_score": 8.6,
        "mitre_attack": "T1190 - Exploit Public-Facing Application",
        "remediation": "Enable Elasticsearch Security (TLS + basic auth) or restrict access through an API reverse proxy.",
        "ports": [9200],
        "services": ["elasticsearch"],
    },
    {
        "rule_id": "EXPOSED_DOCKER_API",
        "name": "Docker Daemon Unencrypted API Exposed",
        "description": "Docker engine API (port 2375) without TLS grants root-equivalent control over the host system.",
        "severity": "critical",
        "limitation": "Port 2376 uses TLS certificates, while port 2375 is unencrypted.",
        "cve_id": "",
        "cvss_score": 9.8,
        "mitre_attack": "T1611 - Escape to Host",
        "remediation": "Never expose TCP port 2375. Use Unix socket or configure mutual TLS on port 2376.",
        "ports": [2375, 2376],
        "services": ["docker", "docker-ssl"],
    },
    {
        "rule_id": "EXPOSED_KUBERNETES",
        "name": "Kubernetes API Server Exposed",
        "description": "Kubernetes API server port 6443 exposed. Targeted by attackers for cluster reconnaissance and takeover.",
        "severity": "medium",
        "limitation": "API server uses TLS and RBAC by default.",
        "cve_id": "",
        "cvss_score": 6.5,
        "mitre_attack": "T1609 - Execution in Container",
        "remediation": "Restrict API server access to administrative VPN IPs and ensure Anonymous Auth is disabled.",
        "ports": [6443],
        "services": ["kubernetes"],
    },
    {
        "rule_id": "EXPOSED_HTTP_MGMT",
        "name": "HTTP Management Interface Detected",
        "description": "Web-based administration panels or development servers may be exposed.",
        "severity": "medium",
        "limitation": "The HTTP service may be a normal public application.",
        "cve_id": "",
        "cvss_score": 5.0,
        "mitre_attack": "T1190 - Exploit Public-Facing Application",
        "remediation": "Verify authentication, enforce HTTPS, and restrict admin endpoints.",
        "ports": [8080, 8443, 9090, 8888, 10000],
        "services": [],
    },
    {
        "rule_id": "EXPOSED_SNMP",
        "name": "SNMP Service Detected",
        "description": "SNMP (v1/v2c) transmits community strings in plaintext and exposes network routing and OS information.",
        "severity": "medium",
        "limitation": "SNMPv3 with authentication and AES encryption is secure.",
        "cve_id": "",
        "cvss_score": 5.8,
        "mitre_attack": "T1046 - Network Service Discovery",
        "remediation": "Migrate to SNMPv3 with authPriv, change default community strings ('public', 'private').",
        "ports": [161, 162],
        "services": ["snmp"],
    },
    {
        "rule_id": "EXPOSED_VNC",
        "name": "VNC Remote Desktop Detected",
        "description": "VNC provides remote desktop access and frequently suffers from weak passwords or unencrypted sessions.",
        "severity": "medium",
        "limitation": "VNC may be tunneled through an encrypted SSH tunnel.",
        "cve_id": "",
        "cvss_score": 6.5,
        "mitre_attack": "T1021.005 - VNC",
        "remediation": "Tunnel VNC sessions through SSH or VPN and require multi-factor authentication.",
        "ports": [5900, 5901, 5902],
        "services": ["vnc"],
    },
    {
        "rule_id": "EXPOSED_WINRM",
        "name": "Windows Remote Management (WinRM) Exposed",
        "description": "WinRM ports (5985 HTTP, 5986 HTTPS) allow remote PowerShell command execution.",
        "severity": "medium",
        "limitation": "WinRM uses Kerberos or NTLM authentication.",
        "cve_id": "",
        "cvss_score": 6.0,
        "mitre_attack": "T1021.006 - Windows Remote Management",
        "remediation": "Enforce HTTPS (port 5986), disable plaintext HTTP (port 5985), and restrict access via firewall.",
        "ports": [5985, 5986],
        "services": ["wsman"],
    },
    {
        "rule_id": "CLEARTEXT_PROTOCOL",
        "name": "Cleartext Protocol Detected",
        "description": "Services transmitting unencrypted communication allow eavesdropping and credential sniffing.",
        "severity": "low",
        "limitation": "The service may be used only inside an isolated VLAN.",
        "cve_id": "",
        "cvss_score": 4.0,
        "mitre_attack": "T1040 - Network Sniffing",
        "remediation": "Migrate HTTP to HTTPS, POP3 to POP3S, IMAP to IMAPS, and disable TFTP.",
        "ports": [80, 110, 143, 25, 69],
        "services": ["http", "pop3", "imap", "smtp", "tftp"],
    },
]


class RiskEngine:
    """
    Evaluates scan results against configurable risk rules.
    Transparent, verifiable, and actionable.
    """

    def __init__(self, rules: list[dict[str, Any]] | None = None) -> None:
        self.rules: list[RiskRule] = []
        raw_rules = rules if rules is not None else DEFAULT_RULES
        for r in raw_rules:
            self.rules.append(RiskRule(
                rule_id=r.get("rule_id", "UNKNOWN"),
                name=r.get("name", "Unknown Rule"),
                description=r.get("description", ""),
                severity=r.get("severity", "info"),
                limitation=r.get("limitation", ""),
                enabled=r.get("enabled", True),
                cve_id=r.get("cve_id", ""),
                cvss_score=float(r.get("cvss_score", 0.0)),
                mitre_attack=r.get("mitre_attack", ""),
                remediation=r.get("remediation", ""),
                ports=r.get("ports", []),
                services=r.get("services", []),
                products=r.get("products", []),
            ))
        logger.info("Risk engine v2.0 initialized with %d rules", len(self.rules))

    def analyze(self, scan_result: ScanResult) -> list[Finding]:
        """Analyze a scan result and return findings."""
        findings: list[Finding] = []

        for host in scan_result.hosts:
            for port in host.ports:
                if not port.is_open:
                    continue
                for rule in self.rules:
                    if not rule.enabled:
                        continue
                    if self._matches(port, rule):
                        evidence = self._build_evidence(host, port)
                        findings.append(Finding(
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            description=rule.description,
                            evidence=evidence,
                            limitation=rule.limitation,
                            host_ip=host.ip_address,
                            port=port.port_id,
                            protocol=port.protocol,
                            service=port.service.display_name(),
                            cve_id=rule.cve_id,
                            cvss_score=rule.cvss_score,
                            mitre_attack=rule.mitre_attack,
                            remediation=rule.remediation,
                        ))

        findings.sort(key=lambda f: f.severity_order)
        logger.info("Analysis complete: %d findings", len(findings))
        return findings

    def _matches(self, port: PortInfo, rule: RiskRule) -> bool:
        """Check if a port matches a rule's criteria."""
        port_match = port.port_id in rule.ports if rule.ports else False
        service_match = (
            port.service.name.lower() in [s.lower() for s in rule.services]
            if rule.services else False
        )
        product_match = (
            any(p.lower() in port.service.product.lower() for p in rule.products)
            if rule.products and port.service.product else False
        )
        return port_match or service_match or product_match

    def _build_evidence(self, host: HostInfo, port: PortInfo) -> str:
        """Build human-readable evidence string."""
        parts = [
            f"Host: {host.ip_address}",
            f"Port: {port.port_id}/{port.protocol}",
            f"State: {port.state.value}",
        ]
        if port.service.name != "unknown":
            parts.append(f"Service: {port.service.display_name()}")
        if port.reason:
            parts.append(f"Reason: {port.reason}")
        return " | ".join(parts)

    @staticmethod
    def compute_security_posture(findings: list[Finding], total_hosts: int = 1) -> dict[str, Any]:
        """
        Calculate overall security score (0 - 100), letter grade, and posture metrics.
        """
        score = 100.0
        deductions = {
            "critical": 25.0,
            "high": 12.0,
            "medium": 5.0,
            "low": 2.0,
            "info": 0.5,
        }

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
                score -= deductions.get(sev, 1.0)

        score = max(0.0, min(100.0, round(score, 1)))

        if score >= 90:
            grade = "A+"
            level = "Optimal Security Posture"
        elif score >= 80:
            grade = "A"
            level = "Strong Security Posture"
        elif score >= 70:
            grade = "B"
            level = "Moderate Risk"
        elif score >= 55:
            grade = "C"
            level = "Elevated Risk"
        elif score >= 40:
            grade = "D"
            level = "High Vulnerability Exposure"
        else:
            grade = "F"
            level = "Critical Threat State"

        return {
            "score": score,
            "grade": grade,
            "level": level,
            "counts": counts,
            "remediation_actions": len([f for f in findings if f.remediation]),
        }

    def get_rules_info(self) -> list[dict[str, Any]]:
        """Return rule metadata for display in the UI."""
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "limitation": r.limitation,
                "enabled": r.enabled,
                "cve_id": r.cve_id,
                "cvss_score": r.cvss_score,
                "mitre_attack": r.mitre_attack,
                "remediation": r.remediation,
                "ports": r.ports,
                "services": r.services,
            }
            for r in self.rules
        ]
