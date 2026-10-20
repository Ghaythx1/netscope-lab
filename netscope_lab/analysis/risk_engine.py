"""
NetScope Lab — Configurable risk-rule engine.

Evaluates hosts and ports against transparent, configurable rules.
Each rule explains what it checks, the evidence it found, and its limitations.

IMPORTANT: No rule claims a confirmed vulnerability. Rules identify conditions
that MAY warrant further investigation.
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
    severity: str  # "info", "low", "medium", "high"
    description: str
    evidence: str
    limitation: str
    host_ip: str = ""
    port: int | None = None
    protocol: str = ""
    service: str = ""

    @property
    def severity_order(self) -> int:
        return {"high": 0, "medium": 1, "low": 2, "info": 3}.get(self.severity, 4)


@dataclass
class RiskRule:
    """A configurable risk detection rule."""
    rule_id: str
    name: str
    description: str
    severity: str
    limitation: str
    enabled: bool = True
    # Matching criteria
    ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)


# Default rules — transparent and conservative
DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "EXPOSED_TELNET",
        "name": "Telnet Service Detected",
        "description": "Telnet transmits data including credentials in cleartext. "
                       "If this service is intentionally exposed, ensure it is adequately secured.",
        "severity": "high",
        "limitation": "Detection is based on port/service identification only. "
                      "The service may be a honeypot, behind a VPN, or otherwise protected.",
        "ports": [23],
        "services": ["telnet"],
    },
    {
        "rule_id": "EXPOSED_FTP",
        "name": "FTP Service Detected",
        "description": "FTP can transmit credentials in cleartext. Consider using SFTP or FTPS instead.",
        "severity": "medium",
        "limitation": "FTP may be configured with TLS (FTPS) which mitigates cleartext risks. "
                      "Further investigation is needed.",
        "ports": [21],
        "services": ["ftp"],
    },
    {
        "rule_id": "EXPOSED_SMB",
        "name": "SMB/CIFS Service Detected",
        "description": "SMB services exposed to untrusted networks may present a risk. "
                       "Historically targeted by ransomware and worms.",
        "severity": "high",
        "limitation": "The service version and patch level cannot be determined from port scanning alone. "
                      "Modern SMB configurations may be adequately secured.",
        "ports": [445, 139],
        "services": ["microsoft-ds", "netbios-ssn"],
    },
    {
        "rule_id": "EXPOSED_RDP",
        "name": "RDP Service Detected",
        "description": "Remote Desktop Protocol exposed to untrusted networks may be targeted "
                       "by brute-force attacks.",
        "severity": "medium",
        "limitation": "RDP may be protected by Network Level Authentication, MFA, or VPN. "
                      "Port detection alone does not indicate a vulnerability.",
        "ports": [3389],
        "services": ["ms-wbt-server"],
    },
    {
        "rule_id": "EXPOSED_SSH",
        "name": "SSH Service Detected",
        "description": "SSH is generally secure, but exposure to untrusted networks increases "
                       "brute-force attack surface.",
        "severity": "low",
        "limitation": "SSH with key-based auth and fail2ban is considered secure. "
                      "This finding is informational.",
        "ports": [22],
        "services": ["ssh"],
    },
    {
        "rule_id": "EXPOSED_DATABASE",
        "name": "Database Service Detected",
        "description": "Database services exposed to untrusted networks may allow unauthorized access.",
        "severity": "high",
        "limitation": "The database may require authentication and be properly firewalled. "
                      "Port presence alone does not confirm unauthorized access.",
        "ports": [3306, 5432, 1433, 1521, 27017, 6379, 9200],
        "services": ["mysql", "postgresql", "ms-sql-s", "oracle", "mongodb", "redis", "elasticsearch"],
    },
    {
        "rule_id": "EXPOSED_HTTP_MGMT",
        "name": "HTTP Management Interface Detected",
        "description": "Web-based management interfaces (e.g., admin panels) may be exposed.",
        "severity": "medium",
        "limitation": "The HTTP service may be a public website, not an admin panel. "
                      "Content analysis is required to confirm.",
        "ports": [8080, 8443, 9090, 8888, 10000],
        "services": [],
    },
    {
        "rule_id": "EXPOSED_SNMP",
        "name": "SNMP Service Detected",
        "description": "SNMP (especially v1/v2c) uses community strings in cleartext. "
                       "May leak system information.",
        "severity": "medium",
        "limitation": "SNMPv3 with authentication and encryption is considered secure. "
                      "Version cannot be confirmed from port scan alone.",
        "ports": [161, 162],
        "services": ["snmp"],
    },
    {
        "rule_id": "EXPOSED_VNC",
        "name": "VNC Service Detected",
        "description": "VNC provides remote desktop access and may be targeted if exposed.",
        "severity": "medium",
        "limitation": "VNC may be tunneled through SSH/VPN. "
                      "Authentication strength cannot be determined from a port scan.",
        "ports": [5900, 5901, 5902],
        "services": ["vnc"],
    },
    {
        "rule_id": "CLEARTEXT_PROTOCOL",
        "name": "Cleartext Protocol Detected",
        "description": "Services using unencrypted protocols may expose sensitive data in transit.",
        "severity": "low",
        "limitation": "The service may be used only on trusted internal networks "
                      "or wrapped in TLS/VPN tunnels.",
        "ports": [80, 110, 143, 25, 69],
        "services": ["http", "pop3", "imap", "smtp", "tftp"],
    },
]


class RiskEngine:
    """
    Evaluates scan results against configurable risk rules.

    Rules are transparent: each finding includes the rule description,
    evidence found, and explicit limitations of the detection.
    """

    def __init__(self, rules: list[dict[str, Any]] | None = None) -> None:
        """
        Initialize the risk engine.

        Args:
            rules: Optional list of rule dictionaries. Uses DEFAULT_RULES if None.
        """
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
                ports=r.get("ports", []),
                services=r.get("services", []),
                products=r.get("products", []),
            ))
        logger.info("Risk engine initialized with %d rules", len(self.rules))

    def analyze(self, scan_result: ScanResult) -> list[Finding]:
        """
        Analyze a scan result and return findings.

        Args:
            scan_result: The parsed scan data to analyze.

        Returns:
            List of findings sorted by severity.
        """
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
        """Build a human-readable evidence string."""
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
                "ports": r.ports,
                "services": r.services,
            }
            for r in self.rules
        ]
