"""
NetScope Lab v2.0 — Threat Intelligence & CVE Correlation Engine.

Maps detected services, banners, and versions to known CVE advisories,
CVSS scores, MITRE ATT&CK techniques, and remediation blueprints.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from netscope_lab.models.scan_data import HostInfo, PortInfo, ScanResult


@dataclass
class ThreatAdvisory:
    """Detailed threat advisory linked to a CVE."""
    cve_id: str
    title: str
    cvss_score: float
    severity: str  # critical, high, medium, low
    affected_product: str
    version_regex: str
    mitre_attack: str
    exploitability: str
    remediation: str


# Curated Knowledgebase of Critical & High Vulnerabilities
KNOWN_ADVISORIES: list[ThreatAdvisory] = [
    ThreatAdvisory(
        cve_id="CVE-2021-41773",
        title="Apache HTTP Server Path Traversal & RCE",
        cvss_score=9.8,
        severity="critical",
        affected_product="apache",
        version_regex=r"2\.4\.49",
        mitre_attack="T1190 - Exploit Public-Facing Application",
        exploitability="Actively Exploited in the Wild",
        remediation="Upgrade Apache HTTP Server immediately to 2.4.51 or later. Disable mod_cgi if not required.",
    ),
    ThreatAdvisory(
        cve_id="CVE-2021-42013",
        title="Apache HTTP Server Path Traversal Incomplete Fix",
        cvss_score=9.8,
        severity="critical",
        affected_product="apache",
        version_regex=r"2\.4\.50",
        mitre_attack="T1190 - Exploit Public-Facing Application",
        exploitability="Actively Exploited in the Wild",
        remediation="Upgrade Apache HTTP Server immediately to 2.4.51 or newer.",
    ),
    ThreatAdvisory(
        cve_id="CVE-2015-3306",
        title="ProFTPD mod_copy Arbitrary Remote File Copy",
        cvss_score=10.0,
        severity="critical",
        affected_product="proftpd",
        version_regex=r"1\.3\.5",
        mitre_attack="T1190 - Exploit Public-Facing Application",
        exploitability="Public Metasploit Module Available",
        remediation="Upgrade ProFTPD to 1.3.5a / 1.3.6 or later, or comment out 'LoadModule mod_copy.c' in proftpd.conf.",
    ),
    ThreatAdvisory(
        cve_id="CVE-2016-6210",
        title="OpenSSH User Enumeration Timing Attack",
        cvss_score=5.3,
        severity="medium",
        affected_product="openssh",
        version_regex=r"(?:[0-6]\.|7\.[0-2])",
        mitre_attack="T1589.002 - Gather Victim Identity Info",
        exploitability="Public PoC Available",
        remediation="Update OpenSSH to version 7.3p1 or higher.",
    ),
    ThreatAdvisory(
        cve_id="CVE-2018-15473",
        title="OpenSSH Username Enumeration",
        cvss_score=5.3,
        severity="medium",
        affected_product="openssh",
        version_regex=r"(?:[0-6]\.|7\.[0-7])",
        mitre_attack="T1087 - Account Discovery",
        exploitability="Widely Automated Script Available",
        remediation="Upgrade OpenSSH to version 7.8 or newer.",
    ),
    ThreatAdvisory(
        cve_id="CVE-2017-0144",
        title="EternalBlue SMBv1 Remote Code Execution (MS17-010)",
        cvss_score=9.8,
        severity="critical",
        affected_product="microsoft-ds",
        version_regex=r".*",
        mitre_attack="T1210 - Exploitation of Remote Services",
        exploitability="Weaponized (WannaCry, NotPetya)",
        remediation="Completely disable SMBv1 across Windows endpoints and apply Microsoft patch MS17-010.",
    ),
    ThreatAdvisory(
        cve_id="CVE-2017-7494",
        title="SambaCry Remote Code Execution in Samba",
        cvss_score=9.8,
        severity="critical",
        affected_product="samba",
        version_regex=r"(?:3\.5\.|4\.[0-5]\.|4\.6\.[0-3])",
        mitre_attack="T1190 - Exploit Public-Facing Application",
        exploitability="Public Metasploit Module Available",
        remediation="Update Samba to 4.6.4, 4.5.10, or 4.4.14, and add 'nt pipe support = no' to smb.conf.",
    ),
    ThreatAdvisory(
        cve_id="CVE-2014-0160",
        title="OpenSSL Heartbleed Information Disclosure",
        cvss_score=7.5,
        severity="high",
        affected_product="openssl",
        version_regex=r"1\.0\.1[a-f]?",
        mitre_attack="T1040 - Network Sniffing",
        exploitability="Exploited in the Wild",
        remediation="Upgrade OpenSSL to 1.0.1g or newer and re-issue SSL/TLS certificates.",
    ),
    ThreatAdvisory(
        cve_id="CVE-2022-22965",
        title="Spring4Shell Remote Code Execution",
        cvss_score=9.8,
        severity="critical",
        affected_product="spring",
        version_regex=r"5\.(?:2\.[0-9]|3\.[0-1][0-7])",
        mitre_attack="T1190 - Exploit Public-Facing Application",
        exploitability="Actively Exploited in the Wild",
        remediation="Upgrade Spring Framework to 5.3.18+ or 5.2.20+ and ensure Java version is updated.",
    ),
]


class ThreatCorrelator:
    """Correlates scan results with known CVE intelligence."""

    @staticmethod
    def correlate_port(host_ip: str, port: PortInfo) -> list[ThreatAdvisory]:
        """Check a single port against advisory database."""
        matches: list[ThreatAdvisory] = []
        svc = port.service
        product = (svc.product or "").lower()
        version = (svc.version or "").lower()
        name = (svc.name or "").lower()
        combined = f"{name} {product} {version} {svc.extra_info}".strip()

        for adv in KNOWN_ADVISORIES:
            # Check product match
            prod_match = (
                adv.affected_product in product
                or adv.affected_product in name
                or adv.affected_product in combined
            )

            # Special case for SMB port 445
            if adv.cve_id == "CVE-2017-0144" and port.port_id == 445:
                matches.append(adv)
                continue

            if prod_match:
                if not adv.version_regex or re.search(adv.version_regex, combined, re.IGNORECASE):
                    matches.append(adv)

        return matches

    @classmethod
    def correlate_scan(cls, scan_result: ScanResult) -> list[dict[str, Any]]:
        """
        Correlate entire scan with CVE intelligence.
        Returns list of structured CVE matches with host and port context.
        """
        advisories: list[dict[str, Any]] = []

        for host in scan_result.hosts:
            for port in host.open_ports:
                matches = cls.correlate_port(host.ip_address, port)
                for m in matches:
                    advisories.append({
                        "host_ip": host.ip_address,
                        "hostnames": host.hostnames,
                        "port": port.port_id,
                        "protocol": port.protocol,
                        "service": port.service.display_name(),
                        "cve_id": m.cve_id,
                        "title": m.title,
                        "cvss_score": m.cvss_score,
                        "severity": m.severity,
                        "mitre_attack": m.mitre_attack,
                        "exploitability": m.exploitability,
                        "remediation": m.remediation,
                    })

        return sorted(advisories, key=lambda x: x["cvss_score"], reverse=True)
