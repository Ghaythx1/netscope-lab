"""
Tests for the risk analysis engine.

Covers:
- Default rule initialization
- Correct finding generation for risky services
- No false positives on closed ports
- Severity ordering
- Rule enable/disable
- Custom rules
- Evidence and limitation fields
"""

import io
import json

import pytest

from netscope_lab.analysis.risk_engine import RiskEngine, Finding
from netscope_lab.models.scan_data import (
    HostInfo,
    PortInfo,
    PortState,
    ScanResult,
    ServiceInfo,
)


def _make_scan(hosts: list[HostInfo]) -> ScanResult:
    """Helper to build a ScanResult from hosts."""
    result = ScanResult()
    result.hosts = hosts
    return result


def _make_host(ip: str, ports: list[PortInfo]) -> HostInfo:
    """Helper to build a HostInfo."""
    host = HostInfo()
    host.ip_address = ip
    host.status = "up"
    host.ports = ports
    return host


def _make_port(port_id: int, state: PortState, service_name: str = "unknown") -> PortInfo:
    """Helper to build a PortInfo."""
    return PortInfo(
        port_id=port_id,
        protocol="tcp",
        state=state,
        service=ServiceInfo(name=service_name),
    )


class TestRiskEngine:
    """Tests for the risk engine."""

    def test_default_rules_loaded(self):
        """Engine loads default rules."""
        engine = RiskEngine()
        assert len(engine.rules) > 0

    def test_detects_telnet(self):
        """Telnet on open port 23 triggers a finding."""
        host = _make_host("10.0.0.1", [
            _make_port(23, PortState.OPEN, "telnet"),
        ])
        scan = _make_scan([host])
        findings = RiskEngine().analyze(scan)
        telnet_findings = [f for f in findings if f.rule_id == "EXPOSED_TELNET"]
        assert len(telnet_findings) == 1
        assert telnet_findings[0].severity == "high"

    def test_detects_ftp(self):
        """FTP on open port 21 triggers a finding."""
        host = _make_host("10.0.0.1", [
            _make_port(21, PortState.OPEN, "ftp"),
        ])
        findings = RiskEngine().analyze(_make_scan([host]))
        assert any(f.rule_id == "EXPOSED_FTP" for f in findings)

    def test_detects_database(self):
        """Open database ports trigger findings."""
        host = _make_host("10.0.0.1", [
            _make_port(3306, PortState.OPEN, "mysql"),
            _make_port(5432, PortState.OPEN, "postgresql"),
        ])
        findings = RiskEngine().analyze(_make_scan([host]))
        db_findings = [f for f in findings if f.rule_id == "EXPOSED_DATABASE"]
        assert len(db_findings) == 2

    def test_no_finding_on_closed_port(self):
        """Closed ports should not trigger findings."""
        host = _make_host("10.0.0.1", [
            _make_port(23, PortState.CLOSED, "telnet"),
            _make_port(21, PortState.CLOSED, "ftp"),
        ])
        findings = RiskEngine().analyze(_make_scan([host]))
        assert len(findings) == 0

    def test_no_finding_on_filtered_port(self):
        """Filtered ports should not trigger findings (not confirmed open)."""
        host = _make_host("10.0.0.1", [
            _make_port(445, PortState.FILTERED, "microsoft-ds"),
        ])
        findings = RiskEngine().analyze(_make_scan([host]))
        assert len(findings) == 0

    def test_severity_ordering(self):
        """Findings are sorted by severity (high first)."""
        host = _make_host("10.0.0.1", [
            _make_port(22, PortState.OPEN, "ssh"),       # low
            _make_port(23, PortState.OPEN, "telnet"),     # high
            _make_port(21, PortState.OPEN, "ftp"),        # medium
        ])
        findings = RiskEngine().analyze(_make_scan([host]))
        severities = [f.severity for f in findings]
        assert severities.index("high") < severities.index("medium")
        assert severities.index("medium") < severities.index("low")

    def test_evidence_contains_host_info(self):
        """Evidence string contains host IP and port."""
        host = _make_host("192.168.1.1", [
            _make_port(23, PortState.OPEN, "telnet"),
        ])
        findings = RiskEngine().analyze(_make_scan([host]))
        assert "192.168.1.1" in findings[0].evidence
        assert "23" in findings[0].evidence

    def test_limitation_not_empty(self):
        """All findings include a limitation disclaimer."""
        host = _make_host("10.0.0.1", [
            _make_port(23, PortState.OPEN, "telnet"),
        ])
        findings = RiskEngine().analyze(_make_scan([host]))
        for f in findings:
            assert f.limitation, f"Finding {f.rule_id} has empty limitation"

    def test_disabled_rule(self):
        """Disabled rules produce no findings."""
        rules = [
            {
                "rule_id": "TEST_RULE",
                "name": "Test",
                "description": "test",
                "severity": "high",
                "limitation": "test",
                "enabled": False,
                "ports": [80],
                "services": [],
            }
        ]
        host = _make_host("10.0.0.1", [
            _make_port(80, PortState.OPEN, "http"),
        ])
        findings = RiskEngine(rules).analyze(_make_scan([host]))
        assert len(findings) == 0

    def test_custom_rules(self):
        """Custom rules work correctly."""
        rules = [
            {
                "rule_id": "CUSTOM_TEST",
                "name": "Custom Test Rule",
                "description": "Detects port 9999",
                "severity": "medium",
                "limitation": "This is a test rule",
                "ports": [9999],
                "services": ["custom-svc"],
            }
        ]
        host = _make_host("10.0.0.1", [
            _make_port(9999, PortState.OPEN, "custom-svc"),
        ])
        findings = RiskEngine(rules).analyze(_make_scan([host]))
        assert len(findings) == 1
        assert findings[0].rule_id == "CUSTOM_TEST"

    def test_no_hosts_no_findings(self):
        """Empty scan produces no findings."""
        findings = RiskEngine().analyze(_make_scan([]))
        assert len(findings) == 0

    def test_rules_info(self):
        """get_rules_info returns structured rule metadata."""
        engine = RiskEngine()
        info = engine.get_rules_info()
        assert len(info) > 0
        for r in info:
            assert "rule_id" in r
            assert "name" in r
            assert "severity" in r
            assert "limitation" in r

    def test_service_match_by_name(self):
        """Rule matches by service name even on non-standard port."""
        host = _make_host("10.0.0.1", [
            _make_port(12345, PortState.OPEN, "telnet"),
        ])
        findings = RiskEngine().analyze(_make_scan([host]))
        telnet_findings = [f for f in findings if f.rule_id == "EXPOSED_TELNET"]
        assert len(telnet_findings) == 1

    def test_port_match_only(self):
        """Rule matches by port even when service name is unknown."""
        host = _make_host("10.0.0.1", [
            _make_port(23, PortState.OPEN, "unknown"),
        ])
        findings = RiskEngine().analyze(_make_scan([host]))
        telnet_findings = [f for f in findings if f.rule_id == "EXPOSED_TELNET"]
        assert len(telnet_findings) == 1
