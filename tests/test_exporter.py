"""
Tests for the report exporter.

Covers:
- JSON report generation and structure
- HTML report generation
- Empty data handling
"""

import json

from netscope_lab.analysis.risk_engine import Finding, RiskEngine
from netscope_lab.analysis.stats import compute_statistics
from netscope_lab.models.scan_data import (
    HostInfo,
    PortInfo,
    PortState,
    ScanResult,
    ServiceInfo,
)
from netscope_lab.reports.exporter import ReportExporter


def _make_sample_result() -> tuple[ScanResult, list[Finding], dict]:
    """Create a sample result for testing."""
    host = HostInfo()
    host.ip_address = "10.0.0.1"
    host.hostnames = ["test.local"]
    host.status = "up"
    host.ports = [
        PortInfo(
            port_id=80,
            protocol="tcp",
            state=PortState.OPEN,
            service=ServiceInfo(name="http", product="Apache", version="2.4"),
        ),
        PortInfo(
            port_id=22,
            protocol="tcp",
            state=PortState.OPEN,
            service=ServiceInfo(name="ssh"),
        ),
    ]

    result = ScanResult()
    result.hosts = [host]
    result.metadata.scanner = "nmap"
    result.metadata.source_file = "test.xml"

    engine = RiskEngine()
    findings = engine.analyze(result)
    stats = compute_statistics(result)

    return result, findings, stats


class TestReportExporter:
    """Tests for report export."""

    def test_json_report_structure(self):
        """JSON report has required top-level keys."""
        result, findings, stats = _make_sample_result()
        report_json = ReportExporter.to_json(result, findings, stats)
        report = json.loads(report_json)
        assert "report_metadata" in report
        assert "scan_metadata" in report
        assert "statistics" in report
        assert "hosts" in report
        assert "findings" in report
        assert "warnings" in report

    def test_json_report_metadata(self):
        """JSON report metadata contains tool info."""
        result, findings, stats = _make_sample_result()
        report = json.loads(ReportExporter.to_json(result, findings, stats))
        assert report["report_metadata"]["tool"] == "NetScope Lab"

    def test_json_report_hosts(self):
        """JSON report contains host data."""
        result, findings, stats = _make_sample_result()
        report = json.loads(ReportExporter.to_json(result, findings, stats))
        assert len(report["hosts"]) == 1
        host = report["hosts"][0]
        assert host["ip_address"] == "10.0.0.1"
        assert len(host["ports"]) == 2

    def test_json_report_findings(self):
        """JSON report contains findings."""
        result, findings, stats = _make_sample_result()
        report = json.loads(ReportExporter.to_json(result, findings, stats))
        # SSH finding should be present
        assert len(report["findings"]) >= 1

    def test_html_report_generation(self):
        """HTML report is valid HTML."""
        result, findings, stats = _make_sample_result()
        html = ReportExporter.to_html(result, findings, stats)
        assert "<!DOCTYPE html>" in html
        assert "NetScope Lab" in html
        assert "10.0.0.1" in html

    def test_html_report_contains_disclaimer(self):
        """HTML report includes vulnerability disclaimer."""
        result, findings, stats = _make_sample_result()
        html = ReportExporter.to_html(result, findings, stats)
        assert "Disclaimer" in html
        assert "confirmed" in html.lower() or "may" in html.lower()

    def test_empty_result_json(self):
        """JSON report handles empty results."""
        result = ScanResult()
        report_json = ReportExporter.to_json(result, [], {})
        report = json.loads(report_json)
        assert len(report["hosts"]) == 0
        assert len(report["findings"]) == 0

    def test_empty_result_html(self):
        """HTML report handles empty results."""
        result = ScanResult()
        html = ReportExporter.to_html(result, [], {})
        assert "<!DOCTYPE html>" in html

    def test_json_report_is_valid_json(self):
        """Output is valid parseable JSON."""
        result, findings, stats = _make_sample_result()
        report_str = ReportExporter.to_json(result, findings, stats)
        parsed = json.loads(report_str)
        assert isinstance(parsed, dict)
