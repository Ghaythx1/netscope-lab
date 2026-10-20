"""
Tests for NetScope Lab v2.0 new features and modules.
"""

import json
import pytest
from netscope_lab.analysis.cve_correlator import ThreatCorrelator
from netscope_lab.analysis.network_calc import NetworkCalculator
from netscope_lab.analysis.risk_engine import Finding, RiskEngine
from netscope_lab.analysis.web_recon import WebSecurityRecon
from netscope_lab.app import create_app
from netscope_lab.models.scan_data import HostInfo, PortInfo, PortState, ScanResult, ServiceInfo
from netscope_lab.reports.exporter import ReportExporter
from netscope_lab.scanner.fast_socket_scanner import FastScanConfig, FastSocketScanner


class TestFastSocketScanner:
    def test_parse_ports_presets(self):
        assert len(FastSocketScanner.parse_ports("top20")) == 20
        assert len(FastSocketScanner.parse_ports("common")) >= 30

    def test_parse_ports_custom(self):
        ports = FastSocketScanner.parse_ports("80,443,8000-8005")
        assert 80 in ports
        assert 443 in ports
        assert 8000 in ports
        assert 8005 in ports
        assert 8006 not in ports

    def test_resolve_targets_single_and_cidr(self):
        targets = FastSocketScanner.resolve_targets("127.0.0.1, 10.0.0.0/30")
        assert "127.0.0.1" in targets
        assert "10.0.0.1" in targets
        assert "10.0.0.2" in targets


class TestThreatCorrelator:
    def test_correlate_cve_match(self):
        host = HostInfo(
            ip_address="192.168.1.10",
            ports=[
                PortInfo(
                    port_id=80,
                    state=PortState.OPEN,
                    service=ServiceInfo(name="http", product="Apache httpd", version="2.4.49"),
                ),
                PortInfo(
                    port_id=445,
                    state=PortState.OPEN,
                    service=ServiceInfo(name="microsoft-ds"),
                ),
            ],
        )
        scan = ScanResult(hosts=[host])
        matches = ThreatCorrelator.correlate_scan(scan)
        assert len(matches) >= 2
        cve_ids = [m["cve_id"] for m in matches]
        assert "CVE-2021-41773" in cve_ids
        assert "CVE-2017-0144" in cve_ids


class TestNetworkCalculator:
    def test_subnet_calculation_24(self):
        details = NetworkCalculator.calculate("192.168.1.0/24")
        assert details is not None
        assert details.network_address == "192.168.1.0"
        assert details.broadcast_address == "192.168.1.255"
        assert details.netmask == "255.255.255.0"
        assert details.usable_hosts == 254
        assert details.is_private is True

    def test_subnet_calculation_single_host(self):
        details = NetworkCalculator.calculate("8.8.8.8")
        assert details is not None
        assert details.is_global is True
        assert details.usable_hosts == 1


class TestReportExporterV2:
    def test_markdown_report_generation(self):
        host = HostInfo(
            ip_address="10.0.0.5",
            ports=[PortInfo(port_id=22, state=PortState.OPEN, service=ServiceInfo(name="ssh"))],
        )
        scan = ScanResult(hosts=[host])
        findings = RiskEngine().analyze(scan)
        md = ReportExporter.to_markdown(scan, findings, {"total_hosts": 1, "total_open_ports": 1})
        assert "# 🔬 NetScope Lab v2.0" in md
        assert "Executive Posture" in md
        assert "10.0.0.5" in md

    def test_executive_summary_json(self):
        scan = ScanResult()
        summary = ReportExporter.to_executive_summary(scan, [], {})
        assert "posture" in summary
        assert "grade" in summary["posture"]
        assert summary["posture"]["grade"] == "A+"


class TestV2Routes:
    @pytest.fixture
    def client(self):
        app = create_app("testing")
        with app.test_client() as client:
            yield client

    def test_fast_scan_get(self, client):
        resp = client.get("/fast-scan")
        assert resp.status_code == 200
        assert b"Fast Native Socket Scanner" in resp.data

    def test_topology_get(self, client):
        resp = client.get("/topology")
        assert resp.status_code == 200
        assert b"Network Topology" in resp.data

    def test_cidr_calc_get_and_post(self, client):
        resp = client.get("/cidr-calc")
        assert resp.status_code == 200
        post_resp = client.post("/cidr-calc", data={"cidr": "10.10.0.0/24"})
        assert post_resp.status_code == 200
        assert b"10.10.0.254" in post_resp.data

    def test_web_recon_get(self, client):
        resp = client.get("/web-recon")
        assert resp.status_code == 200
        assert b"HTTP &amp; TLS Endpoint Inspector" in resp.data or b"Endpoint Inspector" in resp.data
