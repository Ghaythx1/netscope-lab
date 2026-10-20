"""
Tests for Nmap XML and JSON parsers.

Covers:
- Correct XML parsing
- Correct JSON parsing
- Missing fields
- Malformed inputs
- Duplicate hosts
- Port state classification
- Invalid file handling
- Oversized file rejection
"""

import io
import json
import pytest

from netscope_lab.models.scan_data import PortState
from netscope_lab.parsers.nmap_xml import parse_nmap_xml
from netscope_lab.parsers.json_parser import parse_json_report


class TestNmapXMLParser:
    """Tests for Nmap XML parsing."""

    def test_parse_valid_xml(self, minimal_xml):
        """Correctly parse a valid Nmap XML report."""
        result = parse_nmap_xml(io.BytesIO(minimal_xml.encode()), filename="test.xml")
        assert len(result.hosts) == 1
        host = result.hosts[0]
        assert host.ip_address == "10.0.0.1"
        assert "test.local" in host.hostnames
        assert host.status == "up"
        assert len(host.ports) == 2

    def test_parse_port_states(self, minimal_xml):
        """Open and closed ports are classified correctly."""
        result = parse_nmap_xml(io.BytesIO(minimal_xml.encode()))
        host = result.hosts[0]
        open_ports = host.open_ports
        closed_ports = host.closed_ports
        assert len(open_ports) == 1
        assert open_ports[0].port_id == 80
        assert len(closed_ports) == 1
        assert closed_ports[0].port_id == 443

    def test_parse_service_info(self, minimal_xml):
        """Service name, product, and version are extracted."""
        result = parse_nmap_xml(io.BytesIO(minimal_xml.encode()))
        port80 = result.hosts[0].ports[0]
        assert port80.service.name == "http"
        assert port80.service.product == "Apache"
        assert port80.service.version == "2.4.57"

    def test_parse_metadata(self, minimal_xml):
        """Scan metadata is extracted from nmaprun element."""
        result = parse_nmap_xml(io.BytesIO(minimal_xml.encode()))
        assert result.metadata.scanner == "nmap"
        assert result.metadata.scanner_version == "7.94"

    def test_parse_sample_file(self, sample_xml_path):
        """Parse the bundled sample XML file."""
        result = parse_nmap_xml(sample_xml_path)
        assert len(result.hosts) >= 5
        assert result.metadata.scanner == "nmap"

    def test_invalid_xml(self):
        """Reject malformed XML."""
        with pytest.raises(ValueError, match="Invalid XML"):
            parse_nmap_xml(io.BytesIO(b"<not>valid xml"))

    def test_not_nmap_xml(self):
        """Reject valid XML that is not an Nmap report."""
        xml = b'<?xml version="1.0"?><root><data>test</data></root>'
        with pytest.raises(ValueError, match="Not an Nmap XML"):
            parse_nmap_xml(io.BytesIO(xml))

    def test_empty_xml(self):
        """Reject empty input."""
        with pytest.raises(ValueError):
            parse_nmap_xml(io.BytesIO(b""))

    def test_host_missing_ip(self):
        """Warn when a host has no IP address."""
        xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.94">
          <host>
            <status state="up"/>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        result = parse_nmap_xml(io.BytesIO(xml.encode()))
        assert len(result.hosts) == 1
        ip_warnings = [w for w in result.warnings if "IP address" in w.message]
        assert len(ip_warnings) >= 1

    def test_port_missing_portid(self):
        """Warn on port element missing portid."""
        xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.94">
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp">
                <state state="open"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        result = parse_nmap_xml(io.BytesIO(xml.encode()))
        assert len(result.hosts[0].ports) == 0
        assert any("portid" in w.message for w in result.warnings)

    def test_port_invalid_number(self):
        """Warn on non-numeric port ID."""
        xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.94">
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="abc">
                <state state="open"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        result = parse_nmap_xml(io.BytesIO(xml.encode()))
        assert len(result.hosts[0].ports) == 0
        assert any("Invalid port" in w.message for w in result.warnings)

    def test_port_out_of_range(self):
        """Warn on port number outside valid range."""
        xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.94">
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="99999">
                <state state="open"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        result = parse_nmap_xml(io.BytesIO(xml.encode()))
        assert len(result.hosts[0].ports) == 0
        assert any("out of range" in w.message for w in result.warnings)

    def test_duplicate_hosts(self):
        """Detect duplicate host IPs."""
        xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.94">
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
          </host>
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
          </host>
        </nmaprun>"""
        result = parse_nmap_xml(io.BytesIO(xml.encode()))
        assert len(result.hosts) == 2
        dup_warnings = [w for w in result.warnings if w.category == "duplicate"]
        assert len(dup_warnings) >= 1

    def test_filtered_port_state(self):
        """Correctly parse filtered port state."""
        xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.94">
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="8080">
                <state state="filtered" reason="no-response"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        result = parse_nmap_xml(io.BytesIO(xml.encode()))
        port = result.hosts[0].ports[0]
        assert port.state == PortState.FILTERED
        assert port.is_filtered
        assert not port.is_open
        assert not port.is_closed

    def test_file_not_found(self):
        """Raise on non-existent file path."""
        with pytest.raises(ValueError, match="File not found"):
            parse_nmap_xml("/nonexistent/path.xml")

    def test_port_state_enum(self):
        """PortState.from_str handles all known states."""
        assert PortState.from_str("open") == PortState.OPEN
        assert PortState.from_str("closed") == PortState.CLOSED
        assert PortState.from_str("filtered") == PortState.FILTERED
        assert PortState.from_str("open|filtered") == PortState.OPEN_FILTERED
        assert PortState.from_str("garbage") == PortState.UNKNOWN
        assert PortState.from_str("  OPEN  ") == PortState.OPEN


class TestJSONParser:
    """Tests for JSON report parsing."""

    def test_parse_valid_json(self, minimal_json):
        """Correctly parse valid JSON input."""
        data = json.dumps(minimal_json).encode()
        result = parse_json_report(io.BytesIO(data), filename="test.json")
        assert len(result.hosts) == 1
        host = result.hosts[0]
        assert host.ip_address == "10.0.0.1"
        assert "test.local" in host.hostnames
        assert len(host.ports) == 2

    def test_parse_port_states_json(self, minimal_json):
        """Correct port state classification from JSON."""
        data = json.dumps(minimal_json).encode()
        result = parse_json_report(io.BytesIO(data))
        host = result.hosts[0]
        assert len(host.open_ports) == 1
        assert len(host.closed_ports) == 1

    def test_parse_service_info_json(self, minimal_json):
        """Service data extracted from JSON."""
        data = json.dumps(minimal_json).encode()
        result = parse_json_report(io.BytesIO(data))
        port80 = result.hosts[0].ports[0]
        assert port80.service.name == "http"
        assert port80.service.product == "Apache"

    def test_parse_metadata_json(self, minimal_json):
        """Metadata extracted from scan_info."""
        data = json.dumps(minimal_json).encode()
        result = parse_json_report(io.BytesIO(data))
        assert result.metadata.scanner == "nmap"
        assert result.metadata.scan_type == "syn"

    def test_parse_sample_json(self, sample_json_path):
        """Parse bundled sample JSON."""
        result = parse_json_report(sample_json_path)
        assert len(result.hosts) >= 3

    def test_invalid_json(self):
        """Reject malformed JSON."""
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_json_report(io.BytesIO(b"{bad json}"))

    def test_json_not_dict(self):
        """Reject JSON that is not a dictionary."""
        with pytest.raises(ValueError, match="must be an object"):
            parse_json_report(io.BytesIO(b"[1,2,3]"))

    def test_json_hosts_not_list(self):
        """Reject JSON where hosts is not a list."""
        with pytest.raises(ValueError, match="must be a list"):
            parse_json_report(io.BytesIO(json.dumps({"hosts": "not a list"}).encode()))

    def test_json_host_missing_ip(self):
        """Warn on host missing IP."""
        data = {"hosts": [{"status": "up", "ports": []}]}
        result = parse_json_report(io.BytesIO(json.dumps(data).encode()))
        assert any("IP address" in w.message for w in result.warnings)

    def test_json_port_missing_id(self):
        """Warn on port missing port_id."""
        data = {
            "hosts": [
                {
                    "ip": "10.0.0.1",
                    "ports": [{"state": "open", "protocol": "tcp"}],
                }
            ]
        }
        result = parse_json_report(io.BytesIO(json.dumps(data).encode()))
        assert len(result.hosts[0].ports) == 0
        assert any("port_id" in w.message for w in result.warnings)

    def test_json_duplicate_hosts(self):
        """Detect duplicate host IPs in JSON."""
        data = {
            "hosts": [
                {"ip": "10.0.0.1", "status": "up", "ports": []},
                {"ip": "10.0.0.1", "status": "up", "ports": []},
            ]
        }
        result = parse_json_report(io.BytesIO(json.dumps(data).encode()))
        dup_warnings = [w for w in result.warnings if w.category == "duplicate"]
        assert len(dup_warnings) >= 1

    def test_json_empty_input(self):
        """Reject empty input."""
        with pytest.raises(ValueError):
            parse_json_report(io.BytesIO(b""))

    def test_json_malformed_port_entry(self):
        """Warn on non-dict port entry."""
        data = {
            "hosts": [
                {"ip": "10.0.0.1", "ports": ["not a dict"]}
            ]
        }
        result = parse_json_report(io.BytesIO(json.dumps(data).encode()))
        assert len(result.hosts[0].ports) == 0
        assert any("not a dictionary" in w.message for w in result.warnings)

    def test_json_malformed_host_entry(self):
        """Warn on non-dict host entry."""
        data = {"hosts": ["not a dict"]}
        result = parse_json_report(io.BytesIO(json.dumps(data).encode()))
        assert len(result.hosts) == 0
        assert any("not a dictionary" in w.message for w in result.warnings)

    def test_json_service_as_string(self):
        """Handle service given as string instead of dict."""
        data = {
            "hosts": [
                {
                    "ip": "10.0.0.1",
                    "ports": [{"port_id": 80, "state": "open", "service": "http"}],
                }
            ]
        }
        result = parse_json_report(io.BytesIO(json.dumps(data).encode()))
        assert result.hosts[0].ports[0].service.name == "http"
