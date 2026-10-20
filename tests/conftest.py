"""
Shared test fixtures for NetScope Lab tests.
"""

import io
import json
import pytest
from pathlib import Path

from netscope_lab.app import create_app


@pytest.fixture
def app():
    """Create a test Flask application."""
    app = create_app("testing")
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


@pytest.fixture
def sample_xml_path():
    """Path to sample XML data."""
    return Path(__file__).parent.parent / "netscope_lab" / "sample_data" / "sample_scan.xml"


@pytest.fixture
def sample_json_path():
    """Path to sample JSON data."""
    return Path(__file__).parent.parent / "netscope_lab" / "sample_data" / "sample_scan.json"


@pytest.fixture
def minimal_xml() -> str:
    """Minimal valid Nmap XML string."""
    return """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="1000" startstr="2024-01-01 00:00:00">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="test.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache" version="2.4.57" conf="10"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
        <service name="https" conf="3"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1001" elapsed="1.0" summary="done"/>
  </runstats>
</nmaprun>"""


@pytest.fixture
def minimal_json() -> dict:
    """Minimal valid JSON scan data."""
    return {
        "scan_info": {
            "scanner": "nmap",
            "version": "7.94",
            "scan_type": "syn",
        },
        "hosts": [
            {
                "ip": "10.0.0.1",
                "hostnames": ["test.local"],
                "status": "up",
                "ports": [
                    {
                        "port_id": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": {"name": "http", "product": "Apache", "version": "2.4"},
                    },
                    {
                        "port_id": 443,
                        "protocol": "tcp",
                        "state": "closed",
                        "service": {"name": "https"},
                    },
                ],
            }
        ],
    }
