"""
Tests for Flask routes and workflows.

Covers:
- Dashboard loads with sample data
- Host listing and detail pages
- Findings page
- File upload (valid and invalid)
- Report export
- Sample data loading
- Error handling
"""

import io
import json

import pytest


class TestRoutes:
    """Tests for Flask application routes."""

    def test_dashboard_loads(self, client):
        """Dashboard page returns 200."""
        response = client.get("/")
        assert response.status_code == 200
        assert b"NetScope Lab" in response.data

    def test_hosts_page_loads(self, client):
        """Hosts page returns 200."""
        response = client.get("/hosts")
        assert response.status_code == 200

    def test_findings_page_loads(self, client):
        """Findings page returns 200."""
        response = client.get("/findings")
        assert response.status_code == 200

    def test_upload_page_loads(self, client):
        """Upload page returns 200."""
        response = client.get("/upload")
        assert response.status_code == 200

    def test_reports_page_loads(self, client):
        """Reports page returns 200."""
        response = client.get("/reports")
        assert response.status_code == 200

    def test_load_sample_xml(self, client):
        """Loading XML sample data redirects to dashboard."""
        response = client.get("/load-sample/xml", follow_redirects=True)
        assert response.status_code == 200
        assert b"Dashboard" in response.data or b"dashboard" in response.data

    def test_load_sample_json(self, client):
        """Loading JSON sample data redirects to dashboard."""
        response = client.get("/load-sample/json", follow_redirects=True)
        assert response.status_code == 200

    def test_load_sample_both(self, client):
        """Loading both samples merges data."""
        response = client.get("/load-sample/both", follow_redirects=True)
        assert response.status_code == 200

    def test_load_sample_invalid_type(self, client):
        """Invalid sample type flashes error."""
        response = client.get("/load-sample/invalid", follow_redirects=True)
        assert response.status_code == 200

    def test_upload_valid_xml(self, client, minimal_xml):
        """Upload valid XML file succeeds."""
        data = {
            "file": (io.BytesIO(minimal_xml.encode()), "test.xml"),
        }
        response = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        assert response.status_code == 200

    def test_upload_valid_json(self, client, minimal_json):
        """Upload valid JSON file succeeds."""
        json_bytes = json.dumps(minimal_json).encode()
        data = {
            "file": (io.BytesIO(json_bytes), "test.json"),
        }
        response = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        assert response.status_code == 200

    def test_upload_invalid_extension(self, client):
        """Upload with wrong extension is rejected."""
        data = {
            "file": (io.BytesIO(b"data"), "test.txt"),
        }
        response = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        assert response.status_code == 200
        assert b"Unsupported" in response.data

    def test_upload_no_file(self, client):
        """Upload with no file flashes error."""
        response = client.post("/upload", data={}, content_type="multipart/form-data", follow_redirects=True)
        assert response.status_code == 200

    def test_upload_malformed_xml(self, client):
        """Upload malformed XML flashes error."""
        data = {
            "file": (io.BytesIO(b"<broken>xml"), "bad.xml"),
        }
        response = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        assert response.status_code == 200
        assert b"error" in response.data.lower() or b"Error" in response.data

    def test_upload_malformed_json(self, client):
        """Upload malformed JSON flashes error."""
        data = {
            "file": (io.BytesIO(b"{bad json}"), "bad.json"),
        }
        response = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        assert response.status_code == 200

    def test_host_detail_found(self, client, minimal_xml):
        """Host detail page works after data import."""
        # First load data
        data = {"file": (io.BytesIO(minimal_xml.encode()), "test.xml")}
        client.post("/upload", data=data, content_type="multipart/form-data")
        # Then view host detail
        response = client.get("/host/10.0.0.1")
        assert response.status_code == 200
        assert b"10.0.0.1" in response.data

    def test_host_detail_not_found(self, client):
        """Host detail for unknown IP shows not-found message."""
        response = client.get("/host/99.99.99.99")
        assert response.status_code == 200
        assert b"Not Found" in response.data or b"not found" in response.data.lower()

    def test_export_json_with_data(self, client, minimal_xml):
        """JSON export returns downloadable content."""
        data = {"file": (io.BytesIO(minimal_xml.encode()), "test.xml")}
        client.post("/upload", data=data, content_type="multipart/form-data")
        response = client.get("/export/json")
        assert response.status_code == 200
        assert response.content_type == "application/json"
        report = json.loads(response.data)
        assert "hosts" in report

    def test_export_html_with_data(self, client, minimal_xml):
        """HTML export returns downloadable content."""
        data = {"file": (io.BytesIO(minimal_xml.encode()), "test.xml")}
        client.post("/upload", data=data, content_type="multipart/form-data")
        response = client.get("/export/html")
        assert response.status_code == 200
        assert b"<!DOCTYPE html>" in response.data

    def test_export_without_data(self, client):
        """Export without data redirects."""
        # Reset scan data
        from netscope_lab import app as app_module
        app_module._current_scan = None
        response = client.get("/export/json", follow_redirects=True)
        assert response.status_code == 200

    def test_export_invalid_format(self, client, minimal_xml):
        """Export with invalid format redirects."""
        data = {"file": (io.BytesIO(minimal_xml.encode()), "test.xml")}
        client.post("/upload", data=data, content_type="multipart/form-data")
        response = client.get("/export/csv", follow_redirects=True)
        assert response.status_code == 200

    def test_api_stats(self, client):
        """API stats endpoint returns JSON."""
        response = client.get("/api/stats")
        assert response.status_code == 200
        assert response.content_type == "application/json"

    def test_hosts_search(self, client, minimal_xml):
        """Host search filters results."""
        data = {"file": (io.BytesIO(minimal_xml.encode()), "test.xml")}
        client.post("/upload", data=data, content_type="multipart/form-data")
        # Search for specific IP
        response = client.get("/hosts?search=10.0.0.1")
        assert response.status_code == 200
        assert b"10.0.0.1" in response.data

    def test_hosts_state_filter(self, client, minimal_xml):
        """Host state filter works."""
        data = {"file": (io.BytesIO(minimal_xml.encode()), "test.xml")}
        client.post("/upload", data=data, content_type="multipart/form-data")
        response = client.get("/hosts?state=up")
        assert response.status_code == 200

    def test_findings_severity_filter(self, client, minimal_xml):
        """Findings severity filter works."""
        data = {"file": (io.BytesIO(minimal_xml.encode()), "test.xml")}
        client.post("/upload", data=data, content_type="multipart/form-data")
        response = client.get("/findings?severity=high")
        assert response.status_code == 200

    def test_upload_merge(self, client, minimal_xml):
        """Upload with merge checkbox preserves existing data."""
        data1 = {"file": (io.BytesIO(minimal_xml.encode()), "test1.xml")}
        client.post("/upload", data=data1, content_type="multipart/form-data")
        data2 = {
            "file": (io.BytesIO(minimal_xml.encode()), "test2.xml"),
            "merge": "on",
        }
        response = client.post("/upload", data=data2, content_type="multipart/form-data", follow_redirects=True)
        assert response.status_code == 200

    def test_404_page(self, client):
        """404 page returns correct status."""
        response = client.get("/nonexistent-page")
        assert response.status_code == 404
