"""
NetScope Lab — Flask application factory and routes.

A cybersecurity analysis dashboard for imported Nmap XML and JSON scan reports.
"""

from __future__ import annotations

import io
import json
import logging
import os
import threading
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    Response,
    url_for,
)

from netscope_lab.analysis.risk_engine import Finding, RiskEngine
from netscope_lab.analysis.stats import compute_statistics
from netscope_lab.config import config_map
from netscope_lab.history_store import initialize as initialize_history
from netscope_lab.history_store import list_scans, load_latest, load_scan, save_scan
from netscope_lab.models.scan_data import ScanResult
from netscope_lab.parsers.json_parser import parse_json_report
from netscope_lab.parsers.nmap_xml import parse_nmap_xml
from netscope_lab.reports.exporter import ReportExporter
from netscope_lab.scanner.nmap_runner import (
    SCAN_TYPES,
    NmapNotFoundError,
    NmapRunner,
    find_nmap,
)

logger = logging.getLogger(__name__)

# In-memory store for current session's scan data
_current_scan: ScanResult | None = None
_current_findings: list[Finding] = []
_current_stats: dict[str, Any] = {}

# Live scanner state (one scan at a time)
_runner: NmapRunner = NmapRunner()
_runner_lock = threading.Lock()


def create_app(config_name: str = "default") -> Flask:
    """
    Application factory.

    Args:
        config_name: Configuration profile name.

    Returns:
        Configured Flask application.
    """
    global _current_scan, _current_findings, _current_stats
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.config.from_object(config_map.get(config_name, config_map["default"]))
    if app.config.get("TESTING"):
        test_database_dir = tempfile.TemporaryDirectory(prefix="netscope-test-")
        app.extensions["netscope_test_database_dir"] = test_database_dir
        app.config["DATABASE_PATH"] = str(Path(test_database_dir.name) / "scans.sqlite3")

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, app.config.get("LOG_LEVEL", "INFO")),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Ensure upload dir exists
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    initialize_history(app.config["DATABASE_PATH"])
    _current_scan = load_latest(app.config["DATABASE_PATH"])
    _current_findings = RiskEngine().analyze(_current_scan) if _current_scan else []
    _current_stats = compute_statistics(_current_scan) if _current_scan else {}

    # Register routes
    _register_routes(app)

    return app


def _allowed_file(filename: str) -> bool:
    """Check if uploaded file has an allowed extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"xml", "json"}


def _register_routes(app: Flask) -> None:
    """Register all application routes."""

    @app.route("/")
    def dashboard():
        """Main dashboard page."""
        return render_template(
            "dashboard.html",
            scan=_current_scan,
            stats=_current_stats,
            findings=_current_findings,
            has_data=_current_scan is not None and len(_current_scan.hosts) > 0,
        )

    @app.route("/hosts")
    def hosts():
        """Host listing page with search/filter."""
        search = request.args.get("search", "").lower()
        state_filter = request.args.get("state", "all")

        filtered_hosts = []
        if _current_scan:
            for h in _current_scan.hosts:
                if state_filter != "all" and h.status != state_filter:
                    continue
                if search:
                    searchable = f"{h.ip_address} {' '.join(h.hostnames)} {h.status} {h.mac_address} {h.vendor}".lower()
                    if search not in searchable:
                        continue
                filtered_hosts.append(h)

        return render_template(
            "hosts.html",
            hosts=filtered_hosts,
            search=search,
            state_filter=state_filter,
            has_data=_current_scan is not None,
        )

    @app.route("/host/<host_ip>")
    def host_detail(host_ip: str):
        """Detailed host inspection page."""
        host = None
        host_findings: list[Finding] = []

        if _current_scan:
            for h in _current_scan.hosts:
                if h.ip_address == host_ip:
                    host = h
                    break

        if host:
            host_findings = [f for f in _current_findings if f.host_ip == host_ip]

        return render_template(
            "host_detail.html",
            host=host,
            findings=host_findings,
            host_ip=host_ip,
        )

    @app.route("/findings")
    def findings():
        """Findings page with rule details, evidence, and limitations."""
        severity_filter = request.args.get("severity", "all")
        filtered = _current_findings
        if severity_filter != "all":
            filtered = [f for f in _current_findings if f.severity == severity_filter]

        engine = RiskEngine()
        rules_info = engine.get_rules_info()

        return render_template(
            "findings.html",
            findings=filtered,
            severity_filter=severity_filter,
            rules_info=rules_info,
            has_data=_current_scan is not None,
        )

    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        """File upload / import page."""
        global _current_scan, _current_findings, _current_stats

        if request.method == "POST":
            if "file" not in request.files:
                flash("No file selected.", "error")
                return redirect(url_for("upload"))

            file = request.files["file"]
            if file.filename == "" or file.filename is None:
                flash("No file selected.", "error")
                return redirect(url_for("upload"))

            if not _allowed_file(file.filename):
                flash("Unsupported file type. Please upload .xml or .json files.", "error")
                return redirect(url_for("upload"))

            try:
                content = file.read()
                filename = file.filename

                if filename.lower().endswith(".xml"):
                    result = parse_nmap_xml(io.BytesIO(content), filename=filename)
                elif filename.lower().endswith(".json"):
                    result = parse_json_report(io.BytesIO(content), filename=filename)
                else:
                    flash("Unsupported file format.", "error")
                    return redirect(url_for("upload"))

                # Merge or replace
                if request.form.get("merge") == "on" and _current_scan:
                    _current_scan.merge(result)
                    _current_scan.scan_id = uuid.uuid4().hex[:12]
                    _current_scan.import_timestamp = datetime.now().isoformat()
                else:
                    _current_scan = result

                engine = RiskEngine()
                _current_findings = engine.analyze(_current_scan)
                _current_stats = compute_statistics(_current_scan)
                save_scan(app.config["DATABASE_PATH"], _current_scan)

                host_count = len(_current_scan.hosts)
                warning_count = len(_current_scan.warnings)
                flash(
                    f"Successfully imported {filename}: {host_count} hosts found, "
                    f"{warning_count} warnings.",
                    "success",
                )
                return redirect(url_for("dashboard"))

            except ValueError as e:
                flash(f"Import error: {e}", "error")
                return redirect(url_for("upload"))
            except Exception as e:
                logger.exception("Unexpected import error")
                flash(f"Unexpected error: {e}", "error")
                return redirect(url_for("upload"))

        return render_template("upload.html", has_data=_current_scan is not None)

    @app.route("/load-sample/<sample_type>")
    def load_sample(sample_type: str):
        """Load bundled sample data."""
        global _current_scan, _current_findings, _current_stats

        sample_dir = Path(app.config["SAMPLE_DATA_DIR"])

        try:
            if sample_type == "xml":
                path = sample_dir / "sample_scan.xml"
                _current_scan = parse_nmap_xml(path)
            elif sample_type == "json":
                path = sample_dir / "sample_scan.json"
                _current_scan = parse_json_report(path)
            elif sample_type == "both":
                xml_result = parse_nmap_xml(sample_dir / "sample_scan.xml")
                json_result = parse_json_report(sample_dir / "sample_scan.json")
                _current_scan = xml_result
                _current_scan.merge(json_result)
            else:
                flash("Unknown sample type.", "error")
                return redirect(url_for("upload"))

            engine = RiskEngine()
            _current_findings = engine.analyze(_current_scan)
            _current_stats = compute_statistics(_current_scan)
            save_scan(app.config["DATABASE_PATH"], _current_scan, scan_type=f"sample-{sample_type}")
            flash(f"Loaded sample {sample_type.upper()} data successfully.", "success")

        except Exception as e:
            logger.exception("Failed to load sample data")
            flash(f"Error loading sample data: {e}", "error")

        return redirect(url_for("dashboard"))

    @app.route("/reports")
    def reports():
        """Report export page."""
        return render_template(
            "reports.html",
            has_data=_current_scan is not None and len(_current_scan.hosts) > 0,
        )

    @app.route("/history")
    def scan_history():
        """Show scans saved across application restarts."""
        scans = list_scans(app.config["DATABASE_PATH"])
        return render_template("history.html", scans=scans, has_data=_current_scan is not None)

    @app.route("/history/compare", methods=["POST"])
    def compare_historical_scans():
        """Compare two saved scan snapshots."""
        older_id = request.form.get("older_scan", "")
        newer_id = request.form.get("newer_scan", "")
        if not older_id or not newer_id or older_id == newer_id:
            flash("Choose two different saved scans to compare.", "error")
            return redirect(url_for("scan_history"))
        older = load_scan(app.config["DATABASE_PATH"], older_id)
        newer = load_scan(app.config["DATABASE_PATH"], newer_id)
        if not older or not newer:
            flash("One of those saved scans could not be found.", "error")
            return redirect(url_for("scan_history"))

        def open_ports(scan: ScanResult) -> dict[tuple[str, int, str], str]:
            return {
                (host.ip_address, port.port_id, port.protocol): port.service.display_name()
                for host in scan.hosts for port in host.ports if port.is_open
            }

        old_ips = {host.ip_address for host in older.hosts}
        new_ips = {host.ip_address for host in newer.hosts}
        old_ports, new_ports = open_ports(older), open_ports(newer)
        old_port_keys, new_port_keys = set(old_ports), set(new_ports)
        newly_open = [(*key, new_ports[key]) for key in sorted(new_port_keys - old_port_keys)]
        no_longer_open = [(*key, old_ports[key]) for key in sorted(old_port_keys - new_port_keys)]
        service_changes = [
            (*key, old_ports[key], new_ports[key]) for key in sorted(old_port_keys & new_port_keys)
            if old_ports[key] != new_ports[key]
        ]
        return render_template(
            "compare.html",
            older=older,
            newer=newer,
            added_hosts=sorted(new_ips - old_ips),
            missing_hosts=sorted(old_ips - new_ips),
            newly_open=newly_open,
            no_longer_open=no_longer_open,
            service_changes=service_changes,
            has_data=_current_scan is not None,
        )

    @app.route("/history/<scan_id>/load", methods=["POST"])
    def load_historical_scan(scan_id: str):
        """Load a prior scan into the dashboard."""
        global _current_scan, _current_findings, _current_stats
        scan = load_scan(app.config["DATABASE_PATH"], scan_id)
        if not scan:
            flash("That saved scan could not be found.", "error")
            return redirect(url_for("scan_history"))
        _current_scan = scan
        _current_findings = RiskEngine().analyze(scan)
        _current_stats = compute_statistics(scan)
        flash(f"Loaded saved scan {scan_id}.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/export/<format_type>")
    def export_report(format_type: str):
        """Download report in specified format."""
        if not _current_scan:
            flash("No data to export. Import a scan first.", "error")
            return redirect(url_for("reports"))

        exporter = ReportExporter()

        if format_type == "json":
            content = exporter.to_json(_current_scan, _current_findings, _current_stats)
            return Response(
                content,
                mimetype="application/json",
                headers={"Content-Disposition": "attachment; filename=netscope_report.json"},
            )
        elif format_type == "html":
            content = exporter.to_html(_current_scan, _current_findings, _current_stats)
            return Response(
                content,
                mimetype="text/html",
                headers={"Content-Disposition": "attachment; filename=netscope_report.html"},
            )
        elif format_type == "csv":
            content = exporter.to_csv(_current_scan)
            return Response(
                content,
                mimetype="text/csv; charset=utf-8",
                headers={"Content-Disposition": "attachment; filename=netscope_ports.csv"},
            )
        else:
            flash("Unsupported export format.", "error")
            return redirect(url_for("reports"))

    @app.route("/api/stats")
    def api_stats():
        """API endpoint for chart data."""
        return Response(
            json.dumps(_current_stats, default=str),
            mimetype="application/json",
        )

    # ------------------------------------------------------------------
    # Live scanner routes
    # ------------------------------------------------------------------

    @app.route("/scan", methods=["GET", "POST"])
    def live_scan():
        """Live nmap scan — form and launch."""
        global _runner, _current_scan, _current_findings, _current_stats

        # Keep the active scan visible when the user returns to Live Scan.
        if request.method == "GET" and _runner.running:
            return redirect(url_for("scan_status_page"))

        # Check nmap availability
        nmap_available = True
        nmap_path = ""
        try:
            nmap_path = find_nmap()
        except NmapNotFoundError:
            nmap_available = False

        if request.method == "POST":
            if not nmap_available:
                flash("nmap is not installed. Run: sudo apt install nmap", "error")
                return redirect(url_for("live_scan"))

            if _runner.running:
                flash("A scan is already running. Please wait or cancel it.", "error")
                return redirect(url_for("scan_status_page"))

            target = request.form.get("target", "").strip()
            scan_type = request.form.get("scan_type", "quick")
            port_range = request.form.get("port_range", "").strip()
            timing = request.form.get("timing", "3")
            timeout_minutes = request.form.get("timeout_minutes", "30")
            port_mode = request.form.get("port_mode", "profile")
            exclude = request.form.get("exclude", "").strip()
            skip_discovery = request.form.get("skip_discovery") == "on"
            disable_dns = request.form.get("disable_dns") == "on"
            version_intensity = request.form.get("version_intensity", "default")
            os_detection = request.form.get("os_detection") == "on"
            traceroute = request.form.get("traceroute") == "on"
            safe_scripts = request.form.get("safe_scripts") == "on"

            if not target:
                flash("Please enter a scan target.", "error")
                return redirect(url_for("live_scan"))

            if scan_type not in SCAN_TYPES:
                flash("Invalid scan type selected.", "error")
                return redirect(url_for("live_scan"))

            if timeout_minutes not in {"30", "60", "120"}:
                flash("Select a supported maximum scan duration.", "error")
                return redirect(url_for("live_scan"))

            # Create fresh runner and start background thread
            _runner = NmapRunner()

            def _do_scan():
                global _current_scan, _current_findings, _current_stats
                _runner.run(
                    target, scan_type, port_range,
                    timeout=int(timeout_minutes) * 60,
                    timing=timing,
                    port_mode=port_mode,
                    exclude=exclude,
                    skip_discovery=skip_discovery,
                    disable_dns=disable_dns,
                    version_intensity=version_intensity,
                    os_detection=os_detection,
                    traceroute=traceroute,
                    safe_scripts=safe_scripts,
                )
                if _runner.result and not _runner.cancelled:
                    _current_scan = _runner.result
                    _current_scan.metadata.scan_type = _runner.scan_type
                    _current_scan.metadata.source_file = f"Live scan: {_runner.target}"
                    _current_scan.metadata.source_format = "nmap"
                    options = [f"timing=T{timing}", f"ports={port_mode}"]
                    if port_range:
                        options.append(f"custom_ports={port_range}")
                    if exclude:
                        options.append(f"excluded={exclude}")
                    if skip_discovery:
                        options.append("skip_discovery=true")
                    if disable_dns:
                        options.append("reverse_dns=off")
                    if version_intensity != "default":
                        options.append(f"service_detection={version_intensity}")
                    if os_detection:
                        options.append("os_detection=true")
                    if traceroute:
                        options.append("traceroute=true")
                    if safe_scripts:
                        options.append("nse=safe")
                    _current_scan.metadata.command_line = "; ".join(options)
                    engine = RiskEngine()
                    _current_findings = engine.analyze(_current_scan)
                    _current_stats = compute_statistics(_current_scan)
                    save_scan(app.config["DATABASE_PATH"], _current_scan, target=_runner.target, scan_type=_runner.scan_type)
                    logger.info("Scan results stored: %d hosts", len(_current_scan.hosts))

            thread = threading.Thread(target=_do_scan, daemon=True)
            thread.start()

            return redirect(url_for("scan_status_page"))

        return render_template(
            "scan.html",
            scan_types=SCAN_TYPES,
            nmap_available=nmap_available,
            nmap_path=nmap_path,
            has_data=_current_scan is not None,
        )

    @app.route("/scan/status")
    def scan_status_page():
        """Scan progress page."""
        return render_template(
            "scan_status.html",
            runner=_runner,
            has_data=_current_scan is not None,
        )

    @app.route("/api/scan/status")
    def api_scan_status():
        """JSON endpoint polled by the status page."""
        scan_committed = not _runner.result or _current_scan is _runner.result
        data = {
            "running": _runner.running,
            "done": _runner.done and scan_committed,
            "cancelled": _runner.cancelled,
            "message": _runner.message,
            "error": _runner.error,
            "target": _runner.target,
            "scan_type": _runner.scan_type,
            "scan_type_name": SCAN_TYPES.get(_runner.scan_type, {}).get("name", ""),
            "progress_percent": _runner.progress_percent,
            "eta_seconds": _runner.eta_seconds,
            "phase": _runner.phase,
            "progress_source": _runner.progress_source,
            "host_count": len(_current_scan.hosts) if _current_scan and _runner.done and scan_committed and not _runner.error else 0,
            "hosts_up": _current_stats.get("hosts_up", 0) if _runner.done and scan_committed and not _runner.error else 0,
            "open_ports": _current_stats.get("total_open_ports", 0) if _runner.done and scan_committed and not _runner.error else 0,
        }
        return Response(json.dumps(data), mimetype="application/json")

    @app.route("/scan/cancel")
    def scan_cancel():
        """Cancel running scan."""
        if _runner.running:
            _runner.cancel()
            flash("Scan cancelled.", "error")
        else:
            flash("No scan is currently running.", "error")
        return redirect(url_for("scan_status_page"))

    @app.errorhandler(404)
    def not_found(e):
        return render_template("base.html", error="Page not found"), 404

    @app.errorhandler(413)
    def too_large(e):
        flash("File too large. Maximum size is 50 MB.", "error")
        return redirect(url_for("upload"))

