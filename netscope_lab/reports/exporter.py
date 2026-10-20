"""
NetScope Lab — Report exporter.

Generates HTML and JSON reports from scan results and findings.
"""

from __future__ import annotations

import json
import logging
import csv
import io
import html as html_lib
from datetime import datetime
from typing import Any

from netscope_lab.analysis.risk_engine import Finding
from netscope_lab.models.scan_data import ScanResult

logger = logging.getLogger(__name__)


class ReportExporter:
    """Generates exportable reports in HTML and JSON formats."""

    @staticmethod
    def to_json(scan_result: ScanResult, findings: list[Finding], stats: dict[str, Any]) -> str:
        """
        Generate a JSON report.

        Args:
            scan_result: The parsed scan data.
            findings: Risk findings from analysis.
            stats: Computed statistics.

        Returns:
            JSON string of the complete report.
        """
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "NetScope Lab",
                "version": "1.0.0",
            },
            "scan_metadata": {
                "scanner": scan_result.metadata.scanner,
                "scanner_version": scan_result.metadata.scanner_version,
                "scan_type": scan_result.metadata.scan_type,
                "scan_options": scan_result.metadata.command_line,
                "start_time": scan_result.metadata.start_time,
                "end_time": scan_result.metadata.end_time,
                "source_file": scan_result.metadata.source_file,
            },
            "statistics": stats,
            "hosts": [
                {
                    "ip_address": host.ip_address,
                    "hostnames": host.hostnames,
                    "status": host.status,
                    "mac_address": host.mac_address,
                    "vendor": host.vendor,
                    "os_matches": host.os_matches,
                    "ports": [
                        {
                            "port_id": port.port_id,
                            "protocol": port.protocol,
                            "state": port.state.value,
                            "reason": port.reason,
                            "service": {
                                "name": port.service.name,
                                "product": port.service.product,
                                "version": port.service.version,
                            },
                        }
                        for port in host.ports
                    ],
                }
                for host in scan_result.hosts
            ],
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "limitation": f.limitation,
                    "host_ip": f.host_ip,
                    "port": f.port,
                    "protocol": f.protocol,
                    "service": f.service,
                }
                for f in findings
            ],
            "warnings": [
                {
                    "category": w.category,
                    "message": w.message,
                    "host_ip": w.host_ip,
                }
                for w in scan_result.warnings
            ],
        }
        return json.dumps(report, indent=2, default=str)

    @staticmethod
    def to_csv(scan_result: ScanResult) -> str:
        """Export one row per port in a spreadsheet-friendly format."""
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["host", "hostnames", "host_status", "port", "protocol", "state", "service", "product", "version"])
        for host in scan_result.hosts:
            if not host.ports:
                writer.writerow([host.ip_address, ", ".join(host.hostnames), host.status, "", "", "", "", "", ""])
            for port in host.ports:
                cells = [host.ip_address, ", ".join(host.hostnames), host.status, port.port_id,
                         port.protocol, port.state.value, port.service.name,
                         port.service.product, port.service.version]
                # Prevent spreadsheet formula execution from imported scan strings.
                writer.writerow([("'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t")) else value)
                                 for value in cells])
        return output.getvalue()

    @staticmethod
    def to_html(scan_result: ScanResult, findings: list[Finding], stats: dict[str, Any]) -> str:
        """
        Generate a standalone HTML report.

        Args:
            scan_result: The parsed scan data.
            findings: Risk findings from analysis.
            stats: Computed statistics.

        Returns:
            HTML string of the complete report.
        """
        severity_colors = {
            "high": "#ef4444",
            "medium": "#f59e0b",
            "low": "#3b82f6",
            "info": "#6b7280",
        }
        esc = lambda value: html_lib.escape(str(value), quote=True)

        findings_html = ""
        for f in findings:
            color = severity_colors.get(f.severity, "#6b7280")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; padding: 12px; margin: 8px 0; background: #1e293b; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="color: {color};">[{esc(f.severity.upper())}] {esc(f.rule_name)}</strong>
                    <span style="color: #94a3b8; font-size: 0.85em;">{esc(f.rule_id)}</span>
                </div>
                <p style="color: #cbd5e1; margin: 8px 0;">{esc(f.description)}</p>
                <p style="color: #94a3b8; font-size: 0.9em;"><strong>Evidence:</strong> {esc(f.evidence)}</p>
                <p style="color: #f59e0b; font-size: 0.85em;"><strong>⚠ Limitation:</strong> {esc(f.limitation)}</p>
            </div>
            """

        hosts_html = ""
        for host in scan_result.hosts:
            ports_rows = ""
            for p in host.ports:
                state_color = {"open": "#22c55e", "closed": "#ef4444", "filtered": "#f59e0b"}.get(p.state.value, "#6b7280")
                ports_rows += f"""
                <tr>
                    <td>{p.port_id}</td>
                    <td>{esc(p.protocol)}</td>
                    <td style="color: {state_color};">{esc(p.state.value)}</td>
                    <td>{esc(p.service.name)}</td>
                    <td>{esc(p.service.product)} {esc(p.service.version)}</td>
                </tr>
                """
            hosts_html += f"""
            <div class="host-card" style="background: #1e293b; padding: 16px; margin: 12px 0; border-radius: 8px;">
                <h3 style="color: #e2e8f0; margin-top: 0;">{esc(host.display_name)}</h3>
                <p style="color: #94a3b8;">Status: {esc(host.status)} | Open ports: {len(host.open_ports)}</p>
                <table style="width: 100%; border-collapse: collapse; color: #cbd5e1;">
                    <thead>
                        <tr style="border-bottom: 1px solid #334155;">
                            <th style="text-align: left; padding: 6px;">Port</th>
                            <th style="text-align: left; padding: 6px;">Protocol</th>
                            <th style="text-align: left; padding: 6px;">State</th>
                            <th style="text-align: left; padding: 6px;">Service</th>
                            <th style="text-align: left; padding: 6px;">Version</th>
                        </tr>
                    </thead>
                    <tbody>{ports_rows}</tbody>
                </table>
            </div>
            """

        warnings_html = ""
        for w in scan_result.warnings:
            warnings_html += f'<li style="color: #f59e0b;">[{esc(w.category)}] {esc(w.message)}</li>\n'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetScope Lab Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; padding: 24px; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #38bdf8; margin-bottom: 8px; }}
        h2 {{ color: #7dd3fc; margin: 24px 0 12px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 16px 0; }}
        .stat-card {{ background: #1e293b; padding: 16px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #38bdf8; }}
        .stat-label {{ color: #94a3b8; font-size: 0.9em; }}
        .disclaimer {{ background: #1e293b; border: 1px solid #f59e0b; border-radius: 8px; padding: 16px; margin: 16px 0; color: #fbbf24; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔬 NetScope Lab Report</h1>
        <p style="color: #94a3b8;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Source: {esc(scan_result.metadata.source_file)}</p>

        <div class="disclaimer">
            <strong>⚠ Disclaimer:</strong> This report is based on passive analysis of scan data. Findings indicate
            conditions that <em>may</em> warrant further investigation. No vulnerability is confirmed merely because
            a port is open or a service is detected.
        </div>

        <h2>Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats.get('total_hosts', 0)}</div>
                <div class="stat-label">Total Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get('total_open_ports', 0)}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get('unique_services', 0)}</div>
                <div class="stat-label">Unique Services</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(findings)}</div>
                <div class="stat-label">Findings</div>
            </div>
        </div>

        <h2>Findings ({len(findings)})</h2>
        {findings_html if findings_html else '<p style="color: #94a3b8;">No findings detected.</p>'}

        <h2>Hosts ({len(scan_result.hosts)})</h2>
        {hosts_html if hosts_html else '<p style="color: #94a3b8;">No hosts found.</p>'}

        {"<h2>Warnings (" + str(len(scan_result.warnings)) + ")</h2><ul>" + warnings_html + "</ul>" if warnings_html else ""}

        <footer style="margin-top: 32px; padding-top: 16px; border-top: 1px solid #334155; color: #64748b; font-size: 0.85em;">
            NetScope Lab v1.0.0 — Cybersecurity Analysis Tool. This tool analyzes imported data only and does not perform active scanning.
        </footer>
    </div>
</body>
</html>"""
        return html

    @staticmethod
    def to_markdown(scan_result: ScanResult, findings: list[Finding], stats: dict[str, Any]) -> str:
        """
        Generate a comprehensive GitHub-flavored Markdown security assessment report.
        """
        from netscope_lab.analysis.risk_engine import RiskEngine
        posture = RiskEngine.compute_security_posture(findings, len(scan_result.hosts))

        lines = [
            "# 🔬 NetScope Lab v2.0 — Security Assessment Report",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Scanner Engine:** {scan_result.metadata.scanner} ({scan_result.metadata.scanner_version or '2.0.0'})  ",
            f"**Target Scope:** `{scan_result.metadata.command_line or 'Standard Assessment'}`  ",
            "",
            "---",
            "",
            "## 📊 Executive Posture & Scorecard",
            f"- **Security Score:** `{posture['score']} / 100`",
            f"- **Security Grade:** **{posture['grade']}** ({posture['level']})",
            f"- **Total Discovered Hosts:** `{stats.get('total_hosts', len(scan_result.hosts))}`",
            f"- **Total Open Ports:** `{stats.get('total_open_ports', 0)}`",
            f"- **Total Identified Findings:** `{len(findings)}`",
            "",
            "| Severity | Count |",
            "| :--- | :---: |",
            f"| 🔴 Critical | {posture['counts']['critical']} |",
            f"| 🟠 High | {posture['counts']['high']} |",
            f"| 🟡 Medium | {posture['counts']['medium']} |",
            f"| 🔵 Low | {posture['counts']['low']} |",
            f"| ⚪ Info | {posture['counts']['info']} |",
            "",
            "---",
            "",
            "## 🚨 Findings & Risk Analysis",
        ]

        if not findings:
            lines.append("No active security findings detected within scanned scope.")
        else:
            lines.append("| Severity | Rule / Threat | Target | CVE / MITRE | Actionable Remediation |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for f in findings:
                sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(f.severity.lower(), "⚪")
                target = f"`{f.host_ip}:{f.port}`" if f.port else f"`{f.host_ip}`"
                cve_mitre = []
                if f.cve_id:
                    cve_mitre.append(f"**{f.cve_id}**")
                if f.mitre_attack:
                    cve_mitre.append(f.mitre_attack)
                cve_str = "<br>".join(cve_mitre) if cve_mitre else "Standard Rule"
                remediation = f.remediation if f.remediation else "Review service exposure."
                lines.append(f"| {sev_icon} {f.severity.upper()} | **{f.rule_name}** | {target} | {cve_str} | {remediation} |")

        lines.extend([
            "",
            "---",
            "",
            "## 🖥️ Discovered Hosts & Network Attack Surface",
        ])

        if not scan_result.hosts:
            lines.append("No responsive hosts reported in scan.")
        else:
            for host in scan_result.hosts:
                host_title = host.ip_address
                if host.hostnames:
                    host_title += f" ({', '.join(host.hostnames)})"
                lines.append(f"### Host: `{host_title}`")
                lines.append(f"- **Status:** {host.status.upper()} ({host.status_reason or 'detected'})")
                if host.mac_address:
                    lines.append(f"- **MAC Address:** `{host.mac_address}` {f'({host.vendor})' if host.vendor else ''}")
                if host.os_matches:
                    lines.append(f"- **OS Fingerprint:** {', '.join(host.os_matches)}")

                open_p = host.open_ports
                if open_p:
                    lines.append("")
                    lines.append("| Port | Protocol | Service | Product / Banner |")
                    lines.append("| :---: | :---: | :--- | :--- |")
                    for p in open_p:
                        prod = f"{p.service.product} {p.service.version}".strip() or "N/A"
                        lines.append(f"| `{p.port_id}` | {p.protocol.upper()} | {p.service.name} | {prod} |")
                else:
                    lines.append("- *No open ports detected on this host.*")
                lines.append("")

        lines.extend([
            "---",
            "",
            "> ⚠ **Disclaimer:** *This assessment was generated automatically by NetScope Lab v2.0 based on network probing and banner correlation. No exploit was executed.*",
        ])

        return "\n".join(lines)

    @staticmethod
    def to_executive_summary(scan_result: ScanResult, findings: list[Finding], stats: dict[str, Any]) -> dict[str, Any]:
        """
        Generate executive-level summary and metrics for presentation.
        """
        from netscope_lab.analysis.risk_engine import RiskEngine
        posture = RiskEngine.compute_security_posture(findings, len(scan_result.hosts))

        critical_items = [
            {
                "rule_name": f.rule_name,
                "host": f.host_ip,
                "port": f.port,
                "severity": f.severity,
                "remediation": f.remediation,
            }
            for f in findings if f.severity.lower() in ("critical", "high")
        ]

        return {
            "generated_at": datetime.now().isoformat(),
            "posture": posture,
            "total_hosts": len(scan_result.hosts),
            "total_open_ports": stats.get("total_open_ports", 0),
            "critical_risks": critical_items[:8],
            "recommendation_count": len([f for f in findings if f.remediation]),
        }

