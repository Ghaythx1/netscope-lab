"""
NetScope Lab — JSON report parser.

Parses JSON scan reports into ScanResult objects.
Supports a generic JSON format with hosts, ports, and services.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import IO, Any, Union

from netscope_lab.models.scan_data import (
    HostInfo,
    ParseWarning,
    PortInfo,
    PortState,
    ScanMetadata,
    ScanResult,
    ServiceInfo,
)

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


def parse_json_report(source: Union[str, Path, IO[bytes]], filename: str = "") -> ScanResult:
    """
    Parse a JSON scan report.

    Expected JSON structure:
    {
        "scan_info": { ... },
        "hosts": [
            {
                "ip": "...",
                "hostnames": [...],
                "status": "up",
                "ports": [
                    {
                        "port_id": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": { "name": "http", ... }
                    }
                ]
            }
        ]
    }

    Args:
        source: File path or file-like object.
        filename: Original filename for metadata.

    Returns:
        ScanResult with parsed data.

    Raises:
        ValueError: If input is invalid JSON or exceeds size limits.
    """
    result = ScanResult()
    result.metadata.source_format = "json"
    result.metadata.source_file = filename

    try:
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.exists():
                raise ValueError(f"File not found: {path}")
            if path.stat().st_size > MAX_FILE_SIZE:
                raise ValueError(f"File too large (max {MAX_FILE_SIZE // (1024*1024)} MB)")
            result.metadata.source_file = path.name
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            content = source.read()
            if isinstance(content, bytes):
                content = content.decode("utf-8")
            if len(content) > MAX_FILE_SIZE:
                raise ValueError(f"File too large (max {MAX_FILE_SIZE // (1024*1024)} MB)")
            data = json.loads(content)

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e
    except UnicodeDecodeError as e:
        raise ValueError(f"File encoding error: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object/dictionary")

    # Parse metadata
    _parse_scan_info(data, result.metadata)

    # Parse hosts
    hosts_data = data.get("hosts", [])
    if not isinstance(hosts_data, list):
        raise ValueError("'hosts' field must be a list")

    for i, host_data in enumerate(hosts_data):
        if not isinstance(host_data, dict):
            result.warnings.append(ParseWarning(
                category="malformed",
                message=f"Host entry {i} is not a dictionary",
            ))
            continue
        host, warnings = _parse_host(host_data, i)
        result.hosts.append(host)
        result.warnings.extend(warnings)

    # Check duplicates
    _check_duplicates(result)

    logger.info(
        "Parsed JSON report: %d hosts, %d warnings",
        len(result.hosts),
        len(result.warnings),
    )
    return result


def _parse_scan_info(data: dict[str, Any], meta: ScanMetadata) -> None:
    """Extract scan metadata from JSON."""
    info = data.get("scan_info", {})
    if not isinstance(info, dict):
        return
    meta.scanner = info.get("scanner", "")
    meta.scanner_version = info.get("version", "")
    meta.scan_type = info.get("scan_type", info.get("type", ""))
    meta.command_line = info.get("command_line", info.get("args", ""))
    meta.start_time = info.get("start_time", "")
    meta.end_time = info.get("end_time", "")
    meta.elapsed_seconds = float(info.get("elapsed", 0))
    meta.summary = info.get("summary", "")


def _parse_host(host_data: dict[str, Any], index: int) -> tuple[HostInfo, list[ParseWarning]]:
    """Parse a single host from JSON."""
    warnings: list[ParseWarning] = []
    host = HostInfo()

    host.ip_address = str(host_data.get("ip", host_data.get("ip_address", "")))
    if not host.ip_address:
        warnings.append(ParseWarning(
            category="missing_field",
            message=f"Host entry {index} missing IP address",
        ))

    hostnames = host_data.get("hostnames", [])
    if isinstance(hostnames, list):
        host.hostnames = [str(h) for h in hostnames if h]
    elif isinstance(hostnames, str) and hostnames:
        host.hostnames = [hostnames]

    host.status = str(host_data.get("status", "unknown"))
    host.status_reason = str(host_data.get("status_reason", ""))
    host.mac_address = str(host_data.get("mac_address", ""))
    host.vendor = str(host_data.get("vendor", ""))

    os_matches = host_data.get("os_matches", [])
    if isinstance(os_matches, list):
        host.os_matches = [str(o) for o in os_matches if o]

    # Ports
    ports_data = host_data.get("ports", [])
    if isinstance(ports_data, list):
        for j, port_data in enumerate(ports_data):
            if not isinstance(port_data, dict):
                warnings.append(ParseWarning(
                    category="malformed",
                    message=f"Port entry {j} on host {host.ip_address} is not a dictionary",
                    host_ip=host.ip_address,
                ))
                continue
            port, port_warnings = _parse_port(port_data, host.ip_address, j)
            if port is not None:
                host.ports.append(port)
            warnings.extend(port_warnings)

    return host, warnings


def _parse_port(
    port_data: dict[str, Any], host_ip: str, index: int
) -> tuple[PortInfo | None, list[ParseWarning]]:
    """Parse a single port entry from JSON."""
    warnings: list[ParseWarning] = []

    port_id_raw = port_data.get("port_id", port_data.get("portid"))
    if port_id_raw is None:
        warnings.append(ParseWarning(
            category="missing_field",
            message=f"Port entry {index} missing port_id",
            host_ip=host_ip,
        ))
        return None, warnings

    try:
        port_id = int(port_id_raw)
    except (ValueError, TypeError):
        warnings.append(ParseWarning(
            category="malformed",
            message=f"Invalid port number: {port_id_raw}",
            host_ip=host_ip,
        ))
        return None, warnings

    if not (0 <= port_id <= 65535):
        warnings.append(ParseWarning(
            category="malformed",
            message=f"Port number out of range: {port_id}",
            host_ip=host_ip,
        ))
        return None, warnings

    protocol = str(port_data.get("protocol", "tcp"))
    state = PortState.from_str(str(port_data.get("state", "unknown")))
    reason = str(port_data.get("reason", ""))

    # Service
    service = ServiceInfo()
    svc_data = port_data.get("service", {})
    if isinstance(svc_data, dict):
        service.name = str(svc_data.get("name", "unknown"))
        service.product = str(svc_data.get("product", ""))
        service.version = str(svc_data.get("version", ""))
        service.extra_info = str(svc_data.get("extra_info", ""))
        service.os_type = str(svc_data.get("os_type", ""))
        service.method = str(svc_data.get("method", ""))
        try:
            service.confidence = int(svc_data.get("confidence", 0))
        except (ValueError, TypeError):
            service.confidence = 0
    elif isinstance(svc_data, str):
        service.name = svc_data

    port = PortInfo(
        port_id=port_id,
        protocol=protocol,
        state=state,
        reason=reason,
        service=service,
    )
    return port, warnings


def _check_duplicates(result: ScanResult) -> None:
    """Check for duplicate hosts."""
    seen: dict[str, int] = {}
    for host in result.hosts:
        if host.ip_address:
            seen[host.ip_address] = seen.get(host.ip_address, 0) + 1

    for ip, count in seen.items():
        if count > 1:
            result.warnings.append(ParseWarning(
                category="duplicate",
                message=f"Duplicate host IP: {ip} appears {count} times",
                host_ip=ip,
            ))
