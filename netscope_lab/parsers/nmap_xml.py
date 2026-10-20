"""
NetScope Lab — Nmap XML report parser.

Parses Nmap XML output format into ScanResult objects.
Uses defusedxml to prevent XML attacks (XXE, billion laughs, etc.).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import IO, Union

import defusedxml.ElementTree as ET

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


def parse_nmap_xml(source: Union[str, Path, IO[bytes]], filename: str = "") -> ScanResult:
    """
    Parse an Nmap XML report file.

    Args:
        source: File path string, Path object, or file-like object.
        filename: Original filename for metadata (used when source is a stream).

    Returns:
        ScanResult containing parsed hosts, metadata, and warnings.

    Raises:
        ValueError: If the file is too large, not valid XML, or not an Nmap report.
    """
    result = ScanResult()
    result.metadata.source_format = "nmap_xml"
    result.metadata.source_file = filename

    try:
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.exists():
                raise ValueError(f"File not found: {path}")
            if path.stat().st_size > MAX_FILE_SIZE:
                raise ValueError(f"File too large (max {MAX_FILE_SIZE // (1024*1024)} MB)")
            result.metadata.source_file = path.name
            tree = ET.parse(str(path))
            root = tree.getroot()
        else:
            # File-like object (e.g., from upload)
            content = source.read()
            if len(content) > MAX_FILE_SIZE:
                raise ValueError(f"File too large (max {MAX_FILE_SIZE // (1024*1024)} MB)")
            root = ET.fromstring(content)

    except ET.ParseError as e:
        raise ValueError(f"Invalid XML: {e}") from e

    # Validate it's an Nmap report
    if root.tag != "nmaprun":
        raise ValueError(
            f"Not an Nmap XML report (root element is '{root.tag}', expected 'nmaprun')"
        )

    # Parse metadata
    _parse_metadata(root, result.metadata)

    # Parse hosts
    for host_elem in root.findall("host"):
        host, warnings = _parse_host(host_elem)
        result.hosts.append(host)
        result.warnings.extend(warnings)

    # Check for duplicate IPs
    _check_duplicates(result)

    logger.info(
        "Parsed Nmap XML: %d hosts, %d warnings",
        len(result.hosts),
        len(result.warnings),
    )
    return result


def _parse_metadata(root: ET.Element, meta: ScanMetadata) -> None:
    """Extract scan metadata from the nmaprun root element."""
    meta.scanner = root.get("scanner", "nmap")
    meta.scanner_version = root.get("version", "")
    meta.scan_type = root.get("type", "")
    meta.command_line = root.get("args", "")
    meta.start_time = root.get("startstr", root.get("start", ""))

    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            meta.end_time = finished.get("timestr", finished.get("time", ""))
            meta.elapsed_seconds = float(finished.get("elapsed", "0"))
            meta.summary = finished.get("summary", "")


def _parse_host(host_elem) -> tuple[HostInfo, list[ParseWarning]]:
    """Parse a single <host> element."""
    warnings: list[ParseWarning] = []
    host = HostInfo()

    # Status
    status = host_elem.find("status")
    if status is not None:
        host.status = status.get("state", "unknown")
        host.status_reason = status.get("reason", "")
    else:
        warnings.append(ParseWarning(
            category="missing_field",
            message="Host missing status element",
        ))

    # Addresses
    for addr in host_elem.findall("address"):
        addr_type = addr.get("addrtype", "")
        addr_val = addr.get("addr", "")
        if addr_type == "ipv4" or addr_type == "ipv6":
            host.ip_address = addr_val
        elif addr_type == "mac":
            host.mac_address = addr_val
            host.vendor = addr.get("vendor", "")

    if not host.ip_address:
        warnings.append(ParseWarning(
            category="missing_field",
            message="Host missing IP address",
        ))

    # Hostnames
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is not None:
        for hn in hostnames_elem.findall("hostname"):
            name = hn.get("name", "")
            if name:
                host.hostnames.append(name)

    # Ports
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            port, port_warnings = _parse_port(port_elem, host.ip_address)
            if port is not None:
                host.ports.append(port)
            warnings.extend(port_warnings)

    # OS detection
    os_elem = host_elem.find("os")
    if os_elem is not None:
        for osmatch in os_elem.findall("osmatch"):
            name = osmatch.get("name", "")
            if name:
                host.os_matches.append(name)

    return host, warnings


def _parse_port(port_elem, host_ip: str) -> tuple[PortInfo | None, list[ParseWarning]]:
    """Parse a single <port> element."""
    warnings: list[ParseWarning] = []

    port_id_str = port_elem.get("portid", "")
    protocol = port_elem.get("protocol", "tcp")

    if not port_id_str:
        warnings.append(ParseWarning(
            category="missing_field",
            message="Port element missing portid",
            host_ip=host_ip,
        ))
        return None, warnings

    try:
        port_id = int(port_id_str)
    except ValueError:
        warnings.append(ParseWarning(
            category="malformed",
            message=f"Invalid port number: {port_id_str}",
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

    # State
    state_elem = port_elem.find("state")
    state = PortState.UNKNOWN
    reason = ""
    if state_elem is not None:
        state = PortState.from_str(state_elem.get("state", "unknown"))
        reason = state_elem.get("reason", "")
    else:
        warnings.append(ParseWarning(
            category="missing_field",
            message=f"Port {port_id} missing state element",
            host_ip=host_ip,
        ))

    # Service
    service = ServiceInfo()
    svc_elem = port_elem.find("service")
    if svc_elem is not None:
        service.name = svc_elem.get("name", "unknown")
        service.product = svc_elem.get("product", "")
        service.version = svc_elem.get("version", "")
        service.extra_info = svc_elem.get("extrainfo", "")
        service.os_type = svc_elem.get("ostype", "")
        service.method = svc_elem.get("method", "")
        conf_str = svc_elem.get("conf", "0")
        try:
            service.confidence = int(conf_str)
        except ValueError:
            service.confidence = 0

    port = PortInfo(
        port_id=port_id,
        protocol=protocol,
        state=state,
        reason=reason,
        service=service,
    )
    return port, warnings


def _check_duplicates(result: ScanResult) -> None:
    """Check for duplicate hosts within the parsed result."""
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
