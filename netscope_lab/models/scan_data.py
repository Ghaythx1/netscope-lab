"""
NetScope Lab — Data models for scan results.

Defines dataclasses representing parsed scan data including hosts, ports,
services, and overall scan metadata.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class PortState(Enum):
    """Possible port states as reported by Nmap."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"
    UNFILTERED = "unfiltered"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, value: str) -> "PortState":
        """Parse a port state string, falling back to UNKNOWN."""
        normalized = value.strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.UNKNOWN


@dataclass
class ServiceInfo:
    """Detected service information for a port."""
    name: str = "unknown"
    product: str = ""
    version: str = ""
    extra_info: str = ""
    os_type: str = ""
    method: str = ""
    confidence: int = 0

    def display_name(self) -> str:
        """Human-readable service string."""
        parts = [self.name]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts)


@dataclass
class PortInfo:
    """Information about a single scanned port."""
    port_id: int
    protocol: str = "tcp"
    state: PortState = PortState.UNKNOWN
    reason: str = ""
    service: ServiceInfo = field(default_factory=ServiceInfo)

    @property
    def is_open(self) -> bool:
        return self.state in (PortState.OPEN, PortState.OPEN_FILTERED)

    @property
    def is_closed(self) -> bool:
        return self.state in (PortState.CLOSED, PortState.CLOSED_FILTERED)

    @property
    def is_filtered(self) -> bool:
        return self.state in (PortState.FILTERED, PortState.OPEN_FILTERED, PortState.CLOSED_FILTERED)


@dataclass
class HostInfo:
    """Parsed host from a scan report."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    ip_address: str = ""
    hostnames: list[str] = field(default_factory=list)
    status: str = "unknown"
    status_reason: str = ""
    ports: list[PortInfo] = field(default_factory=list)
    os_matches: list[str] = field(default_factory=list)
    mac_address: str = ""
    vendor: str = ""

    @property
    def open_ports(self) -> list[PortInfo]:
        return [p for p in self.ports if p.is_open]

    @property
    def closed_ports(self) -> list[PortInfo]:
        return [p for p in self.ports if p.is_closed]

    @property
    def filtered_ports(self) -> list[PortInfo]:
        return [p for p in self.ports if p.is_filtered]

    @property
    def display_name(self) -> str:
        if self.hostnames:
            return f"{self.hostnames[0]} ({self.ip_address})"
        return self.ip_address

    @property
    def services(self) -> list[ServiceInfo]:
        return [p.service for p in self.ports if p.service.name != "unknown"]


@dataclass
class ScanMetadata:
    """Metadata about the scan itself."""
    scanner: str = ""
    scanner_version: str = ""
    scan_type: str = ""
    command_line: str = ""
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    elapsed_seconds: float = 0.0
    summary: str = ""
    source_file: str = ""
    source_format: str = ""


@dataclass
class ParseWarning:
    """A warning generated during parsing."""
    category: str  # e.g., "missing_field", "malformed", "duplicate"
    message: str
    host_ip: str = ""
    details: str = ""


@dataclass
class ScanResult:
    """Complete result of parsing one or more scan reports."""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    metadata: ScanMetadata = field(default_factory=ScanMetadata)
    hosts: list[HostInfo] = field(default_factory=list)
    warnings: list[ParseWarning] = field(default_factory=list)
    import_timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    @property
    def all_services(self) -> list[str]:
        services: list[str] = []
        for h in self.hosts:
            for p in h.ports:
                if p.service.name != "unknown":
                    services.append(p.service.name)
        return services

    def merge(self, other: "ScanResult") -> None:
        """Merge another scan result into this one, tracking duplicates."""
        existing_ips = {h.ip_address for h in self.hosts}
        for host in other.hosts:
            if host.ip_address in existing_ips:
                self.warnings.append(ParseWarning(
                    category="duplicate",
                    message=f"Duplicate host {host.ip_address} found across files",
                    host_ip=host.ip_address
                ))
            else:
                self.hosts.append(host)
                existing_ips.add(host.ip_address)
        self.warnings.extend(other.warnings)
