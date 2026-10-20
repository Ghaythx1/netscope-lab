"""
NetScope Lab — Statistics computation.

Aggregates scan results into summary statistics for the dashboard.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from netscope_lab.models.scan_data import ScanResult


def compute_statistics(scan_result: ScanResult) -> dict[str, Any]:
    """
    Compute summary statistics from a scan result.

    Args:
        scan_result: The parsed scan data.

    Returns:
        Dictionary of statistics for dashboard display.
    """
    total_hosts = len(scan_result.hosts)
    hosts_up = sum(1 for h in scan_result.hosts if h.status == "up")
    hosts_down = sum(1 for h in scan_result.hosts if h.status == "down")

    total_open = 0
    total_closed = 0
    total_filtered = 0
    port_counter: Counter[int] = Counter()
    service_counter: Counter[str] = Counter()
    protocol_counter: Counter[str] = Counter()
    state_counter: Counter[str] = Counter()

    for host in scan_result.hosts:
        for port in host.ports:
            state_counter[port.state.value] += 1
            protocol_counter[port.protocol] += 1

            if port.is_open:
                total_open += 1
                port_counter[port.port_id] += 1
                if port.service.name != "unknown":
                    service_counter[port.service.name] += 1
            elif port.is_closed:
                total_closed += 1
            elif port.is_filtered:
                total_filtered += 1

    # Top N for charts
    top_ports = port_counter.most_common(15)
    top_services = service_counter.most_common(15)

    return {
        "total_hosts": total_hosts,
        "hosts_up": hosts_up,
        "hosts_down": hosts_down,
        "total_open_ports": total_open,
        "total_closed_ports": total_closed,
        "total_filtered_ports": total_filtered,
        "unique_services": len(service_counter),
        "top_ports": [{"port": p, "count": c} for p, c in top_ports],
        "top_services": [{"service": s, "count": c} for s, c in top_services],
        "protocol_distribution": dict(protocol_counter),
        "state_distribution": dict(state_counter),
        "total_warnings": len(scan_result.warnings),
    }
