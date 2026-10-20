"""Small SQLite-backed store for persistent scan history."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

from netscope_lab.models.scan_data import (
    HostInfo, ParseWarning, PortInfo, PortState, ScanMetadata, ScanResult, ServiceInfo,
)


def _connect(database: str) -> sqlite3.Connection:
    connection = sqlite3.connect(database, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize(database: str) -> None:
    Path(database).parent.mkdir(parents=True, exist_ok=True)
    with _connect(database) as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '',
            scan_type TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            host_count INTEGER NOT NULL DEFAULT 0,
            open_ports INTEGER NOT NULL DEFAULT 0,
            result_json TEXT NOT NULL
        )""")
        connection.execute("CREATE INDEX IF NOT EXISTS scans_created_at ON scans(created_at DESC)")


def _serialize(scan: ScanResult) -> str:
    data: dict[str, Any] = {
        "scan_id": scan.scan_id,
        "metadata": asdict(scan.metadata),
        "import_timestamp": scan.import_timestamp,
        "hosts": [],
        "warnings": [asdict(warning) for warning in scan.warnings],
    }
    for host in scan.hosts:
        host_data = asdict(host)
        host_data["ports"] = [
            {
                "port_id": port.port_id,
                "protocol": port.protocol,
                "state": port.state.value,
                "reason": port.reason,
                "service": asdict(port.service),
            }
            for port in host.ports
        ]
        data["hosts"].append(host_data)
    return json.dumps(data, ensure_ascii=False)


def _deserialize(payload: str) -> ScanResult:
    data = json.loads(payload)
    scan = ScanResult(
        scan_id=data["scan_id"],
        metadata=ScanMetadata(**data.get("metadata", {})),
        import_timestamp=data.get("import_timestamp", ""),
    )
    for host_data in data.get("hosts", []):
        ports = []
        for port_data in host_data.pop("ports", []):
            ports.append(PortInfo(
                port_id=int(port_data["port_id"]),
                protocol=port_data.get("protocol", "tcp"),
                state=PortState.from_str(port_data.get("state", "unknown")),
                reason=port_data.get("reason", ""),
                service=ServiceInfo(**port_data.get("service", {})),
            ))
        scan.hosts.append(HostInfo(ports=ports, **host_data))
    scan.warnings = [ParseWarning(**warning) for warning in data.get("warnings", [])]
    return scan


def save_scan(database: str, scan: ScanResult, target: str = "", scan_type: str = "") -> None:
    with _connect(database) as connection:
        connection.execute("""INSERT OR REPLACE INTO scans
            (scan_id, created_at, target, scan_type, source, host_count, open_ports, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (
            scan.scan_id, scan.import_timestamp, target, scan_type or scan.metadata.scan_type,
            scan.metadata.source_file or scan.metadata.source_format,
            len(scan.hosts), scan.total_open_ports, _serialize(scan),
        ))


def list_scans(database: str, limit: int = 100) -> list[dict[str, Any]]:
    with _connect(database) as connection:
        rows = connection.execute("""SELECT scan_id, created_at, target, scan_type, source,
            host_count, open_ports FROM scans ORDER BY created_at DESC LIMIT ?""", (limit,)).fetchall()
    return [dict(row) for row in rows]


def load_scan(database: str, scan_id: str) -> ScanResult | None:
    with _connect(database) as connection:
        row = connection.execute("SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    return _deserialize(row["result_json"]) if row else None


def load_latest(database: str) -> ScanResult | None:
    with _connect(database) as connection:
        row = connection.execute("SELECT result_json FROM scans ORDER BY created_at DESC LIMIT 1").fetchone()
    return _deserialize(row["result_json"]) if row else None
