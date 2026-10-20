"""
NetScope Lab v2.0 — Fast Native Python Socket Scanner & Banner Grabber.

Provides high-speed, multi-threaded TCP port scanning and service banner
identification without requiring Nmap or administrative privileges.
Integrates directly with NetScope Lab's ScanResult, HostInfo, and PortInfo models.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from netscope_lab.models.scan_data import (
    HostInfo,
    PortInfo,
    PortState,
    ScanMetadata,
    ScanResult,
    ServiceInfo,
)

logger = logging.getLogger(__name__)

# Common well-known TCP ports with default service mapping
COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-ssl",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    5985: "wsman",
    6379: "redis",
    6443: "kubernetes",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "cslistener",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

TOP_20_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
]


@dataclass
class FastScanConfig:
    """Configuration for fast socket scan."""
    targets: list[str]
    ports: list[int] = field(default_factory=lambda: list(TOP_20_PORTS))
    timeout: float = 1.0
    max_workers: int = 50
    grab_banners: bool = True


class FastSocketScanner:
    """
    High-speed native Python port scanner.
    Performs TCP connect probes, banner grabbing, and service detection.
    """

    def __init__(self, config: FastScanConfig | None = None) -> None:
        self.config = config or FastScanConfig(targets=["127.0.0.1"])
        self._is_cancelled = False

    def cancel(self) -> None:
        """Signal cancellation."""
        self._is_cancelled = True

    @staticmethod
    def parse_ports(port_spec: str) -> list[int]:
        """
        Parse port string like '80,443,8000-8010' or preset names.
        """
        spec = port_spec.strip().lower()
        if not spec or spec == "top20":
            return list(TOP_20_PORTS)
        if spec == "common":
            return sorted(COMMON_PORTS.keys())
        if spec == "all":
            return list(range(1, 1025))

        ports: set[int] = set()
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start_s, end_s = part.split("-", 1)
                    start, end = int(start_s), int(end_s)
                    if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                        ports.update(range(start, min(end + 1, 65536)))
                except ValueError:
                    continue
            else:
                try:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.add(p)
                except ValueError:
                    continue
        return sorted(ports) if ports else list(TOP_20_PORTS)

    @staticmethod
    def resolve_targets(target_spec: str) -> list[str]:
        """
        Resolve target specification into unique list of IP addresses or hostnames.
        Supports comma-separated targets, CIDR notation (e.g. 192.168.1.0/29), or hostnames.
        """
        targets: list[str] = []
        raw_items = [t.strip() for t in target_spec.replace("\n", ",").split(",") if t.strip()]

        for item in raw_items:
            # Check for CIDR
            if "/" in item:
                try:
                    net = ipaddress.ip_network(item, strict=False)
                    # Limit expansion to /24 to prevent memory exhaustion
                    if net.num_addresses > 256:
                        logger.warning("CIDR %s is too large for fast scan, capping at /24", item)
                        for host in list(net.hosts())[:256]:
                            targets.append(str(host))
                    else:
                        for host in net.hosts():
                            targets.append(str(host))
                    continue
                except ValueError:
                    pass

            # Standard IP or hostname
            targets.append(item)

        return list(dict.fromkeys(targets))[:256]  # Max 256 targets

    def probe_port(self, target: str, port: int) -> PortInfo | None:
        """
        Probe a single TCP port on target.
        Returns PortInfo if open, None otherwise.
        """
        if self._is_cancelled:
            return None

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout)
        try:
            res = sock.connect_ex((target, port))
            if res == 0:
                service_info = self._detect_service(sock, target, port)
                return PortInfo(
                    port_id=port,
                    protocol="tcp",
                    state=PortState.OPEN,
                    reason="syn-ack",
                    service=service_info,
                )
            return None
        except (socket.timeout, socket.error, OSError):
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _detect_service(self, sock: socket.socket, target: str, port: int) -> ServiceInfo:
        """Attempt banner grab or protocol identification."""
        default_name = COMMON_PORTS.get(port, "unknown")
        product = ""
        version = ""
        extra = ""

        if not self.config.grab_banners:
            return ServiceInfo(name=default_name)

        # Try banner grab
        try:
            sock.settimeout(0.8)
            banner = ""

            # For HTTP / HTTPS
            if port in (80, 443, 8000, 8080, 8443, 8888):
                if port in (443, 8443):
                    # TLS handshake
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        with ctx.wrap_socket(socket.socket(), server_hostname=target) as ssock:
                            ssock.settimeout(1.0)
                            ssock.connect((target, port))
                            ssock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
                            data = ssock.recv(1024).decode("latin-1", errors="ignore")
                            for line in data.splitlines():
                                if line.lower().startswith("server:"):
                                    product = line.split(":", 1)[1].strip()
                    except Exception:
                        product = "HTTPS Server"
                else:
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
                    data = sock.recv(1024).decode("latin-1", errors="ignore")
                    for line in data.splitlines():
                        if line.lower().startswith("server:"):
                            product = line.split(":", 1)[1].strip()
            else:
                # Passive read for FTP, SSH, SMTP
                data = sock.recv(512).decode("latin-1", errors="ignore")
                banner = data.strip()

            if banner:
                if "ssh" in banner.lower():
                    default_name = "ssh"
                    product = banner.split("\r")[0].split("\n")[0]
                elif "ftp" in banner.lower():
                    default_name = "ftp"
                    product = banner.split("\r")[0]
                elif "smtp" in banner.lower() or "esmtp" in banner.lower():
                    default_name = "smtp"
                    product = banner.split("\r")[0]
                elif "mysql" in banner.lower():
                    default_name = "mysql"
                    product = "MySQL Server"
                else:
                    extra = banner[:100]

        except Exception:
            pass

        return ServiceInfo(
            name=default_name,
            product=product,
            version=version,
            extra_info=extra,
        )

    def scan_target(self, target: str) -> HostInfo:
        """Scan all configured ports on a single target."""
        hostnames: list[str] = []
        try:
            resolved_name = socket.gethostbyaddr(target)[0]
            if resolved_name and resolved_name != target:
                hostnames.append(resolved_name)
        except Exception:
            pass

        open_ports: list[PortInfo] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.config.max_workers, len(self.config.ports) or 1)) as executor:
            future_to_port = {
                executor.submit(self.probe_port, target, p): p
                for p in self.config.ports
            }
            for future in concurrent.futures.as_completed(future_to_port):
                if self._is_cancelled:
                    break
                try:
                    res = future.result()
                    if res:
                        open_ports.append(res)
                except Exception:
                    pass

        open_ports.sort(key=lambda p: p.port_id)
        status = "up" if open_ports or target in ("127.0.0.1", "localhost") else "down"

        return HostInfo(
            ip_address=target,
            hostnames=hostnames,
            status=status,
            status_reason="syn-ack" if status == "up" else "no-response",
            ports=open_ports,
        )

    def run_scan(
        self,
        progress_cb: Callable[[int, int, str], None] | None = None,
    ) -> ScanResult:
        """
        Execute scan on all targets.
        Returns a complete ScanResult ready for NetScope Lab dashboard.
        """
        start_time = datetime.now()
        hosts: list[HostInfo] = []
        total_targets = len(self.config.targets)

        for idx, target in enumerate(self.config.targets):
            if self._is_cancelled:
                break
            if progress_cb:
                progress_cb(idx + 1, total_targets, f"Scanning host {target}...")

            host_info = self.scan_target(target)
            if host_info.status == "up" or len(host_info.open_ports) > 0:
                hosts.append(host_info)

        end_time = datetime.now()
        target_str = ", ".join(self.config.targets[:5])
        if len(self.config.targets) > 5:
            target_str += f" (+{len(self.config.targets) - 5} more)"

        metadata = ScanMetadata(
            scanner="NetScope FastScanner",
            scanner_version="2.0.0",
            scan_type="native-socket",
            command_line=f"fast-scan --targets {target_str} --ports {len(self.config.ports)} ports",
            start_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
            end_time=end_time.strftime("%Y-%m-%d %H:%M:%S"),
            source_file="live_socket_scan",
        )

        return ScanResult(hosts=hosts, metadata=metadata)
