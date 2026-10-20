"""
NetScope Lab -- Live Nmap scanner module.

Runs nmap as a subprocess, captures XML output, and returns a ScanResult.
Supports cancellation via a threading.Event and progress callbacks.

IMPORTANT: This module only wraps nmap. You must have explicit authorization
to scan any target. Unauthorized scanning is illegal.
"""

from __future__ import annotations

import io
import ipaddress
import logging
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable

from netscope_lab.parsers.nmap_xml import parse_nmap_xml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scan type registry
# ---------------------------------------------------------------------------

SCAN_TYPES: dict[str, dict[str, Any]] = {
    "ping": {
        "name": "Ping Sweep",
        "icon": "radar",
        "args": ["-sn"],
        "description": "Discover live hosts without scanning ports. Fast and non-intrusive.",
        "requires_root": False,
        "estimated_time": "< 30 seconds",
        "intensity": "low",
    },
    "quick": {
        "name": "Quick Scan",
        "icon": "bolt",
        "args": [],
        "top_ports": 100,
        "description": "Fast scan of the 100 most common TCP ports.",
        "requires_root": False,
        "estimated_time": "30 sec - 2 min",
        "intensity": "low",
    },
    "syn": {
        "name": "SYN Stealth Scan",
        "icon": "shield",
        "args": ["-sS"],
        "description": "Half-open TCP SYN scan. Faster and less noisy than full connect. Requires root.",
        "requires_root": True,
        "estimated_time": "1 - 5 minutes",
        "intensity": "medium",
    },
    "service": {
        "name": "Service Detection",
        "icon": "search",
        "args": ["-sV"],
        "description": "Identify service names and version numbers running on open ports.",
        "requires_root": False,
        "estimated_time": "2 - 5 minutes",
        "intensity": "medium",
    },
    "full": {
        "name": "Full Scan",
        "icon": "microscope",
        "args": ["-sS", "-sV", "-O"],
        "all_ports": True,
        "description": "All TCP ports with service detection and OS fingerprinting. Requires root.",
        "requires_root": True,
        "estimated_time": "10 minutes or more",
        "intensity": "high",
    },
    "aggressive": {
        "name": "Aggressive Scan",
        "icon": "fire",
        "args": ["-A"],
        "description": "All-in-one: OS, versions, NSE scripts, traceroute. Requires root.",
        "requires_root": True,
        "estimated_time": "5 - 20 minutes",
        "intensity": "high",
    },
    "vuln": {
        "name": "Vulnerability Scripts",
        "icon": "bug",
        "args": ["-sV", "--script=vuln"],
        "description": "Run NSE vulnerability detection scripts against open ports.",
        "requires_root": False,
        "estimated_time": "10 - 30 minutes",
        "intensity": "high",
    },
    "udp": {
        "name": "UDP Scan",
        "icon": "wifi",
        "args": ["-sU"],
        "top_ports": 100,
        "description": "Scan the top 100 UDP ports. Requires root and is slower than TCP.",
        "requires_root": True,
        "estimated_time": "15 - 45 minutes",
        "intensity": "high",
    },
    "tcp_connect": {
        "name": "TCP Connect",
        "icon": "🔌",
        "args": ["-sT"],
        "top_ports": 1000,
        "description": "Full TCP connection scan; works without raw-packet root privileges.",
        "requires_root": False,
        "estimated_time": "1 - 10 minutes",
        "intensity": "medium",
    },
    "all_tcp": {
        "name": "All TCP Ports",
        "icon": "🧭",
        "args": ["-sT"],
        "all_ports": True,
        "description": "Checks every TCP port using connect scans; no root privileges required.",
        "requires_root": False,
        "estimated_time": "Several minutes or more",
        "intensity": "high",
    },
    "tcp_udp": {
        "name": "TCP + UDP",
        "icon": "🌐",
        "args": ["-sS", "-sU"],
        "top_ports": 100,
        "description": "Checks common TCP and UDP ports in one authorized assessment. Requires root.",
        "requires_root": True,
        "estimated_time": "Several minutes or more",
        "intensity": "high",
    },
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class NmapNotFoundError(Exception):
    """Raised when nmap is not installed or not in PATH."""


class NmapScanError(Exception):
    """Raised when nmap exits with an error."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_nmap() -> str:
    """Locate the nmap binary. Raises NmapNotFoundError if missing."""
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise NmapNotFoundError(
            "nmap not found in PATH. Install with: sudo apt install nmap"
        )
    return nmap_path


def validate_target(target: str) -> str:
    """
    Validate and sanitize a scan target string.

    Args:
        target: IP address, hostname, range (192.168.1.1-50), or CIDR.

    Returns:
        Stripped, validated target string.

    Raises:
        ValueError: If target is empty or contains dangerous characters.
    """
    target = target.strip()
    if not target:
        raise ValueError("Scan target cannot be empty.")
    forbidden = set(';&|`$(){}\\<>\'"')
    bad = [c for c in target if c in forbidden]
    if bad:
        raise ValueError(
            f"Target contains invalid characters: {', '.join(repr(c) for c in bad)}"
        )
    if len(target) > 256:
        raise ValueError("Target string is too long (max 256 characters).")
    # Never let a target be interpreted as an Nmap command-line option.
    if target.startswith("-") or any(ch.isspace() for ch in target):
        raise ValueError("Enter one IP address, CIDR, hostname, or Nmap address range.")

    # Accept IPs and CIDRs (including IPv6).
    try:
        ipaddress.ip_interface(target)
        return target
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    # Nmap IPv4 range form, e.g. 192.168.1.10-50.
    range_match = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3})", target)
    if range_match:
        try:
            ipaddress.IPv4Address(range_match.group(1))
            if int(range_match.group(2)) <= 255:
                return target
        except ValueError:
            pass

    # Hostnames are accepted, but command switches and malformed names are not.
    hostname = target[:-1] if target.endswith(".") else target
    labels = hostname.split(".")
    if all(
        label and len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        return target
    raise ValueError("Enter a valid IP address, CIDR, hostname, or IPv4 range.")


def validate_port_range(port_range: str) -> str:
    """
    Validate optional port range string.

    Args:
        port_range: e.g. '1-1024', '80,443,8080', '' for default.

    Returns:
        Validated port range string (may be empty).

    Raises:
        ValueError: If format is invalid.
    """
    port_range = port_range.strip()
    if not port_range:
        return ""
    allowed = set("0123456789,-")
    bad = [c for c in port_range if c not in allowed]
    if bad:
        raise ValueError(
            f"Port range contains invalid characters: {', '.join(repr(c) for c in bad)}"
        )
    if len(port_range) > 128:
        raise ValueError("Port range string too long.")
    for item in port_range.split(","):
        if not item:
            raise ValueError("Port range contains an empty entry.")
        if not re.fullmatch(r"\d+(?:-\d+)?", item):
            raise ValueError("Use ports such as 80,443 or ranges such as 1-1024.")
        values = [int(value) for value in item.split("-")]
        if any(value < 1 or value > 65535 for value in values):
            raise ValueError("Ports must be between 1 and 65535.")
        if len(values) == 2 and values[0] > values[1]:
            raise ValueError("Port range start must not exceed its end.")
    return port_range


def validate_targets(targets: str) -> list[str]:
    """Accept a comma or newline separated list of scan targets."""
    if len(targets) > 4096:
        raise ValueError("Target list is too long (maximum 4096 characters).")
    parsed: list[str] = []
    for line in targets.splitlines():
        for item in line.split(","):
            item = item.strip()
            if item:
                parsed.append(validate_target(item))
    if not parsed:
        raise ValueError("Enter at least one scan target.")
    if len(parsed) > 256:
        raise ValueError("A scan can include up to 256 individual targets.")
    return list(dict.fromkeys(parsed))


# ---------------------------------------------------------------------------
# NmapRunner
# ---------------------------------------------------------------------------

class NmapRunner:
    """
    Manages a live nmap scan subprocess.

    Designed to be run in a background thread. Supports cancellation.

    Usage::

        runner = NmapRunner()
        thread = threading.Thread(
            target=runner.run,
            args=("192.168.1.0/24", "quick"),
            daemon=True,
        )
        thread.start()

        # Poll runner.running, runner.done, runner.message
        # runner.cancel() to abort
        # runner.result holds ScanResult when done
    """

    def __init__(self, on_progress: Callable[[str], None] | None = None) -> None:
        self._proc: subprocess.Popen | None = None
        self._cancel_event = threading.Event()
        self._on_progress = on_progress

        # Public state (read from UI thread)
        self.running: bool = False
        self.done: bool = False
        self.cancelled: bool = False
        self.message: str = "Idle"
        self.error: str | None = None
        self.result = None  # ScanResult when successful
        self.target: str = ""
        self.scan_type: str = ""
        self.progress_percent: float = 0.0
        self.eta_seconds: int | None = None
        self.phase: str = "Preparing scan"
        self.progress_source: str = "nmap"
        self.started_at: float | None = None

    def _progress(self, msg: str) -> None:
        self.message = msg
        logger.info("[scan] %s", msg)
        if self._on_progress:
            self._on_progress(msg)

    def cancel(self) -> None:
        """Signal cancellation and kill the subprocess if running."""
        self._cancel_event.set()
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.kill()
                logger.info("nmap subprocess killed.")
            except OSError as e:
                logger.warning("Failed to kill nmap subprocess: %s", e)
        self.cancelled = True
        self.running = False
        self.done = True
        self.message = "Scan cancelled by user."

    def run(
        self,
        target: str,
        scan_type: str = "quick",
        port_range: str = "",
        timeout: int = 1800,
        timing: str = "3",
        port_mode: str = "profile",
        exclude: str = "",
        skip_discovery: bool = False,
        disable_dns: bool = False,
        version_intensity: str = "default",
        os_detection: bool = False,
        traceroute: bool = False,
        safe_scripts: bool = False,
    ) -> None:
        """
        Execute nmap and populate self.result (blocking; run in a thread).

        Args:
            target: IP, hostname, CIDR, or range.
            scan_type: Key from SCAN_TYPES.
            port_range: Optional port specification.
            timeout: Seconds before giving up.
        """
        self.running = True
        self.done = False
        self.cancelled = False
        self.error = None
        self.result = None
        self.target = target
        self.scan_type = scan_type
        self.progress_percent = 0.0
        self.eta_seconds = None
        self.phase = "Preparing scan"
        self.progress_source = "nmap"
        self.started_at = None
        self._cancel_event.clear()

        xml_path: str | None = None
        try:
            # --- Validation ---
            nmap_bin = find_nmap()
            targets = validate_targets(target)
            port_range = validate_port_range(port_range)
            exclude = validate_target(exclude) if exclude else ""

            if timing not in {"2", "3", "4"}:
                raise ValueError("Choose a valid timing profile (T2, T3, or T4).")
            if port_mode not in {"profile", "top100", "top1000", "all", "custom"}:
                raise ValueError("Choose a valid port selection mode.")
            if version_intensity not in {"default", "light", "intensive"}:
                raise ValueError("Choose a valid service detection intensity.")
            if port_mode == "custom" and not port_range and scan_type != "ping":
                raise ValueError("Enter a port range for custom port selection.")

            if scan_type not in SCAN_TYPES:
                raise ValueError(f"Unknown scan type: {scan_type!r}")

            cfg = SCAN_TYPES[scan_type]

            # --- Build command ---
            cmd: list[str] = [nmap_bin, f"-T{timing}"] + list(cfg["args"])
            cmd += ["--stats-every", "1s"]
            if skip_discovery and scan_type != "ping":
                cmd.append("-Pn")
            if disable_dns:
                cmd.append("-n")
            cmd.append("--reason")
            if exclude:
                cmd += ["--exclude", exclude]
            if scan_type != "ping" and version_intensity != "default":
                if "-sV" not in cmd:
                    cmd.append("-sV")
                cmd.append("--version-light" if version_intensity == "light" else "--version-all")
            if scan_type != "ping" and os_detection and "-O" not in cmd and "-A" not in cmd:
                cmd.append("-O")
            if scan_type != "ping" and traceroute and "-A" not in cmd:
                cmd.append("--traceroute")
            if scan_type != "ping" and safe_scripts:
                cmd.append("--script=safe")
            if scan_type != "ping" and port_mode == "custom" and port_range:
                cmd += ["-p", port_range]
            elif scan_type != "ping" and port_mode == "all":
                cmd.append("-p-")
            elif scan_type != "ping" and port_mode in {"top100", "top1000"}:
                cmd += ["--top-ports", "100" if port_mode == "top100" else "1000"]
            elif scan_type != "ping" and port_mode == "profile":
                if port_range:
                    cmd += ["-p", port_range]
                elif cfg.get("all_ports"):
                    cmd.append("-p-")
                elif cfg.get("top_ports"):
                    cmd += ["--top-ports", str(cfg["top_ports"])]
            # Write XML to a temporary file so stderr can be read live for progress.
            with tempfile.NamedTemporaryFile(prefix="netscope_", suffix=".xml", delete=False) as xml_file:
                xml_path = xml_file.name
            os.unlink(xml_path)  # Let Nmap create its output at this unique path.
            cmd += ["-oX", xml_path, *targets]

            self._progress(
                f"Starting {cfg['name']} on {target}..."
            )
            logger.info("nmap command: %s", " ".join(cmd))

            # --- Run ---
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                          text=True, bufsize=1)
            stderr_lines: queue.Queue[str | None] = queue.Queue()
            stderr_captured: list[str] = []

            def _read_stderr() -> None:
                assert self._proc and self._proc.stderr
                for line in self._proc.stderr:
                    stderr_lines.put(line)
                stderr_lines.put(None)

            threading.Thread(target=_read_stderr, daemon=True).start()
            started_at = time.monotonic()
            self.started_at = started_at
            deadline = started_at + timeout
            stderr_done = False
            self.phase = "Starting Nmap"
            estimate_seconds = {
                "ping": 30, "quick": 120, "syn": 300, "service": 420,
                "full": 1500, "aggressive": 900, "vuln": 1800,
                "udp": 2400, "tcp_connect": 600, "all_tcp": 1200,
                "tcp_udp": 2100,
            }.get(scan_type, 300)
            if port_mode == "all" or (port_mode == "profile" and cfg.get("all_ports")):
                estimate_seconds = max(estimate_seconds, 1200)
            estimate_seconds = min(timeout, max(30, estimate_seconds * min(len(targets), 20)))
            while self._proc.poll() is None or not stderr_done:
                if self._cancel_event.is_set():
                    break
                if time.monotonic() >= deadline:
                    self._proc.kill()
                    raise subprocess.TimeoutExpired(cmd, timeout)
                elapsed = time.monotonic() - started_at
                if self.progress_source == "estimate":
                    self.progress_percent = min(94.0, elapsed / estimate_seconds * 90.0)
                    self.eta_seconds = max(1, round(estimate_seconds - elapsed))
                    self.phase = "Estimated progress"
                    self.message = f"Estimated progress: {self.progress_percent:.0f}%"
                try:
                    line = stderr_lines.get(timeout=0.25)
                except queue.Empty:
                    if self.progress_source == "nmap" and time.monotonic() - started_at >= 2:
                        self.progress_source = "estimate"
                    continue
                if line is None:
                    stderr_done = True
                    continue
                stderr_captured.append(line)
                if self.progress_source == "nmap" and time.monotonic() - started_at >= 2:
                    self.progress_source = "estimate"
                phase_match = re.search(r"([A-Za-z][A-Za-z /-]+?)\s+Timing:", line)
                if phase_match:
                    self.phase = phase_match.group(1).strip()
                percent_match = re.search(r"(?:About\s+)?(\d+(?:\.\d+)?)%\s+done", line, re.IGNORECASE)
                if percent_match:
                    self.progress_source = "nmap"
                    self.progress_percent = min(99.0, float(percent_match.group(1)))
                    eta_match = re.search(r"\((?:(\d+):)?(\d+):(\d+)\s+remaining\)", line, re.IGNORECASE)
                    if eta_match:
                        hours = int(eta_match.group(1) or 0)
                        minutes, seconds = int(eta_match.group(2)), int(eta_match.group(3))
                        self.eta_seconds = hours * 3600 + minutes * 60 + seconds
                    else:
                        done = self.progress_percent
                        self.eta_seconds = round(elapsed * (100 - done) / done) if done else None
                    self.message = f"{self.phase}: {self.progress_percent:.0f}%"
                elif "Timing:" in line:
                    self.message = line.strip()

            if self._cancel_event.is_set():
                if self._proc:
                    self._proc.wait()
                return
            assert self._proc.stderr
            stderr_text = "".join(stderr_captured).strip()
            stderr_data = stderr_text.encode("utf-8", errors="replace")
            with open(xml_path, "rb") as xml_file:
                xml_data = xml_file.read()

            if self._cancel_event.is_set():
                return

            # --- Check result ---
            if self._proc.returncode != 0:
                stderr_text = stderr_data.decode("utf-8", errors="replace").strip()
                raise NmapScanError(
                    f"nmap exited with code {self._proc.returncode}. "
                    f"Details: {stderr_text}"
                )

            if not xml_data or not xml_data.strip():
                raise NmapScanError(
                    "nmap produced no output. Check target and permissions."
                )

            # --- Parse ---
            self._progress("Parsing scan results...")
            self.result = parse_nmap_xml(
                io.BytesIO(xml_data),
                filename=f"live_{scan_type}_{target}",
            )

            host_count = len(self.result.hosts)
            up_count = sum(1 for h in self.result.hosts if h.status == "up")
            self._progress(
                f"Done! {host_count} host(s) found, {up_count} up."
            )
            self.progress_percent = 100.0
            self.eta_seconds = 0
            self.phase = "Complete"
            self.progress_source = "nmap"

        except subprocess.TimeoutExpired:
            if self._proc:
                self._proc.kill()
                self._proc.wait()
            self.error = f"Scan timed out after {timeout} seconds."
            self._progress(f"Timed out after {timeout}s.")
        except (NmapNotFoundError, NmapScanError, ValueError) as e:
            self.error = str(e)
            self._progress(f"Error: {e}")
        except Exception as e:
            self.error = f"Unexpected error: {e}"
            self._progress("An unexpected error occurred.")
            logger.exception("Unexpected scan error")
        finally:
            if xml_path and os.path.exists(xml_path):
                os.unlink(xml_path)
            self.running = False
            self.done = True
