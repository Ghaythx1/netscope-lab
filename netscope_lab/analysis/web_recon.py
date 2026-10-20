"""
NetScope Lab v2.0 — Web Security Reconnaissance & HTTP Headers Analyzer.

Analyzes HTTP/HTTPS endpoints for missing security headers, software leakage,
SSL/TLS certificate metadata, and web application risks.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "HTTP Strict Transport Security (HSTS)",
        "description": "Protects against man-in-the-middle attacks by forcing HTTPS.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "severity": "medium",
    },
    "Content-Security-Policy": {
        "name": "Content Security Policy (CSP)",
        "description": "Mitigates Cross-Site Scripting (XSS) and data injection attacks.",
        "recommended": "default-src 'self'",
        "severity": "medium",
    },
    "X-Frame-Options": {
        "name": "Clickjacking Defense (X-Frame-Options)",
        "description": "Prevents page from being rendered inside an iframe.",
        "recommended": "DENY or SAMEORIGIN",
        "severity": "low",
    },
    "X-Content-Type-Options": {
        "name": "MIME Sniffing Protection",
        "description": "Instructs browser to strictly follow declared MIME type.",
        "recommended": "nosniff",
        "severity": "low",
    },
    "Referrer-Policy": {
        "name": "Referrer Leakage Control",
        "description": "Limits referrer information sent with outbound links.",
        "recommended": "strict-origin-when-cross-origin",
        "severity": "info",
    },
    "Permissions-Policy": {
        "name": "Feature & Permissions Policy",
        "description": "Restricts browser features like camera, microphone, and geolocation.",
        "recommended": "geolocation=(), microphone=()",
        "severity": "info",
    },
}


@dataclass
class WebReconResult:
    """Findings from HTTP and TLS analysis."""
    url: str
    host: str
    port: int
    status_code: int = 0
    server_banner: str = ""
    x_powered_by: str = ""
    page_title: str = ""
    present_headers: dict[str, str] = field(default_factory=dict)
    missing_headers: list[dict[str, Any]] = field(default_factory=list)
    ssl_info: dict[str, Any] = field(default_factory=dict)
    error_message: str = ""
    is_https: bool = False


class WebSecurityRecon:
    """Probes web endpoints to evaluate security headers and TLS status."""

    @classmethod
    def analyze_endpoint(cls, host: str, port: int, timeout: float = 3.0) -> WebReconResult:
        """Analyze an HTTP or HTTPS endpoint."""
        is_https = port in (443, 8443) or "443" in str(port)
        scheme = "https" if is_https else "http"
        url = f"{scheme}://{host}:{port}/"

        result = WebReconResult(url=url, host=host, port=port, is_https=is_https)

        # Create permissive SSL context to inspect self-signed certs without failing
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NetScope-Lab-Recon/2.0"},
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx if is_https else None) as resp:
                result.status_code = resp.status
                headers = dict(resp.headers)
                body = resp.read(8192).decode("latin-1", errors="ignore")

                # Extract page title
                title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result.page_title = title_match.group(1).strip()[:120]

        except urllib.error.HTTPError as e:
            result.status_code = e.code
            headers = dict(e.headers)
        except Exception as e:
            result.error_message = str(e)
            return result

        # Check server disclosures
        for k, v in headers.items():
            k_lower = k.lower()
            if k_lower == "server":
                result.server_banner = v
            elif k_lower == "x-powered-by":
                result.x_powered_by = v

        # Check security headers
        header_map_lower = {k.lower(): (k, v) for k, v in headers.items()}
        for sec_header, meta in SECURITY_HEADERS.items():
            lower_name = sec_header.lower()
            if lower_name in header_map_lower:
                orig_k, val = header_map_lower[lower_name]
                result.present_headers[orig_k] = val
            else:
                result.missing_headers.append({
                    "header": sec_header,
                    "name": meta["name"],
                    "description": meta["description"],
                    "recommended": meta["recommended"],
                    "severity": meta["severity"],
                })

        # Fetch SSL details if HTTPS
        if is_https:
            try:
                cert_ctx = ssl.create_default_context()
                cert_ctx.check_hostname = False
                cert_ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with cert_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        cipher = ssock.cipher()
                        version = ssock.version()
                        result.ssl_info = {
                            "tls_version": version,
                            "cipher_suite": cipher[0] if cipher else "Unknown",
                            "bits": cipher[2] if cipher and len(cipher) > 2 else "Unknown",
                        }
            except Exception as e:
                result.ssl_info = {"error": f"TLS Inspection note: {str(e)}"}

        return result
