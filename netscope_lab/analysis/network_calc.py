"""
NetScope Lab v2.0 — Network & CIDR Subnet Calculator.

Calculates subnet ranges, usable hosts, broadcast addresses, wildcard masks,
and categorizes IP scopes (Private, Public, Cloud, RFC1918).
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SubnetDetails:
    """Calculated subnet information."""
    cidr: str
    network_address: str
    broadcast_address: str
    netmask: str
    wildcard_mask: str
    first_usable_ip: str
    last_usable_ip: str
    total_addresses: int
    usable_hosts: int
    ip_version: int
    is_private: bool
    is_global: bool
    is_loopback: bool
    is_multicast: bool
    ip_scope: str
    binary_netmask: str


class NetworkCalculator:
    """Subnet calculation and IP range utilities."""

    @staticmethod
    def calculate(cidr_input: str) -> SubnetDetails | None:
        """
        Calculate full subnet specifications from an IP or CIDR string.
        Examples: '192.168.1.0/24', '10.0.0.1/16', '172.16.0.5'
        """
        try:
            cidr_cleaned = cidr_input.strip()
            # If no mask provided, assume /32 for IPv4, /128 for IPv6
            if "/" not in cidr_cleaned:
                cidr_cleaned += "/32" if ":" not in cidr_cleaned else "/128"

            net = ipaddress.ip_network(cidr_cleaned, strict=False)

            # Usable IP range
            hosts = list(net.hosts()) if net.num_addresses <= 65536 else []
            first_ip = str(hosts[0]) if hosts else str(net.network_address)
            last_ip = str(hosts[-1]) if hosts else str(net.broadcast_address)

            usable_count = len(hosts) if hosts else max(0, net.num_addresses - 2)
            if net.num_addresses == 1:
                usable_count = 1
                first_ip = last_ip = str(net.network_address)

            # Wildcard mask calculation for IPv4
            if net.version == 4:
                netmask_int = int(net.netmask)
                wildcard_int = 0xFFFFFFFF ^ netmask_int
                wildcard_mask = str(ipaddress.IPv4Address(wildcard_int))
                binary_netmask = ".".join(f"{int(octet):08b}" for octet in str(net.netmask).split("."))
            else:
                wildcard_mask = "N/A (IPv6)"
                binary_netmask = bin(int(net.netmask))[2:]

            # IP Scope classification
            if net.is_loopback:
                scope = "Loopback (Local Device Only)"
            elif net.is_private:
                scope = "Private Network (RFC 1918 / Intranet)"
            elif net.is_link_local:
                scope = "Link-Local (APIPA Automatic Address)"
            elif net.is_multicast:
                scope = "Multicast Group"
            elif net.is_global:
                scope = "Public Internet (Routable WAN)"
            else:
                scope = "Reserved / Special Purpose"

            return SubnetDetails(
                cidr=str(net),
                network_address=str(net.network_address),
                broadcast_address=str(net.broadcast_address) if net.version == 4 else "N/A",
                netmask=str(net.netmask),
                wildcard_mask=wildcard_mask,
                first_usable_ip=first_ip,
                last_usable_ip=last_ip,
                total_addresses=net.num_addresses,
                usable_hosts=usable_count,
                ip_version=net.version,
                is_private=net.is_private,
                is_global=net.is_global,
                is_loopback=net.is_loopback,
                is_multicast=net.is_multicast,
                ip_scope=scope,
                binary_netmask=binary_netmask,
            )

        except Exception as e:
            logger.warning("Failed to calculate subnet for '%s': %s", cidr_input, e)
            return None
