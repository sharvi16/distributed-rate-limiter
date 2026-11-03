"""
IP Resolution and Trusted Proxy Validation Utilities.

Provides secure client IP address extraction adhering to RFC 7239 and proxy chain
validation standards to prevent IP spoofing attacks via manipulated X-Forwarded-For headers.
"""

import ipaddress
from typing import List, Optional, Sequence, Union
from starlette.requests import Request


def parse_trusted_proxies(config_str: str) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """
    Parses a comma-separated list of IP addresses and CIDR subnets into IPNetwork objects.
    Example: "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12"
    """
    networks = []
    if not config_str:
        return networks
    for entry in config_str.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            # strict=False allows host addresses (e.g. 127.0.0.1) or unmasked subnets
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass
    return networks


# Default trusted proxies: IPv4 and IPv6 loopback
DEFAULT_TRUSTED_PROXIES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def is_ip_trusted(
    ip_str: str,
    trusted_networks: Sequence[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]
) -> bool:
    """
    Checks if an IP address string falls within any of the configured trusted networks.
    """
    if not ip_str or not trusted_networks:
        return False
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in trusted_networks)
    except ValueError:
        return False


def resolve_client_ip(
    request: Request,
    trusted_networks: Optional[Sequence[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]] = None
) -> str:
    """
    Securely resolves the actual client IP address from an incoming HTTP request.
    
    Security Rules:
      1. If the direct socket peer IP is NOT in trusted_networks, X-Forwarded-For is IGNORED.
         This prevents external clients from spoofing arbitrary IP addresses.
      2. If the direct peer IP IS trusted, X-Forwarded-For is evaluated from right to left.
         The first untrusted, syntactically valid IP encountered is returned as the client IP.
      3. If all valid IPs in X-Forwarded-For are trusted, the leftmost valid IP is returned.
      4. If X-Forwarded-For contains only malformed/invalid addresses, peer IP is returned.
      5. If X-Forwarded-For is absent or empty, peer IP is returned.
    """
    if trusted_networks is None:
        trusted_networks = DEFAULT_TRUSTED_PROXIES

    peer_ip = request.client.host if request.client and request.client.host else "127.0.0.1"

    # Rule 1: Direct peer is not a trusted proxy -> Do NOT trust forwarded headers
    if not is_ip_trusted(peer_ip, trusted_networks):
        return peer_ip

    # Rule 2: Peer is trusted -> inspect X-Forwarded-For
    forwarded_for = request.headers.get("x-forwarded-for")
    if not forwarded_for:
        return peer_ip

    raw_ips = [ip.strip() for ip in forwarded_for.split(",") if ip.strip()]
    if not raw_ips:
        return peer_ip

    # Traverse from right to left (from LB towards client)
    for ip in reversed(raw_ips):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            # Skip malformed non-IP entries
            continue

        if not any(addr in net for net in trusted_networks):
            return str(addr)

    # If all valid entries in X-Forwarded-For were within trusted networks, return the leftmost valid
    for ip in raw_ips:
        try:
            addr = ipaddress.ip_address(ip)
            return str(addr)
        except ValueError:
            continue

    return peer_ip
