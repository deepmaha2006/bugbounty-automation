"""SSRF self-protection for the scan engine itself (spec's threat model,
docs/THREAT_MODEL.md boundary 5).

This is NOT the SSRF *scanner* (scanners/advanced_scanners.py::SSRFScanner,
which tests whether a *target application* is vulnerable to SSRF by asking
it to fetch an attacker-supplied URL). This module protects the platform's
own scanning infrastructure from being tricked into making real outbound
requests to internal/loopback/link-local/reserved addresses — including the
cloud metadata endpoint (169.254.169.254) and the platform's own database/
queue hosts — via nothing more than a URL someone registered as a "target".

Re-resolves DNS on every call rather than trusting a cached result, and is
meant to be called again immediately before a scan actually executes (not
only at asset-registration time), since DNS can change in between
(DNS-rebinding) — see call sites in webapp/services/*_scan_service.py.
"""
import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeScanTargetError(ValueError):
    """A target resolves to infrastructure that must never be scanned."""


def _is_unsafe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparsable address -> fail closed, treat as unsafe
    return (ip.is_private or ip.is_loopback or ip.is_link_local
           or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def resolve_and_check(hostname: str) -> None:
    """Raises UnsafeScanTargetError if `hostname` resolves to ANY disallowed
    address (checks every A/AAAA record returned, not just the first)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise UnsafeScanTargetError(f"Could not resolve target host '{hostname}': {e}") from e
    for info in infos:
        ip_str = info[4][0]
        if _is_unsafe_ip(ip_str):
            raise UnsafeScanTargetError(
                f"Target host '{hostname}' resolves to a disallowed address ({ip_str}) — "
                "internal, loopback, link-local, and reserved infrastructure can never be scanned."
            )


def assert_safe_ip_or_cidr(raw: str) -> None:
    """Validate a raw IP address or CIDR range (system/network scans accept
    these directly, unlike web scans which always go through a hostname) —
    `ipaddress` network objects expose the same is_private/is_loopback/etc.
    properties as single addresses, correctly reporting True for any network
    that falls entirely within a disallowed range (e.g. 10.1.2.0/24 is
    is_private because it's a subset of 10.0.0.0/8)."""
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError as e:
        raise UnsafeScanTargetError(f"Could not parse IP/CIDR target '{raw}': {e}") from e
    if (net.is_private or net.is_loopback or net.is_link_local
            or net.is_multicast or net.is_reserved or net.is_unspecified):
        raise UnsafeScanTargetError(
            f"Target '{raw}' is within a disallowed address range — internal, loopback, "
            "link-local, and reserved infrastructure can never be scanned."
        )


def assert_safe_scan_target(url: str) -> None:
    """Validate a full target URL (scheme+host[:port], or a bare host) is
    safe to actually scan. Call this immediately before any real outbound
    request the scan engine is about to make against a user-supplied target."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    hostname = parsed.hostname
    if not hostname:
        raise UnsafeScanTargetError(f"Could not determine a hostname from target URL: {url!r}")
    if hostname.lower() == "localhost":
        raise UnsafeScanTargetError("Target host 'localhost' can never be scanned.")
    resolve_and_check(hostname)
