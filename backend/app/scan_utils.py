import ipaddress
import json
import socket
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse


_BLOCKED_TARGET_IPS = {
    ipaddress.ip_address("172.16.93.136"),
    ipaddress.ip_address("172.16.93.211"),
}


def normalize_report(report_payload: Any) -> Optional[Dict[str, Any]]:
    if isinstance(report_payload, dict):
        return report_payload
    if isinstance(report_payload, str):
        try:
            return json.loads(report_payload)
        except json.JSONDecodeError:
            return None
    return None


def normalize_scan_types(scan_types: Any) -> list[str]:
    if not isinstance(scan_types, list):
        return []
    normalized: list[str] = []
    for item in scan_types:
        if isinstance(item, (str, bytes)):
            value = str(item).lower().strip()
            if value and value not in normalized:
                normalized.append(value)
    if "all" in normalized and len(normalized) > 1:
        normalized = [value for value in normalized if value != "all"]
    return normalized


def scan_type_from_scan_types(scan_types: Any) -> str:
    normalized = normalize_scan_types(scan_types)
    if normalized == ["all"] or not normalized:
        return "bulk"
    return "detailed"


def _resolve_host_ips(host: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    resolved: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    try:
        addr_info = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return resolved
    for family, _, _, _, sockaddr in addr_info:
        if family == socket.AF_INET:
            addr = sockaddr[0]
        elif family == socket.AF_INET6:
            addr = sockaddr[0]
        else:
            continue
        try:
            resolved.add(ipaddress.ip_address(addr))
        except ValueError:
            continue
    return resolved


def validate_target_url(url: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Returns (is_allowed, blocked_ip, error_code).
    error_code is set for invalid URL/scheme.
    """
    if not isinstance(url, str) or not url.strip():
        return False, None, "invalid_url"

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, None, "unsupported_scheme"

    host = parsed.hostname
    if not host:
        return False, None, "invalid_host"

    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None

    if host_ip:
        if host_ip in _BLOCKED_TARGET_IPS:
            return False, str(host_ip), None
        return True, None, None

    resolved_ips = _resolve_host_ips(host)
    for resolved_ip in resolved_ips:
        if resolved_ip in _BLOCKED_TARGET_IPS:
            return False, str(resolved_ip), None

    return True, None, None
