import ipaddress
import os
from urllib.parse import urlsplit


def _trusted_proxy_networks():
    result = []
    for value in os.getenv("TRUSTED_PROXY_CIDRS", "").split(","):
        value = value.strip()
        if value:
            try:
                result.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
    return result


def resolve_client_ip(peer_ip: str, forwarded_for: str | None = None) -> str:
    """Trust XFF only when the socket peer and all skipped hops are configured proxies."""
    try:
        peer = ipaddress.ip_address(peer_ip)
    except ValueError:
        return "unknown"
    networks = _trusted_proxy_networks()
    if os.getenv("TRUST_PROXY_HEADERS", "false").lower() != "true" or not any(peer in n for n in networks):
        return str(peer)
    chain = []
    for value in (forwarded_for or "").split(","):
        try:
            chain.append(ipaddress.ip_address(value.strip()))
        except ValueError:
            continue
    chain.append(peer)
    for address in reversed(chain):
        if not any(address in network for network in networks):
            return str(address)
    return str(peer)


def csrf_origin_allowed(origin: str | None, configured_origins: str) -> bool:
    if not origin:
        return False
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
        return False
    normalized = f"{parsed.scheme}://{parsed.netloc}".lower()
    allowed = {item.strip().rstrip("/").lower() for item in configured_origins.split(",") if item.strip() and item.strip() != "*"}
    return normalized in allowed
