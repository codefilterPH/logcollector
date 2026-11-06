from functools import lru_cache
from ipaddress import ip_address, ip_network

from django.conf import settings
from django.core.checks import Error
from django.core.exceptions import ImproperlyConfigured


@lru_cache(maxsize=32)
def _parse_cidrs(cidrs):
    try:
        return tuple(ip_network(cidr) for cidr in cidrs)
    except (ValueError, TypeError) as exc:
        raise ImproperlyConfigured(f"Invalid Log Collector CIDR: {exc}") from exc


def check_security_cidrs(app_configs=None, **kwargs):
    errors = []
    for name in ("LOG_COLLECTOR_TRUSTED_PROXY_CIDRS", "LOG_COLLECTOR_TRUSTED_IP_CIDRS"):
        try:
            _parse_cidrs(tuple(getattr(settings, name)))
        except (ImproperlyConfigured, TypeError) as exc:
            errors.append(Error(f"{name}: {exc}", id="log_collector.E001"))
    return errors


def _parse_ip(value):
    try:
        return ip_address(value)
    except (ValueError, TypeError):
        return None


def resolve_client_ip(request) -> str | None:
    """Trust forwarding hops only behind explicitly configured proxies."""
    peer = _parse_ip(request.META.get("REMOTE_ADDR"))
    if peer is None:
        return None
    proxies = _parse_cidrs(tuple(settings.LOG_COLLECTOR_TRUSTED_PROXY_CIDRS))
    if not any(peer in network for network in proxies):
        return str(peer)
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if not forwarded:
        return str(peer)
    hops = [_parse_ip(hop.strip()) for hop in forwarded.split(",")]
    if any(hop is None for hop in hops):
        return str(peer)
    client = peer
    for hop in reversed(hops):
        if not any(client in network for network in proxies):
            break
        client = hop
    return str(client)


def is_configured_trusted_security_ip(ip_address: str) -> bool:
    address = _parse_ip(ip_address)
    if address is None:
        return False
    networks = _parse_cidrs(
        ("127.0.0.0/8", "::1/128") + tuple(settings.LOG_COLLECTOR_TRUSTED_IP_CIDRS)
    )
    return any(address in network for network in networks)


def is_trusted_security_ip(ip_address: str) -> bool:
    """Configured, loopback, and audited white-flag IPs are trusted."""
    address = _parse_ip(ip_address)
    if address is None:
        return False
    if is_configured_trusted_security_ip(str(address)):
        return True
    from log_collector.services.trusted_ips import is_white_flagged_ip

    return is_white_flagged_ip(str(address))
