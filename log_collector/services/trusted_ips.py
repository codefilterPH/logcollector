"""Database-backed, audited exact-IP white flags."""

from ipaddress import ip_address

from log_collector.models import LogCollectorAuditEvent


WHITE_FLAG_ACTIONS = ("white_flag_ip", "remove_white_flag_ip")


def normalize_ip(value):
    if not isinstance(value, str):
        raise ValueError("An IP address string is required.")
    try:
        return str(ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("A valid IP address is required.") from exc


def active_white_flag_ips(ip_addresses=None):
    """Return exact IPs whose latest successful white-flag event enables them."""
    candidates = None
    if ip_addresses is not None:
        candidates = {normalize_ip(value) for value in ip_addresses}
        if not candidates:
            return set()

    events = LogCollectorAuditEvent.objects.filter(
        event_type=LogCollectorAuditEvent.EventType.API_REQUEST,
        outcome="success",
        details__action__in=WHITE_FLAG_ACTIONS,
    )
    if candidates is not None:
        events = events.filter(details__target_ip__in=candidates)

    active = set()
    for event in events.order_by("created_at", "pk").iterator():
        target_ip = event.details.get("target_ip")
        try:
            target_ip = normalize_ip(target_ip)
        except ValueError:
            continue
        if event.details.get("action") == "white_flag_ip":
            active.add(target_ip)
        else:
            active.discard(target_ip)
    return active


def is_white_flagged_ip(ip_address_value):
    try:
        normalized_ip = normalize_ip(ip_address_value)
    except ValueError:
        return False
    return normalized_ip in active_white_flag_ips([normalized_ip])
