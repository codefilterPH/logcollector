"""Bounded remote health status reads and refresh helpers."""

from datetime import datetime

from django.core.cache import cache
from django.utils import timezone

from log_collector.services.remote import RemoteCollectorError, fetch_remote_json

HEALTH_STATUS_TTL_SECONDS = 600
HEALTH_STATUS_STALE_SECONDS = 180


def remote_health_checks(entity):
    checks = [
        ("metrics/", None, "Metrics API unavailable"),
        ("access-logs/", {"page_size": 1}, "Access Logs API unavailable"),
        ("security-summary/", None, "Security Summary API unavailable"),
    ]
    if entity.geolocation_enabled:
        checks.append(("geolocation/", {"page_size": 1}, "Geolocation API unavailable"))
    if entity.user_sessions_enabled:
        checks.append(("user-sessions/", {"page_size": 1}, "User Sessions API unavailable"))
    return checks


def probe_entity_health_status(entity):
    if entity.is_hosting:
        return {
            "status": "online",
            "label": "Online",
            "detail": "Local collector is available",
        }
    if not entity.api_base_url or not entity.remote_api_key:
        return {
            "status": "not_configured",
            "label": "Not configured",
            "detail": "Remote URL or API token missing",
        }

    for resource, params, failure_detail in remote_health_checks(entity):
        try:
            if params is None:
                response_data = fetch_remote_json(entity, resource)
            else:
                response_data = fetch_remote_json(entity, resource, params=params)
        except RemoteCollectorError:
            return {"status": "down", "label": "Down", "detail": failure_detail}
        if not isinstance(response_data, dict):
            return {"status": "down", "label": "Down", "detail": failure_detail}
    return {
        "status": "online",
        "label": "Online",
        "detail": "All enabled APIs responding",
    }


def cached_entity_health_status(entity):
    if entity.is_hosting:
        return probe_entity_health_status(entity)
    if not entity.api_base_url or not entity.remote_api_key:
        return probe_entity_health_status(entity)

    try:
        result = cache.get(f"log_collector:health:{entity.pk}")
    except Exception:
        result = None
    if not result:
        return {
            "status": "unknown",
            "label": "Checking",
            "detail": "No health check has completed yet",
        }

    result = dict(result)
    checked_at = result.get("checked_at")
    try:
        age = (timezone.now() - datetime.fromisoformat(checked_at)).total_seconds()
    except (TypeError, ValueError):
        age = HEALTH_STATUS_STALE_SECONDS + 1
    if age > HEALTH_STATUS_STALE_SECONDS:
        result["status"] = "stale"
        result["label"] = f"{result.get('label', 'Unknown')} (stale)"
        result["detail"] = (
            f"{result.get('detail', '')} Last checked {checked_at or 'unknown'}"
        )
    return result


def save_entity_health_status(entity_id, result, *, checked_at=None):
    checked_at = checked_at or timezone.now()
    key = f"log_collector:health:{entity_id}"
    try:
        current = cache.get(key)
        try:
            current_checked_at = (
                datetime.fromisoformat(current["checked_at"]) if current else None
            )
        except (KeyError, TypeError, ValueError):
            current_checked_at = None
        if current_checked_at and current_checked_at > checked_at:
            return False
        cache.set(
            key,
            {**result, "checked_at": checked_at.isoformat()},
            timeout=HEALTH_STATUS_TTL_SECONDS,
        )
    except Exception:
        return False
    return True
