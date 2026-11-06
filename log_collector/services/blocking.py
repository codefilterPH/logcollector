"""The shared, audited deployment-wide IP block lifecycle.

Authorization belongs to callers. Django state is committed before optional edge
work; an unavailable helper must never undo a block or an unblock.
"""

import json
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from ipaddress import ip_address as parse_ip

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from log_collector.models import (
    BlockedIPAddress, IPBlockAuditEvent, LogCollectorAuditEvent, LogCollectorEntity,
    LogCollectorSettings, SecurityIncident,
)
from log_collector.services.client_ip import is_trusted_security_ip
from log_collector.security_events import sanitize_security_event, security_group_name


@dataclass(frozen=True)
class BlockResult:
    block: BlockedIPAddress | None
    created: bool
    django_applied: bool
    nginx_state: str
    status: str = "applied"


def publish_security_event(entity_id, event_type, payload) -> None:
    """Publish a sanitized snapshot only after the enclosing transaction commits."""
    event = sanitize_security_event(entity_id, event_type, payload)
    if event is None:
        return

    def send():
        layer = get_channel_layer()
        if layer is not None:
            async_to_sync(layer.group_send)(security_group_name(entity_id),
                                             {"type": "security.event", "event": event})

    # A delivery outage must not turn a successfully committed block into an error.
    transaction.on_commit(send, robust=True)


def _publish_block_state(block):
    # Blocks apply to this deployment, including blocks attributed to a remote incident.
    # Remote entity groups remain informational and never become an enforcement target.
    entity_id = LogCollectorEntity.get_hosting_entity().pk
    publish_security_event(entity_id, "block.state_changed", {
        "block_id": block.pk, "incident_id": block.incident_id,
        "desired_active": block.desired_active, "django_state": block.django_state,
        "nginx_state": block.nginx_state,
    })


def _result(block=None, *, created=False, status="applied"):
    return BlockResult(block, created, bool(block and block.desired_active and
                       block.django_state == "active"),
                       block.nginx_state if block else "not_configured", status)


@contextmanager
def _policy_lock():
    # Also serialize creation when no active IP row exists yet. Every lifecycle
    # operation acquires this lock before any block lock, in the same order.
    hosting = LogCollectorEntity.get_hosting_entity()
    policy = LogCollectorSettings.for_entity(hosting)
    with transaction.atomic():
        LogCollectorSettings.objects.select_for_update().get(pk=policy.pk)
        yield


def _audit(block, action, *, previous_django="", previous_nginx="", actor=None,
           reason="", details=None, now=None):
    IPBlockAuditEvent.objects.create(
        block=block, incident_id=block.incident_id, actor=actor, action=action,
        previous_django_state=previous_django, new_django_state=block.django_state,
        previous_nginx_state=previous_nginx, new_nginx_state=block.nginx_state,
        reason=reason, details=details or {}, timestamp=now or timezone.now(),
    )


def _exempt(ip, origin, incident, actor):
    # No block exists for an exempt attempt, so use the collector refusal audit.
    LogCollectorAuditEvent.objects.create(
        entity_id=incident.entity_id if incident else None, user=actor,
        event_type=LogCollectorAuditEvent.EventType.DENIED, outcome="exempt",
        path="", ip_address=ip,
        details={"status": "trusted_ip_exempt", "origin": origin,
                 "incident_id": incident.pk if incident else None},
    )
    return _result(status="exempt")


def _helper_action(action, block):
    """Execute only the fixed helper protocol; never accept a caller command."""
    helper = getattr(settings, "LOG_COLLECTOR_NGINX_BLOCK_HELPER", "")
    if not helper:
        if action == "unblock":
            return "remove_failed", "Nginx helper is not configured; removal is unverified"
        if block.nginx_state != "not_configured":
            return "failed", "Nginx helper is not configured; application is unverified"
        return "not_configured", ""
    if action not in ("block", "unblock"):
        raise ValueError("Invalid Nginx action")
    failure = "failed" if action == "block" else "remove_failed"
    expiry = block.expires_at.isoformat() if action == "block" and block.expires_at else ""
    try:
        completed = subprocess.run(
            [helper, action, block.ip_address, expiry], shell=False,
            timeout=getattr(settings, "LOG_COLLECTOR_NGINX_BLOCK_HELPER_TIMEOUT_SECONDS", 5),
            capture_output=True, text=True,
        )
        if completed.returncode:
            return failure, "Nginx helper exited unsuccessfully"
        if len(completed.stdout.encode("utf-8")) + len(completed.stderr.encode("utf-8")) > 8192:
            return failure, "Nginx helper output exceeded 8192 bytes"
        payload = json.loads(completed.stdout)
        if (not isinstance(payload, dict) or set(payload) != {"applied", "verified", "detail"}
                or type(payload["applied"]) is not bool or type(payload["verified"]) is not bool
                or not isinstance(payload["detail"], str)):
            return failure, "Nginx helper returned an invalid response"
        if not payload["applied"] or not payload["verified"]:
            return failure, "Nginx helper did not verify the action"
        return ("applied" if action == "block" else "removed"), ""
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeError):
        return failure, "Nginx helper could not complete the action"


def _sync_nginx(block_id, *, actor=None, reason="", now=None):
    now = now or timezone.now()
    candidate = BlockedIPAddress.objects.get(pk=block_id)
    if candidate.desired_active and candidate.expires_at is not None and candidate.expires_at <= now:
        return _deactivate(block_id, actor=actor, reason="Block expired", now=now,
                           action="expired", only_expired=True).block
    if candidate.desired_active and is_trusted_security_ip(candidate.ip_address):
        return _deactivate(block_id, actor=actor, reason="Trusted IP exemption", now=now,
                           action="unblocked").block
    with _policy_lock():
        block = BlockedIPAddress.objects.select_for_update().get(pk=block_id)
        if block.desired_active and block.nginx_state not in ("pending", "failed", "not_configured"):
            return block
        if not block.desired_active and block.nginx_state not in ("pending", "remove_failed"):
            return block
        previous = block.nginx_state
        # A previous incarnation's retry must never remove a newer active rule.
        replacement = (BlockedIPAddress.objects.filter(ip_address=block.ip_address, desired_active=True)
                       .exclude(pk=block.pk).first()) if not block.desired_active else None
        if replacement and replacement.nginx_state != "applied":
            # Keep unresolved responsibility, but let a bounded retry reach the
            # replacement rather than repeatedly selecting this deferred row.
            block.save(update_fields=("updated_at",))
            return block
        superseded = replacement is not None
        state, error = (("removed", "") if superseded else
                        _helper_action("block" if block.desired_active else "unblock", block))
        block.nginx_state, block.last_error = state, error
        block.save(update_fields=("nginx_state", "last_error", "updated_at"))
        if state != previous:
            _audit(block, "failed" if state in ("failed", "remove_failed") else "applied",
                   previous_django=block.django_state, previous_nginx=previous,
                   actor=actor, reason=reason, details={"layer": "nginx"}, now=now)
            _publish_block_state(block)
        return block


def block_ip(ip_address, *, origin, reason, incident=None, actor=None, expires_at=None, now=None,
             defer_edge=False, fail_if_active=False) -> BlockResult:
    """Request a block, returning explicit exempt/disabled/stale refusal statuses.

    Automatic calls require a stored incident for the same IP. Only newly seen
    incident evidence extends an automatic block; replaying a request is a no-op.
    Manual authorization (including superuser checks) belongs to the view layer.
    Local import callers defer edge work to the periodic retry without delaying Django state.
    Create-only callers use fail_if_active to return a side-effect-free conflict
    while holding the lifecycle lock, before any existing block can be changed.
    """
    ip = str(parse_ip(ip_address))
    now = now or timezone.now()
    if origin not in BlockedIPAddress.Origin.values:
        raise ValueError("Invalid block origin")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("A reason is required")
    if expires_at is not None and expires_at <= now:
        raise ValueError("Expiry must be in the future")
    if incident is not None:
        if incident.pk is None:
            raise ValueError("A persisted incident is required")
        try:
            incident = SecurityIncident.objects.get(pk=incident.pk)
        except SecurityIncident.DoesNotExist as exc:
            raise ValueError("A persisted incident is required") from exc
        if str(parse_ip(incident.source_ip)) != ip:
            raise ValueError("Incident IP does not match the requested IP")
    if is_trusted_security_ip(ip):
        return _exempt(ip, origin, incident, actor)
    if origin == "automatic":
        if incident is None:
            raise ValueError("Automatic blocking requires an incident")
        if not getattr(settings, "LOG_COLLECTOR_AUTO_BLOCK_ENABLED", False):
            return _result(status="disabled")
        age = (now - incident.last_seen_at).total_seconds()
        if age > getattr(settings, "LOG_COLLECTOR_AUTO_BLOCK_MAX_EVIDENCE_AGE_SECONDS", 900) or age < 0:
            return _result(status="stale")
        expires_at = expires_at or now + timedelta(
            seconds=getattr(settings, "LOG_COLLECTOR_AUTO_BLOCK_DURATION_SECONDS", 86400))

    with _policy_lock():
        block = BlockedIPAddress.objects.select_for_update().filter(ip_address=ip, desired_active=True).first()
        if block and fail_if_active:
            return _result(block, status="conflict")
        evidence = {"evidence_seen_at": incident.last_seen_at.isoformat()} if origin == "automatic" else {}
        if block:
            if origin == "automatic":
                latest = block.audit_events.filter(action="requested").first()
                seen = latest.details.get("evidence_seen_at", "") if latest else ""
                if (block.origin != "automatic" or block.expires_at is None
                        or evidence["evidence_seen_at"] <= seen or expires_at <= block.expires_at):
                    return _result(block, status="unchanged")
            elif block.origin == "manual" and block.expires_at == expires_at:
                return _result(block, status="unchanged")
            previous_nginx = block.nginx_state
            block.origin, block.incident, block.reason = origin, incident, reason
            block.expires_at = expires_at
            if origin == "manual":
                block.created_by = actor
            block.nginx_state = "pending" if settings.LOG_COLLECTOR_NGINX_BLOCK_HELPER or previous_nginx != "not_configured" else "not_configured"
            block.last_error = ""
            block.save()
            _audit(block, "requested", previous_django=block.django_state, previous_nginx=previous_nginx,
                   actor=actor, reason=reason, details=evidence, now=now)
            created = False
        else:
            block = BlockedIPAddress.objects.create(
                ip_address=ip, origin=origin, reason=reason, incident=incident, created_by=actor,
                expires_at=expires_at, django_state="inactive",
                nginx_state="pending" if settings.LOG_COLLECTOR_NGINX_BLOCK_HELPER else "not_configured",
            )
            _audit(block, "requested", actor=actor, reason=reason, details=evidence, now=now)
            block.django_state = "active"
            block.save(update_fields=("django_state", "updated_at"))
            _audit(block, "applied", previous_django="inactive", previous_nginx=block.nginx_state,
                   actor=actor, reason=reason, details={"layer": "django"}, now=now)
            created = True
        _publish_block_state(block)
    if block.nginx_state == "pending" and not defer_edge:
        block = _sync_nginx(block.pk, actor=actor, reason=reason, now=now)
    return _result(block, created=created)


def _deactivate(block_id, *, actor, reason, now, action, only_expired=False):
    with _policy_lock():
        block = BlockedIPAddress.objects.select_for_update().get(pk=block_id)
        if not block.desired_active or (only_expired and (block.expires_at is None or block.expires_at > now)):
            return _result(block, status="unchanged")
        previous_django, previous_nginx = block.django_state, block.nginx_state
        block.desired_active, block.django_state = False, "inactive"
        block.nginx_state = "pending" if settings.LOG_COLLECTOR_NGINX_BLOCK_HELPER or previous_nginx != "not_configured" else "not_configured"
        block.last_error = ""
        block.save(update_fields=("desired_active", "django_state", "nginx_state", "last_error", "updated_at"))
        _audit(block, action, previous_django=previous_django, previous_nginx=previous_nginx,
               actor=actor, reason=reason, now=now)
        _publish_block_state(block)
    if block.nginx_state == "pending":
        block = _sync_nginx(block.pk, actor=actor, reason=reason, now=now)
    return _result(block)


def unblock_ip(block, *, actor=None, reason, now=None) -> BlockResult:
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("A reason is required")
    return _deactivate(block.pk, actor=actor, reason=reason, now=now or timezone.now(), action="unblocked")


def expire_blocks(*, now=None, limit=None) -> int:
    now = now or timezone.now()
    if limit is not None and (not isinstance(limit, int) or limit < 1):
        raise ValueError("Expiry limit must be positive")
    ids = BlockedIPAddress.objects.filter(desired_active=True, expires_at__lte=now).order_by("expires_at", "pk").values_list("pk", flat=True)
    if limit is not None:
        ids = ids[:limit]
    count = 0
    for block_id in ids.iterator(chunk_size=100):
        result = _deactivate(block_id, actor=None, reason="Block expired", now=now,
                             action="expired", only_expired=True)
        count += result.status != "unchanged"
    return count


def retry_pending_nginx_actions(*, limit=100) -> int:
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("Retry limit must be positive")
    if not settings.LOG_COLLECTOR_NGINX_BLOCK_HELPER:
        return 0
    pending = (Q(desired_active=True, nginx_state__in=("pending", "failed", "not_configured")) |
               Q(desired_active=False, nginx_state__in=("pending", "remove_failed")))
    ids = list(BlockedIPAddress.objects.filter(pending).order_by("updated_at", "pk").values_list("pk", flat=True)[:limit])
    for block_id in ids:
        _sync_nginx(block_id, reason="Retry Nginx enforcement")
    return len(ids)
