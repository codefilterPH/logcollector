"""Live evidence response shared by background polling and local imports."""

from datetime import timedelta

from django.db.models import Exists, OuterRef, Q
from django.utils import timezone

from log_collector.models import BlockedIPAddress, SecurityIncident
from log_collector.services.blocking import (
    auto_block_max_evidence_age_seconds,
    block_ip,
    is_auto_block_enabled,
)
from log_collector.services.client_ip import is_trusted_security_ip
from log_collector.services.incidents import process_security_evidence


def respond_to_security_evidence(entity, *, access_logs=(), token_usages=(), now=None, defer_edge=False,
                                 inserted_access_log_ids=None):
    now = now or timezone.now()
    result = process_security_evidence(entity, access_logs=access_logs, token_usages=token_usages, now=now,
                                      inserted_access_log_ids=inserted_access_log_ids)
    counts = {"incidents_created": len(result.created_ids), "incidents_updated": len(result.updated_ids),
              "incidents_qualifying": len(result.qualifying_ids), "blocks_created": 0, "exempt": 0}
    counts.update(respond_to_incidents(result.qualifying_ids, now=now, defer_edge=defer_edge))
    return counts


def respond_to_incidents(incident_ids, *, now=None, defer_edge=False):
    now = now or timezone.now()
    counts = {"blocks_created": 0, "exempt": 0}
    for incident in SecurityIncident.objects.filter(pk__in=incident_ids).order_by("pk"):
        response = block_ip(incident.source_ip, origin="automatic", reason=incident.rule_code,
                            incident=incident, now=now, defer_edge=defer_edge)
        counts["blocks_created"] += response.created
        counts["exempt"] += response.status == "exempt"
    return counts


def reconcile_recent_security_incidents(*, now=None, limit=100, exclude_ids=()):
    """Recover response gaps without rescanning sources or replaying attached evidence."""
    now = now or timezone.now()
    counts = {"incidents_reconciled": 0, "blocks_created": 0, "exempt": 0}
    if limit <= 0 or not is_auto_block_enabled():
        return counts
    active_block = BlockedIPAddress.objects.filter(ip_address=OuterRef("source_ip"), desired_active=True)
    # A shared block may have moved its FK to a later incident. Its lifecycle
    # still covers all same-IP evidence observed before the latest update.
    handled = BlockedIPAddress.objects.filter(
        Q(incident_id=OuterRef("pk")) |
        Q(ip_address=OuterRef("source_ip"), updated_at__gte=OuterRef("last_seen_at"))
    )
    pending = SecurityIncident.objects.annotate(
        has_active_block=Exists(active_block), has_block_response=Exists(handled),
    ).filter(
        has_active_block=False, has_block_response=False, evidence__isnull=False,
        category__in=("malicious", "unauthorized"),
        last_seen_at__gte=now - timedelta(seconds=auto_block_max_evidence_age_seconds()),
        last_seen_at__lte=now,
    ).exclude(pk__in=exclude_ids).order_by("last_seen_at", "pk").distinct()
    candidates = []
    for incident in pending.iterator(chunk_size=100):
        if is_trusted_security_ip(incident.source_ip):
            continue
        candidates.append(incident.pk)
        if len(candidates) >= limit:
            break
    counts["incidents_reconciled"] = len(candidates)
    counts.update(respond_to_incidents(candidates, now=now))
    return counts
