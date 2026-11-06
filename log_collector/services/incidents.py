"""Transactional, idempotent incident assignment and bounded historical replay."""

import hashlib
import json
import re
from bisect import bisect_left, bisect_right
from collections import defaultdict
from copy import copy
from dataclasses import dataclass, field
from datetime import timedelta

from django.db import transaction
from django.db.models import Case, Count, FloatField, IntegerField, Max, Min, Q, Value, When
from django.db.models.functions import Cast
from django.utils import timezone

from log_collector.models import (
    LogCollectorApiTokenUsage, LogCollectorEntity, LogCollectorSettings,
    NginxAccessLog, SecurityIncident, SecurityIncidentEvidence,
)
from log_collector.services.security import (
    DENIAL_WINDOW_SECONDS,
    WINDOW_MINUTES,
    classify_access_logs,
    classify_token_denials,
)
from log_collector.services.blocking import publish_security_event


JOIN_WINDOW = timedelta(minutes=15)
CLASSIFIER_LOOKBACK = timedelta(minutes=5)
SEVERITY_LEVELS = ("low", "medium", "high", "critical")
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITY_LEVELS)}
# Explicit priority is stable even when classifiers change their return order.
RULE_PRIORITY = {rule: index for index, rule in enumerate((
    "traversal_probe", "sensitive_file_probe", "sql_injection", "xss",
    "command_injection", "remote_code_execution", "known_scanner",
    "broad_client_error_probe", "protected_path_denials", "api_key_denials",
))}
REQUESTED_ENTITY = re.compile(r"^/log-collector/api/entities/([\w-]+)/")


@dataclass
class IncidentProcessingResult:
    created_ids: list[int] = field(default_factory=list)
    updated_ids: list[int] = field(default_factory=list)
    qualifying_ids: list[int] = field(default_factory=list)
    skipped_evidence_count: int = 0


def _prepare_sources(entity, access_logs, token_usages):
    access = {row.pk: row for row in access_logs if row.entity_id == entity.pk}
    usages = {row.pk: row for row in token_usages}
    requested = {row.pk: REQUESTED_ENTITY.match(row.path) for row in usages.values() if row.entity_id is None}
    slugs = {match.group(1) for match in requested.values() if match}
    entities = dict(LogCollectorEntity.objects.filter(slug__in=slugs).values_list("slug", "pk")) if slugs else {}
    hosting_id = entity.pk if entity.is_hosting else LogCollectorEntity.get_hosting_entity().pk
    prepared = {}
    for row in usages.values():
        if row.entity_id is None:
            if not row.path.startswith("/log-collector/api/"):
                continue
            match = requested.get(row.pk)
            row = copy(row)
            row.entity_id = entities.get(match.group(1), hosting_id) if match else hosting_id
        prepared[row.pk] = row
    return access, prepared


def _strength(match):
    return (-(match.category == "malicious"), -SEVERITY_RANK[match.severity],
            -match.confidence, RULE_PRIORITY.get(match.rule_code, len(RULE_PRIORITY)),
            match.rule_code, match.target_family)


def _assign_matches(access, usages, matches, winners=None):
    """Resolve overlap before touching persistence; no empty incidents survive."""
    winners = winners if winners is not None else {}
    for match in sorted(matches, key=_strength):
        for kind, identifiers, sources in (("access_log", match.access_log_ids, access),
                                           ("token_usage", match.token_usage_ids, usages)):
            for identifier in identifiers:
                row = sources.get(identifier)
                if row is None:
                    continue
                key = kind, identifier
                if key not in winners or _strength(match) < _strength(winners[key][1]):
                    winners[key] = row, match
    return winners


def _observed(kind, row):
    return row.timestamp if kind == "access_log" else row.created_at


def _fingerprint(entity_id, match):
    values = [entity_id, match.source_ip, match.rule_code, match.target_family]
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def _payload(match, observed):
    # Copy only classifier-owned, sanitized fields, never raw paths, queries or agents.
    return {"rule_code": match.rule_code, "category": match.category, "severity": match.severity,
            "confidence": match.confidence, "target_family": match.target_family,
            "observed_at": observed.isoformat()}


def _persist_assignments(entity, winners):
    result = IncidentProcessingResult()
    if not winners:
        return result
    hosting = entity if entity.is_hosting else LogCollectorEntity.get_hosting_entity()
    settings = LogCollectorSettings.for_entity(hosting)
    with transaction.atomic():
        # One lock serializes all hosting access/token campaigns, including remote attribution.
        LogCollectorSettings.objects.select_for_update().get(pk=settings.pk)
        access_ids = [pk for kind, pk in winners if kind == "access_log"]
        usage_ids = [pk for kind, pk in winners if kind == "token_usage"]
        existing = SecurityIncidentEvidence.objects.filter(
            Q(access_log_id__in=access_ids) | Q(token_usage_id__in=usage_ids)
        ).values_list("access_log_id", "token_usage_id")
        attached = {("access_log", access_id) if access_id else ("token_usage", usage_id)
                    for access_id, usage_id in existing}
        result.skipped_evidence_count = len(attached)
        pending = sorted(((kind, pk, row, match) for (kind, pk), (row, match) in winners.items()
                          if (kind, pk) not in attached),
                         key=lambda item: (_observed(item[0], item[2]), item[0], item[1]))
        candidate_windows = {}
        for kind, _, row, match in pending:
            fingerprint = _fingerprint(row.entity_id, match)
            observed = _observed(kind, row)
            first, last = candidate_windows.get(fingerprint, (observed, observed))
            candidate_windows[fingerprint] = min(first, observed), max(last, observed)
        candidates_by_fingerprint = {}
        touched = {}
        evidence = []
        for kind, pk, row, match in pending:
            observed = _observed(kind, row)
            fingerprint = _fingerprint(row.entity_id, match)
            if fingerprint not in candidates_by_fingerprint:
                first, last = candidate_windows[fingerprint]
                candidates_by_fingerprint[fingerprint] = list(SecurityIncident.objects.filter(
                    fingerprint=fingerprint, last_seen_at__gte=first - JOIN_WINDOW,
                    last_seen_at__lte=last + JOIN_WINDOW,
                ))
            candidates = candidates_by_fingerprint[fingerprint]
            # Revalidate every candidate as chronological evidence advances the join window.
            incident = max((candidate for candidate in candidates
                            if observed - JOIN_WINDOW <= candidate.last_seen_at <= observed + JOIN_WINDOW),
                           key=lambda candidate: (candidate.last_seen_at, candidate.pk), default=None)
            if incident is None:
                incident = SecurityIncident.objects.create(
                    entity_id=row.entity_id, category=match.category, severity=match.severity,
                    confidence_score=match.confidence, source_ip=match.source_ip,
                    rule_code=match.rule_code, target_family=match.target_family,
                    fingerprint=fingerprint, first_seen_at=observed, last_seen_at=observed,
                )
                candidates.append(incident)
                result.created_ids.append(incident.pk)
            elif incident.pk not in touched and incident.pk not in result.created_ids:
                result.updated_ids.append(incident.pk)
            incident.last_seen_at = max(incident.last_seen_at, observed)
            touched[incident.pk] = incident
            evidence.append(SecurityIncidentEvidence(
                incident=incident, **{kind + "_id": pk}, observed_at=observed,
                reason=match.reason, payload=_payload(match, observed),
            ))
        SecurityIncidentEvidence.objects.bulk_create(evidence)
        for incident in touched.values():
            aggregate = incident.evidence.aggregate(
                count=Count("pk"), first=Min("observed_at"), last=Max("observed_at"),
                severity=Max(Case(*(When(payload__severity=severity, then=Value(rank))
                                    for severity, rank in SEVERITY_RANK.items()),
                                  default=Value(0), output_field=IntegerField())),
                confidence=Max(Cast("payload__confidence", FloatField())),
            )
            incident.request_count = aggregate["count"]
            incident.first_seen_at = aggregate["first"]
            incident.last_seen_at = aggregate["last"]
            incident.severity = SEVERITY_LEVELS[aggregate["severity"]]
            incident.confidence_score = aggregate["confidence"]
            incident.latest_evidence = incident.evidence.order_by("-observed_at", "-pk").values_list("payload", flat=True).first()
            incident.save(update_fields=("request_count", "first_seen_at", "last_seen_at", "severity",
                                         "confidence_score", "latest_evidence", "updated_at"))
            publish_security_event(
                incident.entity_id,
                "incident.created" if incident.pk in result.created_ids else "incident.updated",
                {"incident_id": incident.pk, "category": incident.category,
                 "severity": incident.severity, "request_count": incident.request_count},
            )
        result.qualifying_ids = sorted(touched)
    return result


def load_access_log_correlation_context(entity, inserted_ids, *, now):
    """Load only each newly observed source's five-minute correlation neighborhood."""
    bounds = NginxAccessLog.objects.filter(
        entity=entity, pk__in=inserted_ids,
        timestamp__gte=now - timedelta(minutes=WINDOW_MINUTES), timestamp__lte=now,
    ).values("ip_address").annotate(first=Min("timestamp"), last=Max("timestamp"))
    neighborhoods = Q(pk__in=[])
    for bound in bounds:
        neighborhoods |= Q(ip_address=bound["ip_address"],
                           timestamp__gte=bound["first"] - CLASSIFIER_LOOKBACK,
                           timestamp__lte=bound["last"])
    return list(NginxAccessLog.objects.filter(neighborhoods, entity=entity).order_by("timestamp", "pk"))


def _access_classifier_windows(access, inserted_ids):
    """Yield bounded per-source windows that cover every newly inserted row."""
    rows_by_source = defaultdict(list)
    inserted_by_source = defaultdict(list)
    for row in access.values():
        source = (row.entity_id, str(row.ip_address))
        rows_by_source[source].append(row)
        if row.pk in inserted_ids:
            inserted_by_source[source].append(row)

    horizon_step = timedelta(seconds=DENIAL_WINDOW_SECONDS)
    for source in sorted(inserted_by_source, key=lambda value: (value[0], value[1])):
        rows = sorted(rows_by_source[source], key=lambda row: (row.timestamp, row.pk))
        observed = [(row.timestamp, row.pk) for row in rows]
        inserted = sorted(
            inserted_by_source[source], key=lambda row: (row.timestamp, row.pk)
        )
        index = 0
        while index < len(inserted):
            last = index
            maximum_horizon = inserted[index].timestamp + horizon_step
            while (
                last + 1 < len(inserted)
                and inserted[last + 1].timestamp <= maximum_horizon
            ):
                last += 1
            horizon = inserted[last].timestamp
            left = bisect_left(observed, (horizon - CLASSIFIER_LOOKBACK, -1))
            right = bisect_right(observed, (horizon, 2**63 - 1))
            yield rows[left:right], horizon
            index = last + 1


def process_security_evidence(entity, *, access_logs=(), token_usages=(), now=None,
                              inserted_access_log_ids=None) -> IncidentProcessingResult:
    now = now or timezone.now()
    if inserted_access_log_ids is not None:
        inserted_access_log_ids = set(inserted_access_log_ids)
        access_logs = load_access_log_correlation_context(entity, inserted_access_log_ids, now=now)
    access, usages = _prepare_sources(entity, access_logs, token_usages)
    winners = {}
    if inserted_access_log_ids is None:
        classifier_windows = ((access.values(), now),)
    else:
        classifier_windows = _access_classifier_windows(access, inserted_access_log_ids)
    for classifier_rows, horizon in classifier_windows:
        matches = classify_access_logs(classifier_rows, now=horizon)
        if inserted_access_log_ids is not None:
            # Context supports new detections, never independently replays old campaigns.
            matches = [match for match in matches if inserted_access_log_ids.intersection(match.access_log_ids)]
        _assign_matches(access, usages, matches, winners)
    _assign_matches(access, usages, classify_token_denials(usages.values(), now=now), winners)
    return _persist_assignments(entity, winners)


def _pages(queryset, timestamp_field, batch_size):
    cursor = None
    while True:
        page_query = queryset
        if cursor:
            observed, pk = cursor
            page_query = page_query.filter(Q(**{timestamp_field + "__gt": observed}) |
                                          Q(**{timestamp_field: observed, "pk__gt": pk}))
        page = list(page_query.order_by(timestamp_field, "pk")[:batch_size])
        if not page:
            return
        yield page
        cursor = getattr(page[-1], timestamp_field), page[-1].pk


def _backfill(entity, *, since, batch_size, now, dry_run=False):
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    totals = {"created": 0, "updated": 0, "qualifying": 0, "skipped": 0}
    created, updated, qualifying = set(), set(), set()
    dry_count = 0
    sources = (
        (NginxAccessLog.objects.filter(entity=entity, timestamp__gte=since, timestamp__lte=now), "timestamp", "access_log"),
        (LogCollectorApiTokenUsage.objects.filter(Q(entity=entity) | Q(entity__isnull=True),
                                                  created_at__gte=since, created_at__lte=now), "created_at", "token_usage"),
    )
    for queryset, timestamp_field, kind in sources:
        context = []
        winners = {}

        def finalize(ready):
            nonlocal dry_count
            if dry_run:
                dry_count += len(ready)
                return
            # Both live processing and replay use the same transactional assignment service.
            result = _persist_assignments(entity, ready)
            created.update(result.created_ids)
            updated.update(result.updated_ids)
            qualifying.update(result.qualifying_ids)
            totals["skipped"] += result.skipped_evidence_count

        for page in _pages(queryset, timestamp_field, batch_size):
            context.extend(page)
            access, usages = _prepare_sources(entity, context if kind == "access_log" else (),
                                              context if kind == "token_usage" else ())
            # Evaluate each historical horizon so thresholds do not depend on page boundaries.
            for horizon in sorted({getattr(row, timestamp_field) for row in page}):
                matches = classify_access_logs(access.values(), now=horizon) + classify_token_denials(usages.values(), now=horizon)
                _assign_matches(access, usages, matches, winners)
            cutoff = getattr(page[-1], timestamp_field) - CLASSIFIER_LOOKBACK
            # Wait out the correlation window before committing a weaker early match.
            ready = {key: value for key, value in winners.items() if _observed(key[0], value[0]) < cutoff}
            finalize(ready)
            winners = {key: value for key, value in winners.items() if key not in ready}
            context = [row for row in context if getattr(row, timestamp_field) >= cutoff]
        finalize(winners)
    totals.update(created=len(created), updated=len(updated - created), qualifying=dry_count if dry_run else len(qualifying))
    return totals


def backfill_entity_incidents(entity, *, since, batch_size=1000, now=None) -> dict:
    return _backfill(entity, since=since, batch_size=batch_size, now=now or timezone.now())
