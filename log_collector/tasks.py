"""Bounded security collection and deployment-wide block maintenance."""

import logging
from datetime import timedelta
from uuid import uuid4

from celery import shared_task
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from log_collector.integrations import send_mobile_sms
from log_collector.models import (
    LogCollectorApiTokenUsage,
    LogCollectorEntity,
    NginxAccessLog,
    SecurityIncident,
    SecurityIncidentSMSAlert,
    SecurityIncidentSMSDelivery,
)
from log_collector.services.blocking import expire_blocks, retry_pending_nginx_actions
from log_collector.services.health import probe_entity_health_status, save_entity_health_status
from log_collector.services.incidents import IncidentProcessingResult, process_security_evidence
from log_collector.services.response import reconcile_recent_security_incidents, respond_to_incidents
from log_collector.services.security import DENIAL_WINDOW_SECONDS, WINDOW_MINUTES
from log_collector.services.security_sms import (
    SECURITY_SMS_MESSAGE,
    create_security_sms_alert,
    is_qualifying_security_sms_incident,
    refresh_security_sms_alert_status,
)
from log_collector.services.sync import sync_entity_access_logs


logger = logging.getLogger(__name__)
TOKEN_USAGE_BATCH_SIZE = 5000
BLOCK_BATCH_SIZE = 100


@shared_task(queue="default", soft_time_limit=25, time_limit=30)
def refresh_entity_health_statuses() -> dict:
    entity_ids = list(
        LogCollectorEntity.objects.filter(
            is_active=True,
            entity_type=LogCollectorEntity.EntityType.INTEGRATION,
            api_base_url__gt="",
            remote_api_key__gt="",
        ).values_list("pk", flat=True)
    )
    for entity_id in entity_ids:
        refresh_entity_health_status.delay(entity_id)
    return {"queued": len(entity_ids)}


@shared_task(queue="default", soft_time_limit=55, time_limit=60)
def refresh_entity_health_status(entity_id: int) -> dict:
    entity = LogCollectorEntity.objects.filter(pk=entity_id, is_active=True).first()
    if entity is None:
        return {"status": "not_found"}
    lock_key = f"log_collector:health-refresh-lock:{entity_id}"
    lock_value = uuid4().hex
    try:
        lock_acquired = cache.add(lock_key, lock_value, timeout=75)
    except Exception:
        lock_acquired = None
    if lock_acquired is False:
        return {"status": "in_progress"}

    checked_at = timezone.now()
    try:
        try:
            result = probe_entity_health_status(entity)
        except Exception:
            logger.exception("Remote health refresh failed. entity_id=%s", entity_id)
            result = {
                "status": "down",
                "label": "Down",
                "detail": "Health check failed",
            }
        saved = save_entity_health_status(entity_id, result, checked_at=checked_at)
        return {"status": result["status"], "saved": saved}
    finally:
        if lock_acquired:
            try:
                if cache.get(lock_key) == lock_value:
                    cache.delete(lock_key)
            except Exception:
                pass


def _log_failure(operation, exception):
    # Exception text/tracebacks may contain filesystem data, request values or keys.
    logger.error("Security %s failed (%s)", operation, type(exception).__name__)


def _chunks(values, size):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def _sms_chunk_size():
    return min(
        max(int(getattr(settings, "LOG_COLLECTOR_SECURITY_SMS_CHUNK_SIZE", 1000)), 1),
        1000,
    )


def _queue_delivery_ids(alert, delivery_ids):
    if not delivery_ids:
        refresh_security_sms_alert_status(alert.pk)
        return 0
    alert.status = SecurityIncidentSMSAlert.Status.DISPATCHING
    alert.dispatch_queued_at = timezone.now()
    alert.save(update_fields=("status", "dispatch_queued_at", "updated_at"))
    for delivery_chunk in _chunks(delivery_ids, _sms_chunk_size()):
        send_security_incident_sms_chunk.delay(alert.pk, delivery_chunk)
    return len(delivery_ids)


@shared_task(queue="sms", max_retries=0)
def queue_security_incident_sms_alert(incident_id):
    incident = (
        SecurityIncident.objects.select_related("entity")
        .filter(pk=incident_id)
        .first()
    )
    if incident is None:
        return {"status": "not_found", "delivery_count": 0}
    if not getattr(settings, "LOG_COLLECTOR_SECURITY_SMS_ENABLED", False):
        return {"status": "disabled", "delivery_count": 0}
    if not is_qualifying_security_sms_incident(incident):
        return {"status": "ineligible", "delivery_count": 0}

    alert, _ = create_security_sms_alert(incident)
    if alert.status == SecurityIncidentSMSAlert.Status.NO_RECIPIENTS:
        return {"status": "no_recipients", "delivery_count": 0}
    delivery_ids = list(
        alert.deliveries.filter(
            status=SecurityIncidentSMSDelivery.Status.PENDING
        ).values_list("pk", flat=True)
    )
    count = _queue_delivery_ids(alert, delivery_ids)
    return {"status": "queued" if count else "already_dispatched", "delivery_count": count}


@shared_task(queue="sms", max_retries=0)
def send_security_incident_sms_chunk(alert_id, delivery_ids):
    alert = SecurityIncidentSMSAlert.objects.filter(pk=alert_id).first()
    if alert is None:
        return {"status": "not_found", "sent": 0, "failed": 0}

    sent = 0
    failed = 0
    for delivery_id in list(delivery_ids)[:1000]:
        with transaction.atomic():
            delivery = (
                SecurityIncidentSMSDelivery.objects.select_for_update()
                .filter(pk=delivery_id, alert=alert)
                .first()
            )
            if delivery is None or delivery.status not in {
                SecurityIncidentSMSDelivery.Status.PENDING,
                SecurityIncidentSMSDelivery.Status.FAILED,
            }:
                continue
            delivery.status = SecurityIncidentSMSDelivery.Status.SENDING
            delivery.last_error = ""
            delivery.save(update_fields=("status", "last_error"))
            phone_number = delivery.phone_number

        try:
            send_mobile_sms(
                mobile_number=phone_number,
                message=SECURITY_SMS_MESSAGE,
                context={
                    "purpose": "log_collector_security_alert",
                    "alert_id": alert.pk,
                    "delivery_id": delivery_id,
                },
            )
        except Exception as exc:
            logger.exception(
                "Security SMS delivery failed. alert_id=%s delivery_id=%s",
                alert.pk,
                delivery_id,
            )
            SecurityIncidentSMSDelivery.objects.filter(pk=delivery_id).update(
                status=SecurityIncidentSMSDelivery.Status.FAILED,
                last_error=str(exc)[:2000],
            )
            failed += 1
        else:
            SecurityIncidentSMSDelivery.objects.filter(pk=delivery_id).update(
                status=SecurityIncidentSMSDelivery.Status.SENT,
                sent_at=timezone.now(),
                last_error="",
            )
            sent += 1

    refresh_security_sms_alert_status(alert.pk)
    return {"status": "processed", "sent": sent, "failed": failed}


@shared_task(queue="sms", max_retries=0)
def retry_security_incident_sms_alert(alert_id):
    alert = SecurityIncidentSMSAlert.objects.filter(pk=alert_id).first()
    if alert is None:
        return {"status": "not_found", "delivery_count": 0}
    delivery_ids = list(
        alert.deliveries.filter(
            status__in=(
                SecurityIncidentSMSDelivery.Status.PENDING,
                SecurityIncidentSMSDelivery.Status.FAILED,
            )
        )
        .order_by("pk")
        .values_list("pk", flat=True)
    )
    count = _queue_delivery_ids(alert, delivery_ids)
    return {"status": "queued" if count else "nothing_to_retry", "delivery_count": count}


def _enqueue_created_incidents(created_ids):
    for incident_id in created_ids:
        transaction.on_commit(
            lambda incident_id=incident_id: queue_security_incident_sms_alert.delay(
                incident_id
            )
        )


def process_synced_security(entity, sync_result, *, now=None, include_token_denials=False):
    if not isinstance(sync_result, dict):
        return IncidentProcessingResult()
    inserted_ids = tuple(sync_result.get("inserted_ids") or ())
    token_usages = ()
    if include_token_denials:
        now = now or timezone.now()
        token_usages = LogCollectorApiTokenUsage.objects.filter(
            entity=entity,
            outcome="denied",
            created_at__gte=now - timedelta(seconds=DENIAL_WINDOW_SECONDS),
            security_evidence__isnull=True,
        )
    result = process_security_evidence(
        entity,
        inserted_access_log_ids=inserted_ids,
        token_usages=token_usages,
        now=now,
    )
    _enqueue_created_incidents(result.created_ids)
    respond_to_incidents(result.qualifying_ids, now=now, defer_edge=True)
    return result


@shared_task(queue="default", soft_time_limit=25, time_limit=30)
def collect_analyze_and_respond() -> dict:
    counts = {"imported": 0, "access_logs_processed": 0, "token_usages_processed": 0,
              "incidents_created": 0, "incidents_updated": 0, "incidents_qualifying": 0,
              "incidents_reconciled": 0, "blocks_created": 0, "exempt": 0, "errors": 0}
    try:
        entity = LogCollectorEntity.get_hosting_entity()
        # Cursor advancement and incident evidence commit together. A failed or
        # interrupted classification leaves the same file rows for the next poll.
        with transaction.atomic():
            imported = sync_entity_access_logs(entity, process_security=False)
            now = timezone.now()
            access = list(NginxAccessLog.objects.filter(
                entity=entity, pk__in=imported["inserted_ids"],
                timestamp__gte=now - timedelta(minutes=WINDOW_MINUTES), timestamp__lte=now,
            ).order_by("timestamp", "pk"))
            usages = list(LogCollectorApiTokenUsage.objects.filter(
                security_evidence__isnull=True, outcome="denied",
                created_at__gte=now - timedelta(seconds=DENIAL_WINDOW_SECONDS), created_at__lte=now,
            ).order_by("created_at", "pk")[:TOKEN_USAGE_BATCH_SIZE])
            result = process_security_evidence(entity, inserted_access_log_ids=[row.pk for row in access],
                                               token_usages=usages, now=now)
        counts.update(imported=imported["imported"], access_logs_processed=len(access),
                      token_usages_processed=len(usages), incidents_created=len(result.created_ids),
                      incidents_updated=len(result.updated_ids), incidents_qualifying=len(result.qualifying_ids))
        counts.update(
            created_incident_count=len(result.created_ids),
            created_incident_ids=list(result.created_ids),
            updated_incident_count=len(result.updated_ids),
        )
        _enqueue_created_incidents(result.created_ids)
        # Helpers run only after the ingestion/evidence transaction has committed.
        counts.update(respond_to_incidents(result.qualifying_ids, now=now))
        recovered = reconcile_recent_security_incidents(now=now, limit=BLOCK_BATCH_SIZE,
                                                       exclude_ids=result.qualifying_ids)
        for key, value in recovered.items():
            counts[key] += value
    except Exception as exception:
        _log_failure("collection", exception)
        counts["errors"] += 1
    return counts


@shared_task(queue="default", soft_time_limit=25, time_limit=30)
def expire_security_blocks() -> dict:
    try:
        return {"expired": expire_blocks(limit=BLOCK_BATCH_SIZE), "errors": 0}
    except Exception as exception:
        _log_failure("expiry", exception)
        return {"expired": 0, "errors": 1}


@shared_task(queue="default", soft_time_limit=25, time_limit=30)
def retry_security_edge_actions() -> dict:
    try:
        return {"retried": retry_pending_nginx_actions(limit=BLOCK_BATCH_SIZE), "errors": 0}
    except Exception as exception:
        _log_failure("edge retry", exception)
        return {"retried": 0, "errors": 1}
