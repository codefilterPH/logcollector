from pathlib import Path
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

from log_collector.models import (
    LogCollectorAuditEvent,
    LogCollectorFileCursor,
    LogCollectorSettings,
    NginxAccessLog,
)
from log_collector.services.nginx import parse_nginx_line
from log_collector.services.response import respond_to_security_evidence


@transaction.atomic
def sync_entity_access_logs(entity, *, process_security=True):
    """Read only unconsumed local log lines while holding a per-file cursor lock."""
    if not entity.is_hosting or not entity.is_active or not entity.access_logs_enabled:
        return {"imported": 0, "inserted_ids": [], "skipped": True}
    settings = LogCollectorSettings.for_entity(entity)
    now = timezone.now()
    imported = 0
    inserted_ids = []
    for source_path in settings.nginx_access_log_paths:
        path = Path(source_path)
        if not path.is_file():
            continue
        with transaction.atomic():
            cursor, _ = LogCollectorFileCursor.objects.select_for_update().get_or_create(
                entity=entity, source_path=str(path)
            )
            if (
                cursor.last_synced_at
                and (now - cursor.last_synced_at).total_seconds() < settings.sync_cooldown_seconds
            ):
                continue
            file_size = path.stat().st_size
            if file_size < cursor.offset:
                cursor.offset = 0
            rows = []
            with path.open("r", encoding="utf-8", errors="replace") as source:
                source.seek(cursor.offset)
                for _ in range(settings.max_lines_per_sync):
                    line = source.readline()
                    if not line:
                        break
                    parsed = parse_nginx_line(line)
                    if parsed:
                        rows.append(
                            NginxAccessLog(
                                entity=entity,
                                timestamp=parsed.timestamp,
                                ip_address=parsed.ip_address,
                                method=parsed.method,
                                path=parsed.path,
                                query_string=parsed.query_string,
                                protocol=parsed.protocol,
                                status_code=parsed.status_code,
                                bytes_sent=parsed.bytes_sent,
                                referrer=parsed.referrer,
                                user_agent=parsed.user_agent,
                                source_path=str(path),
                                raw_line_hash=parsed.raw_line_hash,
                            )
                        )
                cursor.offset = source.tell()
            for row in rows:
                try:
                    with transaction.atomic():
                        row.save(force_insert=True)
                    imported += 1
                    inserted_ids.append(row.pk)
                except IntegrityError:
                    continue
            cursor.observed_size = file_size
            cursor.last_synced_at = now
            cursor.save(update_fields=("offset", "observed_size", "last_synced_at"))
    if imported:
        LogCollectorAuditEvent.objects.create(
            entity=entity,
            event_type=LogCollectorAuditEvent.EventType.SYNC,
            path="log-sync",
            details={"imported": imported},
        )
        if process_security:
            respond_to_security_evidence(
                entity, inserted_access_log_ids=inserted_ids,
                now=now, defer_edge=True,
            )
    return {"imported": imported, "inserted_ids": inserted_ids, "skipped": False}


def purge_expired_access_logs(entity):
    settings = LogCollectorSettings.for_entity(entity)
    if not settings:
        return 0
    cutoff = timezone.now() - timedelta(days=settings.retention_days)
    deleted, _ = NginxAccessLog.objects.filter(
        entity=entity, timestamp__lt=cutoff, security_evidence__isnull=True
    ).delete()
    return deleted
