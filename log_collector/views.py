import csv
import json
import logging
import re
from collections.abc import Mapping
from datetime import datetime, time, timedelta
from ipaddress import ip_address as parse_ip_address
from urllib.parse import parse_qsl

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Case, Count, IntegerField, Q, Value, When
from django.db.models.functions import TruncDate, TruncMinute
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.html import strip_tags
from django.views.decorators.http import require_http_methods, require_POST
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from crowdsec_integration.models import CrowdSecConnection
from crowdsec_integration.services import CrowdSecError, encrypt_password, request as crowdsec_request, validate_connection
from log_collector.integrations import contain_user_account, optional_model

from log_collector.forms import (
    EntityForm,
    HostingSettingsForm,
    IntegratedDomainForm,
    LogCollectorApiTokenForm,
)
from log_collector.models import (
    BlockedIPAddress,
    IPBlockAuditEvent,
    LogCollectorApiToken,
    LogCollectorAuditEvent,
    LogCollectorEntity,
    LogCollectorIntegratedDomain,
    LogCollectorSettings,
    NginxAccessLog,
    SecurityIncident,
    SecurityIncidentEvidence,
)
from log_collector.permissions import LogCollectorApiTokenPermission, get_client_ip
from log_collector.services.blocking import block_ip, unblock_ip
from log_collector.services.client_ip import (
    is_configured_trusted_security_ip,
    is_trusted_security_ip,
)
from log_collector.services.trusted_ips import (
    active_white_flag_ips,
    is_white_flagged_ip,
    normalize_ip,
)
from log_collector.services.remote import (
    RemoteCollectorError,
    fetch_remote_json,
    fetch_remote_response,
)
from log_collector.services.security import analyze_security
from log_collector.services.sync import sync_entity_access_logs as sync_access_logs_only
from log_collector.tasks import process_synced_security


DATA_CENTER_GROUP = "DATA_CENTER"
MAX_DASHBOARD_PAGE_SIZE = 1000
MAX_URL_USERNAME_LENGTH = 150
URL_USERNAME_KEYS = frozenset({"username", "user", "login", "email"})
logger = logging.getLogger(__name__)


def sync_entity_access_logs(entity):
    """Import logs and run the bounded live security fallback for new rows."""
    result = sync_access_logs_only(entity, process_security=False)
    process_synced_security(entity, result)
    return result


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


def entity_health_status(entity):
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
            "detail": "Remote URL or API token is missing",
        }
    for resource, params, failure_detail in remote_health_checks(entity):
        try:
            if params is None:
                fetch_remote_json(entity, resource)
            else:
                fetch_remote_json(entity, resource, params=params)
        except RemoteCollectorError:
            return {
                "status": "down",
                "label": "Down",
                "detail": failure_detail,
            }
    return {
        "status": "online",
        "label": "Online",
        "detail": "All enabled APIs responding",
    }


def entity_endpoint_descriptors(request, entity, audit_events_enabled=False):
    """Return collector endpoint details using the entity's actual destination."""
    if entity.is_hosting:
        base = request.build_absolute_uri(
            reverse("log_collector:api_metrics", args=(entity.slug,))
        ).removesuffix("metrics/")
    elif entity.api_base_url:
        base = (
            f"{entity.api_base_url.rstrip('/')}/log-collector/api/entities/"
            f"{entity.remote_entity_slug}/"
        )
    else:
        base = ""

    endpoint_definitions = (
        ("metrics", "Metrics", "metrics/", entity.enable_api_endpoint),
        ("access_logs", "Access Logs", "access-logs/", entity.enable_api_endpoint),
        ("geolocation", "Geolocation", "geolocation/", entity.geolocation_enabled),
        ("user_sessions", "User Sessions", "user-sessions/", entity.user_sessions_enabled),
        ("security_summary", "Security Summary", "security-summary/", entity.enable_api_endpoint),
        ("audit_events", "Audit Events", "audit-events/", audit_events_enabled),
    )
    return [
        {
            "key": key,
            "label": label,
            "method": "GET",
            "url": f"{base}{resource}" if base else "",
            "enabled": enabled,
        }
        for key, label, resource, enabled in endpoint_definitions
    ]


def is_data_center_user(user):
    return user.is_authenticated and user.groups.filter(name=DATA_CENTER_GROUP).exists()


def app_appearance():
    hosting = LogCollectorEntity.get_hosting_entity()
    appearance = LogCollectorSettings.for_entity(hosting)
    return {"app_name": appearance.app_name, "app_theme": appearance.theme}


def audit_event(request, event_type, entity=None, outcome="success", **details):
    api_key = getattr(request, "log_collector_api_token", None)
    LogCollectorAuditEvent.objects.create(
        entity=entity,
        user=request.user if getattr(request.user, "is_authenticated", False) else None,
        api_key_name=getattr(api_key, "name", ""),
        event_type=event_type,
        path=request.path[:500],
        method=request.method,
        outcome=outcome,
        ip_address=get_client_ip(request),
        details=details,
    )


def require_data_center(request, entity=None, superuser=False):
    allowed = is_data_center_user(request.user) and (not superuser or request.user.is_superuser)
    if not allowed:
        audit_event(request, LogCollectorAuditEvent.EventType.DENIED, entity, outcome="denied")
        return False
    return True


def access_log_request_context(method):
    normalized_method = (method or "").upper()
    if normalized_method == "OPTIONS":
        return {
            "kind": "capability_probe",
            "label": "Capability probe",
            "tone": "neutral",
            "explanation": (
                "Server response only; authentication and action execution are not established."
            ),
        }
    if normalized_method in {"GET", "HEAD"}:
        return {
            "kind": "read_request",
            "label": "Read request",
            "tone": "standard",
            "explanation": "The access log does not identify an authenticated user.",
        }
    if normalized_method in {"POST", "PUT", "PATCH", "DELETE"}:
        return {
            "kind": "state_change_request",
            "label": "State-change request",
            "tone": "standard",
            "explanation": "The access log does not identify an authenticated user.",
        }
    return {
        "kind": "other_request",
        "label": "Other request",
        "tone": "standard",
        "explanation": "The access log does not identify an authenticated user.",
    }


def access_log_url_username(query_string):
    """Return an explicit, bounded identity hint from a request query string."""
    for key, value in parse_qsl(
        (query_string or "")[:8192], keep_blank_values=True
    ):
        cleaned = value.strip()
        if key.casefold() in URL_USERNAME_KEYS and cleaned:
            return cleaned[:MAX_URL_USERNAME_LENGTH]
    return ""


def report_datetime(value):
    if not value:
        return ""
    if isinstance(value, str):
        from django.utils.dateparse import parse_datetime

        value = parse_datetime(value)
    if not value:
        return ""
    if timezone.is_naive(value):
        value = timezone.make_aware(value)
    return timezone.localtime(value).strftime("%b %d, %Y, %I:%M:%S %p")


def security_blocks_by_ip(ip_addresses):
    blocks = {}
    for block in BlockedIPAddress.objects.filter(
        ip_address__in=set(ip_addresses)
    ).order_by("-desired_active", "-created_at", "-id"):
        blocks.setdefault(block.ip_address, block)
    return blocks


def serialize_log(row, security_alert=None, *, block=None, include_block_state=False):
    payload = {
        "id": row.id,
        "timestamp": row.timestamp.isoformat(),
        "ip_address": row.ip_address,
        "method": row.method,
        "path": row.path,
        "query_string": row.query_string,
        "url_username": access_log_url_username(row.query_string),
        "status_code": row.status_code,
        "request_context": access_log_request_context(row.method),
        "bytes_sent": row.bytes_sent,
        "referrer": row.referrer,
        "user_agent": row.user_agent,
        "security_alert": security_alert,
    }
    if include_block_state:
        state = serialize_security_block(block) if block else {
            "django_state": "inactive",
            "nginx_state": "not_configured",
            "block_id": None,
            "expires_at": None,
        }
        payload.update({
            key: state[key]
            for key in ("django_state", "nginx_state", "block_id", "expires_at")
        })
        payload["is_trusted_ip"] = is_trusted_security_ip(row.ip_address)
        payload["is_white_flagged"] = is_white_flagged_ip(row.ip_address)
    return payload


def serialize_ip_threat(incident):
    if incident is None:
        return None
    reasons = incident.latest_evidence.get("reasons", [])
    if not isinstance(reasons, list):
        reasons = []
    return {
        "category": incident.category,
        "severity": incident.severity,
        "incident_id": incident.pk,
        "last_seen_at": incident.last_seen_at.isoformat(),
        "reasons": [str(reason) for reason in reasons if reason],
    }


def qualifying_ip_threats(entity, ip_addresses, *, now=None):
    now = now or timezone.now()
    trusted_ips = {
        ip for ip in set(ip_addresses) if is_trusted_security_ip(ip)
    }
    candidate_ips = set(ip_addresses) - trusted_ips
    if not candidate_ips:
        return {}
    severity_rank = {
        SecurityIncident.Severity.CRITICAL: 2,
        SecurityIncident.Severity.HIGH: 1,
    }
    incidents = SecurityIncident.objects.filter(
        entity=entity,
        source_ip__in=candidate_ips,
        category__in=(
            SecurityIncident.Category.MALICIOUS,
            SecurityIncident.Category.UNAUTHORIZED,
        ),
        severity__in=severity_rank,
        last_seen_at__gte=now - timedelta(minutes=15),
    ).order_by("-last_seen_at", "-id")
    threats = {}
    for incident in incidents:
        current = threats.get(incident.source_ip)
        if current is None or severity_rank[incident.severity] > severity_rank[current.severity]:
            threats[incident.source_ip] = incident
    return threats


def qualifying_ip_threat(entity, ip_address, *, now=None):
    return qualifying_ip_threats(entity, [ip_address], now=now).get(ip_address)


def serialize_user_session(
    row, security_alert=None, *, ip_threat=None, block=None
):
    payload = {
        "id": row.pk,
        "session_key": row.session_key,
        "user": row.user.get_username(),
        "ip_address": row.ip,
        "created_at": row.created_at.isoformat(),
        "last_seen_at": row.last_seen_at.isoformat(),
        "user_agent": row.user_agent,
        "security_alert": security_alert,
        "ip_threat": serialize_ip_threat(ip_threat),
    }
    state = serialize_security_block(block) if block else {
        "django_state": "inactive",
        "nginx_state": "not_configured",
        "block_id": None,
        "expires_at": None,
    }
    payload.update({
        key: state[key]
        for key in ("django_state", "nginx_state", "block_id", "expires_at")
    })
    payload["is_trusted_ip"] = is_trusted_security_ip(row.ip)
    payload["is_white_flagged"] = is_white_flagged_ip(row.ip)
    return payload


def local_security_analysis(entity):
    """Return the current in-memory security assessment for a local entity."""
    cutoff = timezone.now() - timedelta(minutes=15)
    access_logs = entity.access_logs.filter(timestamp__gte=cutoff)
    user_sessions = ()
    if entity.user_sessions_enabled:
        session_model = optional_model("LOG_COLLECTOR_USER_SESSION_MODEL")
        if session_model is not None:
            user_sessions = session_model.objects.select_related("user").filter(last_seen_at__gte=cutoff)
    return analyze_security(access_logs=access_logs, user_sessions=user_sessions)


def local_security_summary(entity):
    summary = dict(local_security_analysis(entity).summary)
    incidents = visible_security_incidents(entity.security_incidents.all())
    active = BlockedIPAddress.objects.filter(desired_active=True, django_state="active").filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
    )
    summary.update(
        unauthorized_incident_count=sum(
            incident.category == "unauthorized" for incident in incidents
        ),
        malicious_incident_count=sum(
            incident.category == "malicious" for incident in incidents
        ),
        active_block_count=active.count(),
        critical_incident_count=sum(
            incident.severity == "critical" for incident in incidents
        ),
        edge_failure_count=BlockedIPAddress.objects.filter(nginx_state__in=("failed", "remove_failed")).count(),
    )
    return summary


def visible_security_incidents(incidents):
    """Keep historical trusted-source incidents out of current security views."""
    return [
        incident
        for incident in incidents
        if not is_trusted_security_ip(incident.source_ip)
    ]


def get_page_size(request):
    try:
        page_size = int(request.GET.get("page_size", 25))
    except (TypeError, ValueError):
        page_size = 25
    return min(max(page_size, 1), MAX_DASHBOARD_PAGE_SIZE)


def csv_response(filename, headers, rows):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    writer = csv.writer(response)
    writer.writerow(headers)
    for row in rows:
        writer.writerow(row)
    return response


def paginated_payload(request, queryset, serializer):
    page_size = get_page_size(request)
    page = Paginator(queryset, page_size).get_page(request.GET.get("page", 1))
    return {
        "count": page.paginator.count,
        "page": page.number,
        "page_size": page_size,
        "num_pages": page.paginator.num_pages,
        "results": [serializer(item) for item in page.object_list],
    }


@login_required
def log_collector_home(request):
    if not require_data_center(request):
        return HttpResponseForbidden()
    hosting = LogCollectorEntity.get_hosting_entity()
    if not hosting.is_active:
        return HttpResponseForbidden("The hosting entity is inactive.")
    return redirect(reverse("log_collector:entity_dashboard", args=(hosting.slug,)) + "?security=alerts")


@login_required
def entity_selection(request):
    if not require_data_center(request):
        return HttpResponseForbidden()
    hosting = LogCollectorEntity.get_hosting_entity()
    audit_event(request, LogCollectorAuditEvent.EventType.PAGE_VIEW, hosting)
    entities = [
        {"entity": entity, "health": entity_health_status(entity)}
        for entity in LogCollectorEntity.objects.filter(is_active=True)
    ]
    return render(
        request,
        "log_collector/entity_selection.html",
        {"entities": entities, **app_appearance()},
    )


@login_required
@require_http_methods(["GET", "POST"])
def entity_create(request):
    if not require_data_center(request, superuser=True):
        return HttpResponseForbidden()
    form = EntityForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        entity = form.save(commit=False)
        entity.entity_type = LogCollectorEntity.EntityType.INTEGRATION
        entity.save()
        return redirect("log_collector:entity_dashboard", slug=entity.slug)
    return render(
        request,
        "log_collector/entity_form.html",
        {"form": form, "creating": True, **app_appearance()},
    )


@login_required
def entity_dashboard(request, slug):
    entity = get_object_or_404(LogCollectorEntity, slug=slug, is_active=True)
    if not require_data_center(request, entity):
        return HttpResponseForbidden()
    if entity.is_hosting:
        sync_entity_access_logs(entity)
        security_summary = local_security_analysis(entity).summary
    else:
        security_summary = {
            "critical_alert_count": 0,
            "latest_alert_at": None,
            "window_minutes": 15,
            "alerts": [],
        }
    audit_event(request, LogCollectorAuditEvent.EventType.PAGE_VIEW, entity)
    return render(
        request,
        "log_collector/dashboard.html",
        {
            "entity": entity,
            "security_summary": security_summary,
            "can_manage_blocks": entity.is_hosting and is_data_center_user(request.user),
            "can_contain_users": entity.is_hosting and request.user.is_superuser,
            "can_white_flag": entity.is_hosting and request.user.is_superuser,
            "can_manage_crowdsec": entity.is_hosting and request.user.is_superuser,
            **app_appearance(),
        },
    )


@login_required
def security_report(request, slug):
    entity = get_object_or_404(LogCollectorEntity, slug=slug, is_active=True)
    if not require_data_center(request, entity, superuser=True):
        return HttpResponseForbidden()
    try:
        if entity.is_hosting:
            sync_entity_access_logs(entity)
            security_summary = local_security_analysis(entity).summary
            incidents = visible_security_incidents(
                entity.security_incidents.annotate(evidence_count=Count("evidence"))
                .order_by("-last_seen_at", "-id")
            )
            incident_count = len(incidents)
            blocks = {}
            for block in BlockedIPAddress.objects.filter(
                ip_address__in=[incident.source_ip for incident in incidents]
            ).order_by("-desired_active", "-created_at", "-id"):
                blocks.setdefault(block.ip_address, block)
            report_incidents = []
            for incident in incidents[:100]:
                evidence = list(
                    incident.evidence.select_related("access_log", "token_usage")
                    .order_by("-observed_at", "-id")[:100]
                )
                report_incidents.append({
                    **serialize_security_incident(incident, blocks),
                    "last_seen_display": report_datetime(incident.last_seen_at),
                    "url_username": next((
                        access_log_url_username(row.access_log.query_string)
                        for row in evidence
                        if row.access_log_id
                        and access_log_url_username(row.access_log.query_string)
                    ), ""),
                    "evidence_count": incident.evidence_count,
                    "evidence": [{
                        "id": row.pk, "observed_at": row.observed_at,
                        "reason": row.reason,
                        "source": "access_log" if row.access_log_id else "token_usage",
                        "method": (row.access_log or row.token_usage).method,
                        "status_code": (row.access_log or row.token_usage).status_code,
                        "target_family": row.payload.get("target_family", incident.target_family),
                    } for row in evidence],
                })
        else:
            security_summary = fetch_remote_json(entity, "security-summary/")
            grouped = fetch_remote_json(entity, "security-incidents/", params={"page_size": 100})
            incident_count = grouped["count"]
            report_incidents = []
            for incident in grouped["results"][:100]:
                evidence = fetch_remote_json(entity, f"security-incidents/{incident['id']}/evidence/")
                evidence_rows = evidence["results"][:100]
                report_incidents.append({
                    **incident,
                    "last_seen_display": report_datetime(incident.get("last_seen_at")),
                    "url_username": next((
                        access_log_url_username(row["access_log"].get("query_string", ""))
                        for row in reversed(evidence_rows)
                        if row.get("access_log")
                        and access_log_url_username(row["access_log"].get("query_string", ""))
                    ), ""),
                    "evidence_count": evidence["count"],
                    "evidence": [{
                        "id": row["id"], "observed_at": row["observed_at"],
                        "reason": row["reason"],
                        "source": "access_log" if row.get("access_log") else "token_usage",
                        "method": (row.get("access_log") or row.get("token_usage") or {}).get("method", ""),
                        "status_code": (row.get("access_log") or row.get("token_usage") or {}).get("status_code", ""),
                        "target_family": row.get("payload", {}).get("target_family", incident["target_family"]),
                    } for row in evidence_rows],
                })
    except RemoteCollectorError:
        return render(
            request,
            "log_collector/security_report.html",
            {
                "entity": entity,
                "security_summary": None,
                "generated_at": timezone.now(),
                "error": "The connected collector could not provide a current security report.",
                **app_appearance(),
            },
            status=502,
        )
    audit_event(request, LogCollectorAuditEvent.EventType.PAGE_VIEW, entity, report="security")
    return render(
        request,
        "log_collector/security_report.html",
        {
            "entity": entity,
            "security_summary": security_summary,
            "report_incidents": report_incidents,
            **app_appearance(),
            "incident_count": incident_count,
            "generated_at": timezone.now(),
            "error": None,
        },
    )


def management_action_response(request, ok, message, status=200, **payload):
    """Return JSON to enhanced management actions and PRG otherwise."""
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse({"ok": ok, "message": message, **payload}, status=status)
    (messages.success if ok else messages.error)(request, message)
    return redirect(request.path)


@login_required
@require_http_methods(["GET", "POST"])
def entity_manage(request, slug):
    entity = get_object_or_404(LogCollectorEntity, slug=slug)
    if not request.user.is_superuser:
        audit_event(request, LogCollectorAuditEvent.EventType.DENIED, entity, outcome="denied")
        return HttpResponseForbidden()
    entity_form = EntityForm(
        request.POST if request.POST.get("save_entity") else None,
        instance=entity,
        prefix="entity",
    )
    settings_form = None
    generated_token = None
    domain_form = IntegratedDomainForm(
        request.POST if request.POST.get("add_domain") else None,
        prefix="domain",
    )
    if entity.is_hosting:
        settings_form = HostingSettingsForm(
            request.POST if "save_settings" in request.POST else None,
            instance=LogCollectorSettings.for_entity(entity),
            prefix="settings",
        )
    token_form = LogCollectorApiTokenForm(prefix="token")
    crowdsec_connection = CrowdSecConnection.objects.filter(entity_id=entity.pk).first() if entity.is_hosting else None
    if request.method == "POST":
        if "save_crowdsec_connection" in request.POST:
            if not entity.is_hosting:
                return HttpResponseForbidden()
            api_url = (request.POST.get("crowdsec_api_url") or "").strip().rstrip("/")
            machine_id = (request.POST.get("crowdsec_machine_id") or "").strip()
            password = request.POST.get("crowdsec_password") or ""
            if not password and crowdsec_connection:
                from crowdsec_integration.services import _password
                try:
                    password = _password(crowdsec_connection)
                except CrowdSecError as exc:
                    messages.error(request, str(exc))
                    return redirect(request.path)
            if not api_url or len(api_url) > 500 or not machine_id or len(machine_id) > 255 or not password or len(password) > 1000:
                messages.error(request, "Enter the CrowdSec Local API URL, machine ID, and password.")
                return redirect(request.path)
            try:
                validate_connection(api_url, machine_id, password)
            except CrowdSecError as exc:
                messages.error(request, str(exc))
                return redirect(request.path)
            CrowdSecConnection.objects.update_or_create(
                entity_id=entity.pk,
                defaults={"api_url": api_url, "machine_id": machine_id, "encrypted_password": encrypt_password(password)},
            )
            audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="crowdsec-connection", action="saved")
            messages.success(request, "CrowdSec connection verified and saved.")
            return redirect(request.path)
        if "delete_crowdsec_connection" in request.POST and entity.is_hosting:
            CrowdSecConnection.objects.filter(entity_id=entity.pk).delete()
            audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="crowdsec-connection", action="removed")
            messages.success(request, "CrowdSec connection settings removed.")
            return redirect(request.path)
        if "test_connection" in request.POST:
            try:
                if entity.is_hosting:
                    sync_entity_access_logs(entity)
                    return management_action_response(
                        request, True, "Local collector is available."
                    )
                fetch_remote_json(entity, "metrics/")
            except RemoteCollectorError:
                return management_action_response(
                    request,
                    False,
                    "Connection failed. Check remote URL, entity slug, and API token.",
                    status=502,
                )
            return management_action_response(request, True, "Connection successful.")
        if "save_entity" in request.POST:
            if entity_form.is_valid():
                entity_form.save()
                return management_action_response(request, True, "Entity settings saved.")
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return management_action_response(
                    request,
                    False,
                    "Fix the highlighted entity settings before saving.",
                    status=400,
                    errors=entity_form.errors.get_json_data(),
                )
        if settings_form and "save_settings" in request.POST and settings_form.is_valid():
            settings_form.save()
            return redirect(request.path)
        if "add_domain" in request.POST and domain_form.is_valid():
            domain = domain_form.save(commit=False)
            domain.entity = entity
            domain.save()
            return redirect(request.path)
        if "create_token" in request.POST:
            token_form = LogCollectorApiTokenForm(request.POST, prefix="token")
            if token_form.is_valid():
                created_token, generated_token = token_form.save(
                    entity=entity, created_by=request.user
                )
                token_form = LogCollectorApiTokenForm(prefix="token")
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return management_action_response(
                        request,
                        True,
                        "Token created. Copy it now; it will not be shown again.",
                        raw_token=generated_token,
                        token_id=created_token.id,
                    )
            elif request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return management_action_response(
                    request,
                    False,
                    "Fix the token fields before creating it.",
                    status=400,
                    errors=token_form.errors.get_json_data(),
                )
        if "revoke_token" in request.POST:
            token = get_object_or_404(
                LogCollectorApiToken, entity=entity, pk=request.POST.get("token_id")
            )
            token.is_active = False
            token.save(update_fields=("is_active", "updated_at"))
            return management_action_response(request, True, "Token revoked.", token_id=token.id)
        if "rotate_token" in request.POST:
            token = get_object_or_404(
                LogCollectorApiToken, entity=entity, pk=request.POST.get("token_id")
            )
            token.is_active = False
            token.save(update_fields=("is_active", "updated_at"))
            rotated_token, generated_token = LogCollectorApiToken.create_token(
                entity=entity,
                name=token.name,
                created_by=request.user,
                expires_at=token.expires_at,
                allowed_ip_address=token.allowed_ip_address,
                allowed_origin_domain=token.allowed_origin_domain,
            )
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return management_action_response(
                    request,
                    True,
                    "Token rotated. Copy the new token now; it will not be shown again.",
                    raw_token=generated_token,
                    token_id=rotated_token.id,
                )
        if "delete_token" in request.POST:
            token = get_object_or_404(
                LogCollectorApiToken, entity=entity, pk=request.POST.get("token_id")
            )
            token_id = token.id
            token.delete()
            return management_action_response(request, True, "Token deleted.", token_id=token_id)
    audit_event(request, LogCollectorAuditEvent.EventType.TAB_LOAD, entity, tab="management")
    return render(
        request,
        "log_collector/entity_manage.html",
        {
            "entity": entity,
            "entity_form": entity_form,
            "settings_form": settings_form,
            **app_appearance(),
            "crowdsec_connection": crowdsec_connection,
            "domain_form": domain_form,
            "token_form": token_form,
            "generated_token": generated_token,
            "tokens": entity.api_tokens.annotate(usage_count=Count("usage_logs")),
            "recent_token_usage": Paginator(
                entity.api_token_usage.select_related("token"), 25
            ).get_page(request.GET.get("usage_page", 1)),
            "domains": Paginator(entity.integrated_domains.all(), 25).get_page(
                request.GET.get("domains_page", 1)
            ),
            "endpoints": entity_endpoint_descriptors(
                request, entity, audit_events_enabled=True
            ),
        },
    )


@login_required
@require_POST
def domain_delete(request, slug, domain_id):
    entity = get_object_or_404(LogCollectorEntity, slug=slug)
    if not require_data_center(request, entity, superuser=True):
        return HttpResponseForbidden()
    get_object_or_404(LogCollectorIntegratedDomain, entity=entity, pk=domain_id).delete()
    return redirect("log_collector:entity_manage", slug=slug)


@login_required
@require_POST
def entity_delete(request, slug):
    entity = get_object_or_404(LogCollectorEntity, slug=slug)
    if not require_data_center(request, entity, superuser=True):
        return HttpResponseForbidden()
    if entity.is_hosting:
        return HttpResponseForbidden("The hosting entity cannot be deleted.")
    entity.delete()
    return redirect("log_collector:entity_selection")


class EntityApiBase(APIView):
    permission_classes = [LogCollectorApiTokenPermission]
    allow_api_tokens = False

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        usage = getattr(request, "log_collector_token_usage", None)
        if usage is not None and usage.status_code is None:
            usage.status_code = response.status_code
            usage.save(update_fields=("status_code",))
        return response

    def get_entity(self, slug):
        return get_object_or_404(LogCollectorEntity, slug=slug, is_active=True)

    def authorize(self, request, entity, superuser=False, api_key_allowed=True):
        api_key = getattr(request, "log_collector_api_token", None)
        if api_key:
            if (
                not api_key_allowed
                or not entity.enable_api_endpoint
                or api_key.entity_id != entity.id
            ):
                audit_event(request, LogCollectorAuditEvent.EventType.DENIED, entity, outcome="denied")
                raise PermissionDenied("This API token is not authorized for this entity.")
            return
        if not require_data_center(request, entity, superuser=superuser):
            raise PermissionDenied("DATA_CENTER access is required.")

    def local_or_remote(self, entity, resource, params=None):
        if entity.is_hosting:
            return None
        return fetch_remote_json(entity, resource, params=params)

    def remote_csv_response(self, entity, resource, filename, params=None):
        if entity.is_hosting:
            return None
        remote = fetch_remote_response(entity, resource, params=params)
        response = HttpResponse(
            remote.content,
            content_type=remote.headers.get("Content-Type") or "text/csv",
        )
        response["Content-Disposition"] = remote.headers.get(
            "Content-Disposition"
        ) or f'attachment; filename="{filename}"'
        return response


def _ten_minute_activity_series(
    queryset, timestamp_field, *, window_start, window_end, tzinfo
):
    bucket_count = 24 * 6
    counts = [0] * bucket_count
    timestamp_range = {
        f"{timestamp_field}__gte": window_start,
        f"{timestamp_field}__lt": window_end,
    }
    minute_counts = (
        queryset.filter(**timestamp_range)
        .annotate(bucket_minute=TruncMinute(timestamp_field, tzinfo=tzinfo))
        .values("bucket_minute")
        .annotate(count=Count("pk"))
    )
    for row in minute_counts:
        minute = row["bucket_minute"]
        minute = (
            timezone.localtime(minute, tzinfo)
            if timezone.is_aware(minute)
            else timezone.make_aware(minute, tzinfo)
        )
        bucket_index = int((minute - window_start).total_seconds() // 600)
        if 0 <= bucket_index < bucket_count:
            counts[bucket_index] += row["count"]
    return [
        {
            "bucket_start": (window_start + timedelta(minutes=10 * index)).isoformat(),
            "count": counts[index],
        }
        for index in range(bucket_count)
    ]


class EntityMetricsApi(EntityApiBase):
    allow_api_tokens = True

    def get(self, request, slug):
        entity = self.get_entity(slug)
        self.authorize(request, entity)
        try:
            remote = self.local_or_remote(entity, "metrics/")
        except RemoteCollectorError as exc:
            return Response({"detail": str(exc)}, status=502)
        if remote is not None:
            audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="metrics")
            return Response(remote)
        sync_entity_access_logs(entity)
        logs = entity.access_logs
        today = timezone.localdate()
        first_day = today - timedelta(days=6)
        local_timezone = timezone.get_current_timezone()
        local_now = timezone.localtime(timezone.now(), local_timezone)
        activity_window_end = local_now.replace(
            minute=(local_now.minute // 10) * 10, second=0, microsecond=0
        )
        activity_window_start = activity_window_end - timedelta(minutes=24 * 60)
        first_day_start = timezone.make_aware(
            datetime.combine(first_day, time.min), local_timezone
        )
        tomorrow_start = timezone.make_aware(
            datetime.combine(today + timedelta(days=1), time.min), local_timezone
        )
        daily_counts = {
            row["day"]: row["count"]
            for row in (
                logs.filter(timestamp__gte=first_day_start, timestamp__lt=tomorrow_start)
                .annotate(day=TruncDate("timestamp", tzinfo=local_timezone))
                .values("day")
                .annotate(count=Count("id"))
            )
        }
        attack_activity = _ten_minute_activity_series(
            SecurityIncidentEvidence.objects.filter(incident__entity=entity),
            "observed_at",
            window_start=activity_window_start,
            window_end=activity_window_end,
            tzinfo=local_timezone,
        )
        automatic_ip_blocks = _ten_minute_activity_series(
            IPBlockAuditEvent.objects.filter(
                block__origin=BlockedIPAddress.Origin.AUTOMATIC,
                action=IPBlockAuditEvent.Action.APPLIED,
                previous_django_state=BlockedIPAddress.DjangoState.INACTIVE,
                new_django_state=BlockedIPAddress.DjangoState.ACTIVE,
            ),
            "timestamp",
            window_start=activity_window_start,
            window_end=activity_window_end,
            tzinfo=local_timezone,
        )
        payload = {
            "entity": {"name": entity.name, "slug": entity.slug, "type": entity.entity_type},
            "access_log_count": logs.count(),
        "requests_today": logs.filter(timestamp__date=timezone.now().date()).count(),
        "error_count": logs.filter(status_code__gte=400).count(),
        "unique_ips": logs.values("ip_address").distinct().count(),
            "daily_requests": [
                {
                    "date": (first_day + timedelta(days=offset)).isoformat(),
                    "count": daily_counts.get(first_day + timedelta(days=offset), 0),
                }
                for offset in range(7)
            ],
            "attack_activity_10m": attack_activity,
            "automatic_ip_blocks_10m": automatic_ip_blocks,
            "security_summary": local_security_summary(entity),
    }
        audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="metrics")
        return Response(payload)


class AccessLogsApi(EntityApiBase):
    allow_api_tokens = True

    def get(self, request, slug):
        entity = self.get_entity(slug)
        self.authorize(request, entity)
        try:
            if request.GET.get("export") == "csv":
                remote_csv = self.remote_csv_response(
                    entity, "access-logs/", "access-logs.csv", request.GET
                )
                if remote_csv is not None:
                    audit_event(
                        request,
                        LogCollectorAuditEvent.EventType.API_REQUEST,
                        entity,
                        resource="access-logs",
                    )
                    return remote_csv
            remote = self.local_or_remote(entity, "access-logs/", request.GET)
        except RemoteCollectorError as exc:
            return Response({"detail": str(exc)}, status=502)
        if remote is not None:
            audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="access-logs")
            return Response(remote)
        sync_entity_access_logs(entity)
        logs = entity.access_logs.all()
        app_logs = request.GET.get("source") == "app"
        if app_logs:
            logs = logs.filter(path__startswith="/log-collector/")
        else:
            logs = logs.exclude(path__startswith="/log-collector/")
        query = request.GET.get("q", "").strip()
        if query:
            from django.db.models import Q
            logs = logs.filter(
                Q(path__icontains=query)
                | Q(ip_address__icontains=query)
                | Q(method__icontains=query)
                | Q(status_code__icontains=query)
                | Q(query_string__icontains=query)
            )
        audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="access-logs")
        if request.GET.get("export") == "csv":
            return csv_response(
                "access-logs.csv",
                [
                    "timestamp",
                    "ip_address",
                    "method",
                    "path",
                    "query_string",
                    "url_username",
                    "status_code",
                    "request_context",
                    "bytes_sent",
                    "referrer",
                    "user_agent",
                ],
                (
                    [
                        row.timestamp.isoformat(),
                        row.ip_address,
                        row.method,
                        row.path,
                        row.query_string,
                        access_log_url_username(row.query_string),
                        row.status_code,
                        access_log_request_context(row.method)["label"],
                        row.bytes_sent,
                        row.referrer,
                        row.user_agent,
                    ]
                    for row in logs
                ),
            )
        analysis = local_security_analysis(entity)
        page_size = get_page_size(request)
        page = Paginator(logs, page_size).get_page(request.GET.get("page", 1))
        blocks = security_blocks_by_ip(row.ip_address for row in page.object_list)
        return Response({
            "count": page.paginator.count,
            "page": page.number,
            "page_size": page_size,
            "num_pages": page.paginator.num_pages,
            "results": [
                serialize_log(
                    row,
                    analysis.access_log_alerts.get(row.id),
                    block=blocks.get(row.ip_address),
                    include_block_state=True,
                )
                for row in page.object_list
            ],
        })


class GeolocationApi(EntityApiBase):
    allow_api_tokens = True

    def get(self, request, slug):
        entity = self.get_entity(slug)
        self.authorize(request, entity)
        if not entity.geolocation_enabled:
            raise PermissionDenied("Geolocation monitoring is disabled.")
        try:
            if request.GET.get("export") == "csv":
                remote_csv = self.remote_csv_response(
                    entity, "geolocation/", "geolocation.csv", request.GET
                )
                if remote_csv is not None:
                    audit_event(
                        request,
                        LogCollectorAuditEvent.EventType.API_REQUEST,
                        entity,
                        resource="geolocation",
                    )
                    return remote_csv
            remote = self.local_or_remote(entity, "geolocation/", request.GET)
        except RemoteCollectorError as exc:
            return Response({"detail": str(exc)}, status=502)
        if remote is not None:
            return Response(remote)
        location_model = optional_model("LOG_COLLECTOR_GEOLOCATION_MODEL")
        if location_model is None:
            return Response({"detail": "LOG_COLLECTOR_GEOLOCATION_MODEL is not configured."}, status=503)
        locations = location_model.objects.select_related("user").order_by("-captured_at")
        query = request.GET.get("q", "").strip()
        if query:
            locations = locations.filter(
                **{f"user__{get_user_model().USERNAME_FIELD}__icontains": query}
            )
        audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="geolocation")
        if request.GET.get("export") == "csv":
            return csv_response(
                "geolocation.csv",
                ["captured_at", "user", "ip_address", "latitude", "longitude", "country", "city"],
                (
                    [
                        row.captured_at.isoformat(),
                        row.user.get_username(),
                        row.ip_address,
                        row.latitude,
                        row.longitude,
                        row.country,
                        row.city,
                    ]
                    for row in locations
                ),
            )
        payload = paginated_payload(
            request,
            locations,
            lambda row: {
                "id": row.pk,
                "user": row.user.get_username(),
                "captured_at": row.captured_at.isoformat(),
                "ip_address": row.ip_address,
                "is_trusted_ip": is_trusted_security_ip(row.ip_address),
                "is_white_flagged": is_white_flagged_ip(row.ip_address),
                "latitude": str(row.latitude),
                "longitude": str(row.longitude),
                "country": row.country,
                "city": row.city,
            },
        )
        return Response(payload)


class UserSessionsApi(EntityApiBase):
    allow_api_tokens = True

    def get(self, request, slug):
        entity = self.get_entity(slug)
        self.authorize(request, entity)
        if not entity.user_sessions_enabled:
            raise PermissionDenied("User-session monitoring is disabled.")
        try:
            if request.GET.get("export") == "csv":
                remote_csv = self.remote_csv_response(
                    entity, "user-sessions/", "user-sessions.csv", request.GET
                )
                if remote_csv is not None:
                    audit_event(
                        request,
                        LogCollectorAuditEvent.EventType.API_REQUEST,
                        entity,
                        resource="user-sessions",
                    )
                    return remote_csv
            remote = self.local_or_remote(entity, "user-sessions/", request.GET)
        except RemoteCollectorError as exc:
            return Response({"detail": str(exc)}, status=502)
        if remote is not None:
            return Response(remote)
        session_model = optional_model("LOG_COLLECTOR_USER_SESSION_MODEL")
        if session_model is None:
            return Response({"detail": "LOG_COLLECTOR_USER_SESSION_MODEL is not configured."}, status=503)
        sessions = session_model.objects.select_related("user").order_by("-last_seen_at")
        query = request.GET.get("q", "").strip()
        if query:
            sessions = sessions.filter(
                Q(**{f"user__{get_user_model().USERNAME_FIELD}__icontains": query})
                | Q(ip__icontains=query)
            )
        audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="user-sessions")
        if request.GET.get("export") == "csv":
            return csv_response(
                "user-sessions.csv",
                ["session_key", "user", "ip_address", "created_at", "last_seen_at", "user_agent"],
                (
                    [
                        row.session_key,
                        row.user.get_username(),
                        row.ip,
                        row.created_at.isoformat(),
                        row.last_seen_at.isoformat(),
                        row.user_agent,
                    ]
                    for row in sessions
                ),
            )
        analysis = local_security_analysis(entity)
        page_size = get_page_size(request)
        page = Paginator(sessions, page_size).get_page(request.GET.get("page", 1))
        rows = list(page.object_list)
        threats = qualifying_ip_threats(entity, [row.ip for row in rows])
        blocks = security_blocks_by_ip(row.ip for row in rows)
        payload = {
            "count": page.paginator.count,
            "page": page.number,
            "page_size": page_size,
            "num_pages": page.paginator.num_pages,
            "results": [
                serialize_user_session(
                    row,
                    analysis.user_session_alerts.get(row.id),
                    ip_threat=threats.get(row.ip),
                    block=blocks.get(row.ip),
                )
                for row in rows
            ],
        }
        return Response(payload)


def serialize_security_block(block):
    effective = bool(block.desired_active and block.django_state == "active" and (
        block.expires_at is None or block.expires_at > timezone.now()
    ))
    return {
        "block_id": block.pk,
        "ip_address": block.ip_address,
        "django_state": "active" if effective else "inactive",
        "nginx_state": block.nginx_state,
        "expires_at": block.expires_at.isoformat() if block.expires_at else None,
        "desired_active": block.desired_active,
        "last_error": block.last_error,
    }


def serialize_security_incident(incident, blocks):
    block = blocks.get(incident.source_ip)
    state = serialize_security_block(block) if block else {
        "django_state": "inactive", "nginx_state": "not_configured",
        "block_id": None, "expires_at": None,
    }
    return {
        "id": incident.pk,
        "category": incident.category,
        "severity": incident.severity,
        "confidence_score": incident.confidence_score,
        "source_ip": incident.source_ip,
        "rule_code": incident.rule_code,
        "target_family": incident.target_family,
        "first_seen_at": incident.first_seen_at.isoformat(),
        "last_seen_at": incident.last_seen_at.isoformat(),
        "request_count": incident.request_count,
        "latest_evidence": incident.latest_evidence,
        "is_trusted_ip": is_trusted_security_ip(incident.source_ip),
        "is_white_flagged": is_white_flagged_ip(incident.source_ip),
        **{key: state[key] for key in ("django_state", "nginx_state", "block_id", "expires_at")},
    }


class SecurityIncidentsApi(EntityApiBase):
    allow_api_tokens = True

    def get(self, request, slug):
        entity = self.get_entity(slug)
        self.authorize(request, entity)
        try:
            if request.GET.get("export") == "csv":
                remote_csv = self.remote_csv_response(entity, "security-incidents/", "security-incidents.csv", request.GET)
                if remote_csv is not None:
                    return remote_csv
            remote = self.local_or_remote(entity, "security-incidents/", request.GET)
        except RemoteCollectorError as exc:
            return Response({"detail": str(exc)}, status=502)
        if remote is not None:
            return Response(remote)

        incidents = entity.security_incidents.all()
        for field, choices in (("category", SecurityIncident.Category.values), ("severity", SecurityIncident.Severity.values)):
            value = request.GET.get(field)
            if value:
                if value not in choices:
                    return Response({"detail": f"Invalid {field}."}, status=400)
                incidents = incidents.filter(**{field: value})
        query = request.GET.get("q", "").strip()
        if query:
            incidents = incidents.filter(
                Q(source_ip__icontains=query) | Q(rule_code__icontains=query)
                | Q(target_family__icontains=query) | Q(category__icontains=query)
                | Q(severity__icontains=query)
            )
        sort = request.GET.get("sort", "-last_seen_at")
        sort_field = sort.removeprefix("-")
        if sort_field not in {"id", "category", "severity", "confidence_score", "source_ip", "rule_code", "target_family", "first_seen_at", "last_seen_at", "request_count"}:
            return Response({"detail": "Invalid sort field."}, status=400)
        if sort_field == "severity":
            incidents = incidents.annotate(severity_rank=Case(
                *[When(severity=value, then=Value(rank)) for rank, value in enumerate(SecurityIncident.Severity.values)],
                output_field=IntegerField(),
            ))
            sort = ("-" if sort.startswith("-") else "") + "severity_rank"
        incidents = visible_security_incidents(incidents.order_by(sort, "-id"))

        # Blocks are deployment-wide, even when their originating incident differs.
        blocks = {}
        for block in BlockedIPAddress.objects.filter(
            ip_address__in=[incident.source_ip for incident in incidents]
        ).order_by("-desired_active", "-created_at", "-id"):
            blocks.setdefault(block.ip_address, block)
        serializer = lambda incident: serialize_security_incident(incident, blocks)
        audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="security-incidents")
        if request.GET.get("export") == "csv":
            headers = ["id", "category", "severity", "confidence_score", "source_ip", "rule_code", "target_family", "first_seen_at", "last_seen_at", "request_count", "latest_evidence", "django_state", "nginx_state", "block_id", "expires_at"]
            def rows():
                for incident in incidents:
                    row = serializer(incident)
                    row["latest_evidence"] = json.dumps(row["latest_evidence"], sort_keys=True)
                    yield [row[key] for key in headers]
            return csv_response("security-incidents.csv", headers, rows())
        return Response(paginated_payload(request, incidents, serializer))


class SecurityIncidentEvidenceApi(EntityApiBase):
    allow_api_tokens = True

    def get(self, request, slug, incident_id):
        entity = self.get_entity(slug)
        self.authorize(request, entity)
        try:
            remote = self.local_or_remote(entity, f"security-incidents/{incident_id}/evidence/", request.GET)
        except RemoteCollectorError as exc:
            return Response({"detail": str(exc)}, status=502)
        if remote is not None:
            return Response(remote)
        incident = get_object_or_404(SecurityIncident, entity=entity, pk=incident_id)
        results = []
        for evidence in incident.evidence.select_related("access_log", "token_usage"):
            usage = evidence.token_usage
            results.append({
                "id": evidence.pk, "observed_at": evidence.observed_at.isoformat(),
                "reason": evidence.reason, "payload": evidence.payload,
                "access_log": serialize_log(evidence.access_log) if evidence.access_log else None,
                "token_usage": {
                    "id": usage.pk, "created_at": usage.created_at.isoformat(),
                    "path": usage.path, "method": usage.method, "ip_address": usage.ip_address,
                    "outcome": usage.outcome, "denial_reason": usage.denial_reason,
                    "status_code": usage.status_code,
                } if usage else None,
            })
        audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="security-incident-evidence")
        return Response({"incident_id": incident.pk, "count": len(results), "results": results})


def manual_security_reason(data):
    if not isinstance(data, Mapping):
        raise ValueError("A JSON object or form is required.")
    reason = data.get("reason")
    if not isinstance(reason, str):
        raise ValueError("A reason is required.")
    reason = " ".join(re.sub(r"[\x00-\x1f\x7f]", " ", strip_tags(reason)).split())
    if not reason:
        raise ValueError("A reason is required.")
    return reason


class CrowdSecApiBase(EntityApiBase):
    def local_connection(self, request, slug, *, manage=False):
        entity = self.get_entity(slug)
        if not entity.is_hosting:
            raise PermissionDenied("CrowdSec is available on the local hosting entity only.")
        self.authorize(request, entity, superuser=manage, api_key_allowed=False)
        if not isinstance(request.successful_authenticator, SessionAuthentication):
            raise PermissionDenied("A signed-in dashboard session is required.")
        return entity

    def connection(self, entity):
        return CrowdSecConnection.objects.filter(entity_id=entity.pk).first()


class CrowdSecConnectionApi(CrowdSecApiBase):
    def get(self, request, slug):
        entity = self.local_connection(request, slug)
        connection = self.connection(entity)
        if not connection:
            return Response({"status": "not_configured", "configured": False})
        try:
            crowdsec_request(connection, "GET", "v1/alerts?limit=1")
        except CrowdSecError as exc:
            return Response({"status": "error", "configured": True, "detail": str(exc)})
        return Response({"status": "connected", "configured": True, "api_url": connection.api_url})

    def post(self, request, slug):
        entity = self.local_connection(request, slug, manage=True)
        api_url = str(request.data.get("api_url", "")).strip().rstrip("/")
        machine_id = str(request.data.get("machine_id", "")).strip()
        password = request.data.get("password")
        if password is not None and not isinstance(password, str):
            return Response({"detail": "CrowdSec machine password must be text."}, status=400)
        old = self.connection(entity)
        if not password and old:
            from crowdsec_integration.services import _password
            try:
                password = _password(old)
            except CrowdSecError as exc:
                return Response({"detail": str(exc)}, status=400)
        if not api_url or len(api_url) > 500 or not machine_id or len(machine_id) > 255 or not password or len(password) > 1000:
            return Response({"detail": "LAPI URL, machine ID, and password are required."}, status=400)
        try:
            validate_connection(api_url, machine_id, password)
        except CrowdSecError as exc:
            return Response({"detail": str(exc)}, status=400)
        connection, _ = CrowdSecConnection.objects.update_or_create(
            entity_id=entity.pk,
            defaults={"api_url": api_url, "machine_id": machine_id, "encrypted_password": encrypt_password(password)},
        )
        audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="crowdsec-connection", action="saved")
        return Response({"status": "connected", "configured": True, "api_url": connection.api_url})

    def delete(self, request, slug):
        entity = self.local_connection(request, slug, manage=True)
        CrowdSecConnection.objects.filter(entity_id=entity.pk).delete()
        audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="crowdsec-connection", action="removed")
        return Response({"status": "not_configured", "configured": False})


class CrowdSecAlertsApi(CrowdSecApiBase):
    def get(self, request, slug):
        entity = self.local_connection(request, slug)
        connection = self.connection(entity)
        if not connection:
            return Response({"detail": "CrowdSec is not configured."}, status=409)
        try:
            result = crowdsec_request(connection, "GET", "v1/alerts?limit=100")
        except CrowdSecError as exc:
            return Response({"detail": str(exc)}, status=502)
        return Response({"results": result if isinstance(result, list) else []})


class CrowdSecDecisionsApi(CrowdSecApiBase):
    def get(self, request, slug):
        entity = self.local_connection(request, slug)
        connection = self.connection(entity)
        if not connection:
            return Response({"detail": "CrowdSec is not configured."}, status=409)
        try:
            result = crowdsec_request(connection, "GET", "v1/decisions?limit=100")
        except CrowdSecError as exc:
            return Response({"detail": str(exc)}, status=502)
        return Response({"results": result if isinstance(result, list) else []})

    def post(self, request, slug):
        entity = self.local_connection(request, slug, manage=True)
        connection = self.connection(entity)
        if not connection:
            return Response({"detail": "CrowdSec is not configured."}, status=409)
        try:
            target = str(parse_ip_address(request.data.get("ip_address", "")))
            duration = str(request.data.get("duration", "4h"))
            if not re.fullmatch(r"[1-9][0-9]{0,3}[smhd]", duration):
                raise ValueError("Duration must be a number followed by s, m, h, or d.")
            reason = manual_security_reason(request.data)[:120]
        except (TypeError, ValueError) as exc:
            return Response({"detail": str(exc)}, status=400)
        try:
            crowdsec_request(connection, "POST", "v1/decisions", params={
                "duration": duration, "origin": "log_collector", "scenario": f"manual/{reason}",
                "type": "ban", "value": f"Ip:{target}",
            })
        except CrowdSecError as exc:
            return Response({"detail": f"CrowdSec rejected the decision: {exc}"}, status=502)
        audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="crowdsec-decision", action="block", target_ip=target)
        return Response({"ok": True, "ip_address": target}, status=201)

    def delete(self, request, slug):
        entity = self.local_connection(request, slug, manage=True)
        connection = self.connection(entity)
        if not connection:
            return Response({"detail": "CrowdSec is not configured."}, status=409)
        try:
            target = str(parse_ip_address(request.data.get("ip_address", "")))
        except (TypeError, ValueError) as exc:
            return Response({"detail": str(exc)}, status=400)
        try:
            crowdsec_request(connection, "DELETE", f"v1/decisions?ip={target}")
        except CrowdSecError as exc:
            return Response({"detail": f"CrowdSec rejected the removal: {exc}"}, status=502)
        audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="crowdsec-decision", action="unblock", target_ip=target)
        return Response({"ok": True, "ip_address": target})


class SecurityActionApi(EntityApiBase):
    def authorize_action(self, request, entity):
        self.authorize(request, entity, superuser=False, api_key_allowed=False)
        if (not entity.is_hosting or request.headers.get("X-Api-Key")
                or request.headers.get("Authorization")
                or not isinstance(request.successful_authenticator, SessionAuthentication)):
            raise PermissionDenied("A local hosting DATA_CENTER session is required.")


class SecurityBlockApi(SecurityActionApi):
    def post(self, request, slug):
        entity = self.get_entity(slug)
        self.authorize_action(request, entity)
        try:
            reason = manual_security_reason(request.data)
            duration = request.data.get("duration_seconds")
            permanent = request.data.get("permanent", False)
            if type(permanent) is not bool:
                raise ValueError("Permanent must be a boolean.")
            if duration is not None and (permanent or type(duration) is not int or duration <= 0):
                raise ValueError("Duration must be a positive integer, without permanent.")
            expiry = timezone.now() + timedelta(seconds=duration) if duration is not None else None
            incident_id = request.data.get("incident_id")
            incident = get_object_or_404(SecurityIncident, entity=entity, pk=incident_id) if incident_id is not None else None
            ip = request.data.get("ip_address")
            if not isinstance(ip, str):
                raise ValueError("An IP address string is required.")
            normalized_ip = str(parse_ip_address(ip))
            if is_trusted_security_ip(normalized_ip):
                raise ValueError("Trusted IP addresses cannot be blocked.")
            if not entity.access_logs.filter(ip_address=normalized_ip).exists():
                raise ValueError(
                    "Only IP addresses observed in access logs can be blocked."
                )
            if incident is not None and incident.source_ip != normalized_ip:
                raise ValueError("The incident source IP does not match the block target.")
            result = block_ip(normalized_ip, origin="manual", reason=reason, actor=request.user,
                              incident=incident, expires_at=expiry, fail_if_active=True)
        except (TypeError, ValueError, OverflowError) as exc:
            return Response({"detail": str(exc)}, status=400)
        if result.status == "exempt":
            return Response({"detail": "Trusted IP addresses cannot be blocked."}, status=400)
        if result.status in ("conflict", "unchanged"):
            return Response({"detail": "The IP already has an active block."}, status=409)
        return Response(serialize_security_block(result.block), status=201)


class SecurityUnblockApi(SecurityActionApi):
    def post(self, request, slug, block_id):
        entity = self.get_entity(slug)
        self.authorize_action(request, entity)
        try:
            reason = manual_security_reason(request.data)
            block = get_object_or_404(BlockedIPAddress, pk=block_id)
            result = unblock_ip(block, actor=request.user, reason=reason)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=400)
        if result.status == "unchanged":
            return Response({"detail": "The block is already inactive."}, status=409)
        return Response(serialize_security_block(result.block))


class SecurityWhiteFlagApi(EntityApiBase):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, slug):
        entity = self.get_entity(slug)
        if (
            not entity.is_hosting
            or request.headers.get("X-Api-Key")
            or request.headers.get("Authorization")
            or not isinstance(request.successful_authenticator, SessionAuthentication)
            or not request.user.is_superuser
        ):
            raise PermissionDenied("A superuser session on the local hosting entity is required.")
        try:
            action = request.data.get("action")
            normalized_ip = normalize_ip(request.data.get("ip_address"))
            reason = manual_security_reason(request.data)
            if action not in {"white_flag", "remove_white_flag"}:
                raise ValueError("An action of white_flag or remove_white_flag is required.")
            if is_configured_trusted_security_ip(normalized_ip):
                raise ValueError("Configured trusted IP addresses cannot be white flagged.")
            if not entity.access_logs.filter(ip_address=normalized_ip).exists():
                raise ValueError("Only an IP observed in local access logs can be white flagged.")
        except (TypeError, ValueError) as exc:
            return Response({"detail": str(exc)}, status=400)

        with transaction.atomic():
            LogCollectorEntity.objects.select_for_update().get(pk=entity.pk)
            active = normalized_ip in active_white_flag_ips([normalized_ip])
            if (action == "white_flag" and active) or (action == "remove_white_flag" and not active):
                return Response({"detail": "White Flag is already in the requested state."}, status=409)
            audit_event(
                request,
                LogCollectorAuditEvent.EventType.API_REQUEST,
                entity,
                action="white_flag_ip" if action == "white_flag" else "remove_white_flag_ip",
                target_ip=normalized_ip,
                reason=reason,
            )
        return Response(
            {"ip_address": normalized_ip, "white_flagged": action == "white_flag"},
            status=201 if action == "white_flag" else 200,
        )


class UserSessionContainApi(EntityApiBase):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, slug, session_id):
        entity = self.get_entity(slug)
        if (
            not entity.is_hosting
            or request.headers.get("X-Api-Key")
            or request.headers.get("Authorization")
            or not isinstance(request.successful_authenticator, SessionAuthentication)
            or not request.user.is_authenticated
            or not request.user.is_superuser
        ):
            audit_event(
                request,
                LogCollectorAuditEvent.EventType.DENIED,
                entity,
                outcome="denied",
                action="contain_user",
            )
            raise PermissionDenied("A local hosting superuser session is required.")
        if not entity.user_sessions_enabled:
            raise PermissionDenied("User-session monitoring is disabled.")

        try:
            reason = manual_security_reason(request.data)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=400)

        session_model = optional_model("LOG_COLLECTOR_USER_SESSION_MODEL")
        if session_model is None:
            return Response({"detail": "LOG_COLLECTOR_USER_SESSION_MODEL is not configured."}, status=503)
        session = get_object_or_404(
            session_model.objects.select_related("user"), pk=session_id
        )
        target = session.user
        confirmation = request.data.get("confirmation_username")
        if confirmation != target.get_username():
            return Response({"detail": "The confirmation username does not match."}, status=400)
        if target.pk == request.user.pk:
            return Response({"detail": "You cannot contain your own account."}, status=400)
        if not target.is_active:
            return Response({"detail": "The target account is already inactive."}, status=409)
        if is_trusted_security_ip(session.ip):
            return Response({"detail": "Trusted IP addresses cannot be contained."}, status=400)
        if not entity.access_logs.filter(ip_address=session.ip).exists():
            return Response(
                {"detail": "The session IP has not been observed in this entity's access logs."},
                status=409,
            )
        if target.is_superuser and not get_user_model().objects.filter(
            is_superuser=True, is_active=True
        ).exclude(pk=target.pk).exists():
            return Response({"detail": "The last active superuser cannot be contained."}, status=400)

        try:
            with transaction.atomic():
                locked_session = session_model.objects.select_for_update().select_related(
                    "user"
                ).get(pk=session.pk)
                target = get_user_model().objects.select_for_update().get(
                    pk=locked_session.user_id
                )
                if target.pk == request.user.pk:
                    return Response(
                        {"detail": "You cannot contain your own account."}, status=400
                    )
                if request.data.get("confirmation_username") != target.get_username():
                    return Response(
                        {"detail": "The confirmation username does not match."},
                        status=400,
                    )
                if not target.is_active:
                    return Response(
                        {"detail": "The target account is already inactive."}, status=409
                    )
                incident = qualifying_ip_threat(entity, locked_session.ip)
                if incident is None:
                    return Response(
                        {"detail": "The session IP no longer has a current qualifying threat."},
                        status=409,
                    )
                if is_trusted_security_ip(locked_session.ip):
                    return Response(
                        {"detail": "Trusted IP addresses cannot be contained."}, status=400
                    )
                if not entity.access_logs.filter(ip_address=locked_session.ip).exists():
                    return Response(
                        {"detail": "The session IP is no longer present in access logs."},
                        status=409,
                    )
                if target.is_superuser:
                    active_superuser_ids = list(
                        get_user_model().objects.select_for_update()
                        .filter(is_superuser=True, is_active=True)
                        .values_list("pk", flat=True)
                    )
                    if active_superuser_ids == [target.pk]:
                        return Response(
                            {"detail": "The last active superuser cannot be contained."},
                            status=400,
                        )
                revocations = contain_user_account(target)
                block_result = block_ip(
                    locked_session.ip,
                    origin=BlockedIPAddress.Origin.MANUAL,
                    reason=reason,
                    incident=incident,
                    actor=request.user,
                )
                if block_result.block is None or not block_result.django_applied:
                    raise RuntimeError("Django IP enforcement could not be applied.")
                block = block_result.block
                audit_event(
                    request,
                    LogCollectorAuditEvent.EventType.API_REQUEST,
                    entity,
                    outcome="success",
                    action="contain_user",
                    target_user_id=target.pk,
                    target_username=target.get_username(),
                    ip_address=locked_session.ip,
                    incident_id=incident.pk,
                    reason=reason,
                    revocations=revocations.as_dict(),
                    block_id=block.pk,
                    nginx_state=block.nginx_state,
                )
        except session_model.DoesNotExist:
            return Response({"detail": "The user session no longer exists."}, status=409)
        except Exception:
            logger.exception(
                "User-session containment failed for entity=%s session=%s",
                entity.slug,
                session.pk,
            )
            audit_event(
                request,
                LogCollectorAuditEvent.EventType.API_REQUEST,
                entity,
                outcome="failed",
                action="contain_user",
                target_user_id=target.pk,
                target_username=target.get_username(),
                ip_address=session.ip,
                reason=reason,
            )
            return Response(
                {"detail": "Account containment failed; no database changes were applied."},
                status=500,
            )

        payload = serialize_security_block(block)
        payload.update({
            "target_user_id": target.pk,
            "target_username": target.get_username(),
            "revocations": revocations.as_dict(),
            "warning": (
                "The IP block is deployment-wide and may affect other users sharing it."
            ),
        })
        return Response(payload)


class SecuritySummaryApi(EntityApiBase):
    allow_api_tokens = True

    def get(self, request, slug):
        entity = self.get_entity(slug)
        self.authorize(request, entity)
        try:
            remote = self.local_or_remote(entity, "security-summary/")
        except RemoteCollectorError as exc:
            return Response({"detail": str(exc)}, status=502)
        if remote is not None:
            audit_event(
                request,
                LogCollectorAuditEvent.EventType.API_REQUEST,
                entity,
                resource="security-summary",
            )
            return Response(remote)
        payload = local_security_summary(entity)
        audit_event(
            request,
            LogCollectorAuditEvent.EventType.API_REQUEST,
            entity,
            resource="security-summary",
        )
        return Response(payload)


class EndpointsApi(EntityApiBase):
    allow_api_tokens = True

    def get(self, request, slug):
        entity = self.get_entity(slug)
        self.authorize(request, entity, superuser=True)
        token_authenticated = bool(getattr(request, "log_collector_api_token", None))
        payload = {
            "entity": entity.slug,
            "api_key_enabled": entity.enable_api_endpoint,
            "endpoints": entity_endpoint_descriptors(
                request,
                entity,
                audit_events_enabled=token_authenticated or request.user.is_superuser,
            ),
        }
        audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="endpoints")
        return Response(payload)


class AuditEventsApi(EntityApiBase):
    allow_api_tokens = True

    def get(self, request, slug):
        entity = self.get_entity(slug)
        self.authorize(request, entity, superuser=True)
        events = entity.audit_events.select_related("user")
        query = request.GET.get("q", "").strip()
        if query:
            user_query = f"user__{get_user_model().USERNAME_FIELD}__icontains"
            events = events.filter(
                Q(event_type__icontains=query)
                | Q(outcome__icontains=query)
                | Q(path__icontains=query)
                | Q(**{user_query: query})
                | Q(api_key_name__icontains=query)
            )
        if request.GET.get("export") == "csv":
            return csv_response(
                "audit-events.csv",
                ["created_at", "event_type", "outcome", "path", "user", "api_key_name"],
                (
                    [
                        row.created_at.isoformat(),
                        row.event_type,
                        row.outcome,
                        row.path,
                        row.user.get_username() if row.user else "",
                        row.api_key_name,
                    ]
                    for row in events
                ),
            )
        payload = paginated_payload(
            request,
            events,
            lambda row: {
                "id": row.pk,
                "event_type": row.event_type,
                "outcome": row.outcome,
                "path": row.path,
                "user": row.user.get_username() if row.user else None,
                "api_key_name": row.api_key_name,
                "created_at": row.created_at.isoformat(),
            },
        )
        audit_event(request, LogCollectorAuditEvent.EventType.API_REQUEST, entity, resource="audit-events")
        return Response(payload)


class EntityCollectionApi(EntityApiBase):
    def get(self, request):
        self.authorize(
            request, LogCollectorEntity.get_hosting_entity(), superuser=True, api_key_allowed=False
        )
        return Response(
            [
                {"name": entity.name, "slug": entity.slug, "entity_type": entity.entity_type}
                for entity in LogCollectorEntity.objects.all()
            ]
        )

    def post(self, request):
        self.authorize(
            request, LogCollectorEntity.get_hosting_entity(), superuser=True, api_key_allowed=False
        )
        form = EntityForm(request.data)
        if not form.is_valid():
            return Response(form.errors, status=400)
        entity = form.save(commit=False)
        entity.entity_type = LogCollectorEntity.EntityType.INTEGRATION
        entity.save()
        return Response({"name": entity.name, "slug": entity.slug}, status=201)


class EntityDetailApi(EntityApiBase):
    def get(self, request, slug):
        entity = self.get_entity(slug)
        self.authorize(request, entity, superuser=True, api_key_allowed=False)
        return Response({"name": entity.name, "slug": entity.slug, "entity_type": entity.entity_type})

    def patch(self, request, slug):
        entity = self.get_entity(slug)
        self.authorize(request, entity, superuser=True, api_key_allowed=False)
        form = EntityForm(request.data, instance=entity, partial=True)
        if not form.is_valid():
            return Response(form.errors, status=400)
        entity = form.save()
        return Response({"name": entity.name, "slug": entity.slug})

    def delete(self, request, slug):
        entity = self.get_entity(slug)
        self.authorize(request, entity, superuser=True, api_key_allowed=False)
        if entity.is_hosting:
            return Response({"detail": "The hosting entity cannot be deleted."}, status=400)
        entity.delete()
        return Response(status=204)
