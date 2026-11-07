import re
from urllib.parse import urlsplit

from django.conf import settings
from django.core.exceptions import DisallowedHost
from django.urls import Resolver404, resolve
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission, SAFE_METHODS
from log_collector.access import has_dashboard_access

from log_collector.services.client_ip import resolve_client_ip as get_client_ip


def get_request_host(request):
    try:
        return request.get_host()
    except DisallowedHost:
        return request.META.get("HTTP_HOST", "")


def get_origin_domain(request):
    origin = request.META.get("HTTP_ORIGIN") or request.META.get("HTTP_REFERER") or ""
    if not origin:
        return ""
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return ""
    host = parsed.netloc or parsed.path.split("/", 1)[0]
    return host.split("@")[-1].split(":", 1)[0].strip(".").lower()


def resolve_entity_from_view(view):
    try:
        from log_collector.models import LogCollectorEntity

        slug = getattr(view, "kwargs", {}).get("slug")
        return LogCollectorEntity.objects.filter(slug=slug).first() if slug else None
    except Exception:
        return None


def _usage_entity(view):
    from log_collector.models import LogCollectorEntity

    return resolve_entity_from_view(view) or LogCollectorEntity.get_hosting_entity()


def _usage_text(request, value, limit):
    supplied_key = (request.headers.get("X-Api-Key") or "").strip()
    text = str(value or "")
    if supplied_key:
        text = text.replace(supplied_key, "[redacted]")
    return re.sub(r"[\x00-\x1f\x7f]", " ", text)[:limit]


def _has_dashboard_session(request):
    user = request.user
    if not (
        getattr(user, "is_authenticated", False)
        and isinstance(
            getattr(request, "successful_authenticator", None), SessionAuthentication
        )
        and has_dashboard_access(user)
    ):
        return False
    origin = request.META.get("HTTP_ORIGIN") or request.META.get("HTTP_REFERER")
    if not origin:
        return True
    try:
        parsed = urlsplit(origin)
        return (
            parsed.scheme == request.scheme
            and parsed.netloc.lower() == request.get_host().lower()
            and parsed.username is None
            and parsed.password is None
        )
    except (ValueError, DisallowedHost):
        return False


def _denial_path(request):
    """Record the server-owned route template, never caller-controlled segments."""
    try:
        return ("/" + resolve(request.path).route)[:500]
    except Resolver404:
        return "/log-collector/api/[unresolved]/"


def _usage_method(request):
    methods = (*SAFE_METHODS, "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT")
    return request.method if request.method in methods else ""


def record_token_usage(request, view, outcome, reason="", token=None, entity=None):
    try:
        from log_collector.models import LogCollectorApiTokenUsage

        entity = entity if entity is not None else _usage_entity(view)
        allowed = outcome == "allowed"
        token_prefix = token.key_prefix if token is not None and allowed else ""
        ip_address = get_client_ip(request)
        origin_domain = get_origin_domain(request) if allowed else ""
        usage = LogCollectorApiTokenUsage.objects.create(
            token=token,
            entity=entity,
            token_name=(
                _usage_text(request, getattr(token, "name", ""), 120) if allowed else ""
            ),
            token_prefix=token_prefix,
            path=(
                _usage_text(request, request.path, 500) if allowed else _denial_path(request)
            ),
            method=_usage_method(request),
            outcome=outcome,
            denial_reason=reason,
            ip_address=ip_address,
            request_host=(
                _usage_text(request, get_request_host(request), 255) if allowed else ""
            ),
            origin_domain=_usage_text(request, origin_domain, 255),
            user_agent=(
                _usage_text(request, request.META.get("HTTP_USER_AGENT"), 512)
                if allowed else ""
            ),
        )
        if token is not None and outcome == "allowed":
            token.record_usage(ip_address=ip_address, origin_domain=origin_domain)
        return usage
    except Exception:
        return None


def audit_permission_denial(request, view, reason):
    """Permission checks run before views, so record denied API requests here."""
    try:
        from log_collector.models import LogCollectorAuditEvent

        LogCollectorAuditEvent.objects.create(
            entity=_usage_entity(view),
            event_type=LogCollectorAuditEvent.EventType.DENIED,
            path=_denial_path(request),
            method=_usage_method(request),
            outcome="denied",
            ip_address=get_client_ip(request),
            details={"reason": reason},
        )
    except Exception:
        return


class LogCollectorApiTokenPermission(BasePermission):
    """Allow same-origin dashboard sessions or entity-scoped read-only tokens."""

    message = "Authentication credentials were not provided."

    def _deny(self, request, view, reason, message=None, token=None, entity=None):
        request.log_collector_token_usage = record_token_usage(
            request,
            view,
            outcome="denied",
            reason=reason,
            token=token,
            entity=entity,
        )
        audit_permission_denial(request, view, reason)
        raise AuthenticationFailed(message or self.message)

    def has_permission(self, request, view):
        if _has_dashboard_session(request):
            return True

        supplied_key = (request.headers.get("X-Api-Key") or "").strip()
        if not supplied_key:
            self._deny(request, view, "missing_credentials")

        if request.method not in SAFE_METHODS:
            request.log_collector_token_usage = record_token_usage(
                request, view, "denied", "read_only_api_token"
            )
            audit_permission_denial(request, view, "read_only_api_token")
            return False

        from log_collector.models import LogCollectorApiToken

        key_prefix = LogCollectorApiToken.parse_prefix(supplied_key)
        if not key_prefix:
            self._deny(request, view, "invalid_api_token", "API token not found or inactive.")

        token = (
            LogCollectorApiToken.objects.select_related("entity")
            .filter(key_prefix=key_prefix)
            .first()
        )
        if token is None or not token.matches(supplied_key):
            self._deny(request, view, "invalid_api_token", "API token not found or inactive.")

        entity = resolve_entity_from_view(view)
        if entity is not None and token.entity_id != entity.id:
            self._deny(
                request,
                view,
                "token_entity_mismatch",
                "API token is not authorized for this entity.",
                token=token,
                entity=entity,
            )

        if not getattr(settings, "LOG_COLLECTOR_ENABLE_API_ENDPOINT", True):
            self._deny(
                request,
                view,
                "api_endpoint_disabled",
                "The log collector API endpoint is disabled.",
                token=token,
                entity=entity,
            )

        if not getattr(view, "allow_api_tokens", False):
            self._deny(
                request,
                view,
                "api_token_scope_rejected",
                "API token is not authorized for this endpoint.",
                token=token,
                entity=entity,
            )

        if entity is not None and not entity.enable_api_endpoint:
            self._deny(
                request,
                view,
                "entity_api_endpoint_disabled",
                "This entity API endpoint is disabled.",
                token=token,
                entity=entity,
            )

        if not token.is_active:
            self._deny(
                request,
                view,
                "api_token_inactive",
                "API token not found or inactive.",
                token=token,
                entity=entity,
            )

        if token.is_expired():
            self._deny(
                request,
                view,
                "api_token_expired",
                "API token has expired.",
                token=token,
                entity=entity,
            )

        if not token.allows_ip(get_client_ip(request)):
            self._deny(
                request,
                view,
                "api_token_ip_rejected",
                "Invalid API token IP or domain.",
                token=token,
                entity=entity,
            )

        if not token.allows_origin_domain(get_origin_domain(request)):
            self._deny(
                request,
                view,
                "api_token_origin_rejected",
                "Invalid API token IP or domain.",
                token=token,
                entity=entity,
            )

        request.log_collector_api_token = token
        request.log_collector_token_usage = record_token_usage(
            request, view, outcome="allowed", token=token, entity=entity
        )
        return True
