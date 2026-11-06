"""Read-only, rule-based security analysis for collector data."""

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from math import log2
from urllib.parse import parse_qsl, unquote

from django.conf import settings
from django.utils import timezone

from log_collector.services.client_ip import is_trusted_security_ip


WINDOW_MINUTES = 15
CONCURRENT_SESSION_MINIMUM = 3
CONCURRENT_SESSION_IP_MINIMUM = 3
CONCURRENT_SESSION_USER_AGENT_MINIMUM = 3
ERROR_BURST_MINUTES = 5
ERROR_BURST_MINIMUM = 20
ERROR_BURST_DISTINCT_PATHS = 10
DENIAL_WINDOW_SECONDS = 60
DENIAL_MINIMUM = 5
MAX_PATH_LENGTH = 4096
MAX_QUERY_LENGTH = 8192
MAX_USER_AGENT_LENGTH = 512
DEFAULT_PROTECTED_PATH_PREFIXES = ("/accounts/", "/api/auth/", "/api/user-profile/mfa/")
SENSITIVE_COMPONENTS = frozenset((".env", ".git", "wp-config.php", "settings.py"))
SENSITIVE_SUFFIXES = (
    ".conf", ".config", ".ini", ".pem", ".key", ".p12", ".pfx", ".sql", ".bak",
    ".yaml", ".yml", ".toml", ".properties",
)
TOKEN_DENIAL_REASONS = frozenset((
    "missing_credentials", "invalid_api_token", "api_token_inactive", "api_token_expired",
    "token_entity_mismatch", "api_token_ip_rejected", "api_token_origin_rejected",
    "api_token_scope_rejected", "read_only_api_token", "api_endpoint_disabled",
    "entity_api_endpoint_disabled",
))
CREDENTIAL_PATH_LABELS = frozenset((
    "password", "passwd", "token", "tokens", "api-key", "api_key", "apikey", "key", "keys",
    "secret", "cookie", "authorization", "bearer", "jwt", "reset", "reset-password",
    "access_token", "access-token", "refresh_token", "refresh-token", "id_token", "id-token",
    "client_secret", "client-secret", "api_token", "api-token", "session_token", "session-token",
))
UUID_COMPONENT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)
READABLE_SLUG_COMPONENT = re.compile(r"[a-z]+(?:[-_.](?:[a-z]+|\d{1,4}))+", re.I)
EXPLOIT_SIGNATURES = {
    "sql_injection": re.compile(
        r"\bunion\s+(?:all\s+)?select\b|\b(?:sleep|benchmark)\s*\(|\binformation_schema\s*\."
        r"|\b(?:or|and)\s+(?:(?P<number>\d+)\s*=\s*(?P=number)(?!\d)"
        r"|'(?P<quoted>[^']{1,40})'\s*=\s*'(?P=quoted)')", re.I
    ),
    "xss": re.compile(r"<\s*script\b|javascript\s*:|\bon(?:error|load)\s*=", re.I),
    "command_injection": re.compile(
        r"(?:;|&&|\|\||\||`|\$\()\s*(?:/bin/)?"
        r"(?:sh|bash|cat|wget|curl|nc|netcat|whoami|id|powershell|cmd)(?:\s|[(`/]|$)", re.I
    ),
    "remote_code_execution": re.compile(
        r"\$\{jndi:|php://(?:input|filter)|\b(?:eval|assert|system|shell_exec|passthru)\s*\("
        r"|/bin/(?:ba)?sh\b|\{\{\s*(?:\d+\s*[*+]\s*\d+|[^}]{0,80}__\w+__)", re.I
    ),
}

SCANNER_USER_AGENT_MARKERS = (
    "burp suite",
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "acunetix",
    "wpscan",
    "nessus",
    "openvas",
    "gobuster",
    "dirbuster",
    "ffuf",
)


@dataclass(frozen=True)
class DetectionMatch:
    category: str
    rule_code: str
    severity: str
    confidence: float
    source_ip: str
    target_family: str
    reason: str
    observed_at: datetime
    access_log_ids: tuple[int, ...] = ()
    token_usage_ids: tuple[int, ...] = ()


@dataclass(frozen=True)
class SecurityAnalysis:
    access_log_alerts: dict
    user_session_alerts: dict
    summary: dict


def _critical_alert(reasons):
    return {"level": "critical", "reasons": reasons}


def _append_reason(alerts, identifier, reason):
    reasons = alerts.setdefault(identifier, [])
    if reason not in reasons:
        reasons.append(reason)


def _in_window(records, field, cutoff):
    return [record for record in records if getattr(record, field, None) and getattr(record, field) >= cutoff]


def _decode_path(value):
    path = (value or "")[:MAX_PATH_LENGTH].split("?", 1)[0].split("#", 1)[0]
    return unquote(path).lower().replace("\\", "/")


def _sensitive_family(value):
    components = tuple(component for component in value.split("/") if component)
    if ".." in components:
        return "traversal"
    if (any(component in SENSITIVE_COMPONENTS or component.startswith(".env.")
            or component.endswith(SENSITIVE_SUFFIXES) for component in components)
            or any(components[i:i + 2] == ("etc", "passwd") for i in range(len(components) - 1))):
        return "sensitive-file"
    return None


def _protected_prefixes():
    extensions = getattr(settings, "LOG_COLLECTOR_PROTECTED_PATH_PREFIXES", ())
    return tuple(dict.fromkeys(
        DEFAULT_PROTECTED_PATH_PREFIXES + tuple(_decode_path(prefix).rstrip("/") + "/" for prefix in extensions)
    ))


def _protected_family(path):
    for prefix in _protected_prefixes():
        if path == prefix.rstrip("/") or path.startswith(prefix):
            return prefix + "*"
    return None


def normalize_target_family(path):
    """Decode once; preserve only the first two components for ordinary paths."""
    return _normalized_family(_decode_path(path))


def _is_credential_or_opaque_component(component, previous=""):
    """Inspect only bounded components; keep readable slugs, never UUIDs."""
    value = component[:MAX_PATH_LENGTH]
    label = re.split(r"[=:]", value, maxsplit=1)[0]
    if (previous[:MAX_PATH_LENGTH] in CREDENTIAL_PATH_LABELS
            or label in CREDENTIAL_PATH_LABELS and label != value
            or UUID_COMPONENT.fullmatch(value)):
        return True
    if len(value) < 20 or READABLE_SLUG_COMPONENT.fullmatch(value):
        return False
    if value.isalpha():
        return len(value) >= 24
    has_letters = any(character.isalpha() for character in value)
    mixed_alphanumeric_token = has_letters and any(character.isdigit() for character in value)
    punctuated_token = has_letters and any(
        not character.isalnum() and not character.isspace() and character not in "._-"
        for character in value
    )
    if mixed_alphanumeric_token or punctuated_token:
        return True
    # Evaluate the complete value so token separators do not reset the count.
    entropy = -sum((count / len(value)) * log2(count / len(value))
                   for count in Counter(value).values())
    return entropy >= 4.0


def _normalized_family(decoded):
    family = _sensitive_family(decoded) or _protected_family(decoded)
    if family:
        return family[:255]
    components = [component for component in decoded.split("/") if component][:2]
    safe = []
    for index, component in enumerate(components):
        if (_is_credential_or_opaque_component(component, components[index - 1] if index else "")
                or any(pattern.search(component) for pattern in EXPLOIT_SIGNATURES.values())):
            safe.append("[redacted]")
        else:
            safe.append(component)
    return ("/" + "/".join(safe))[:255]


def _safe_scanner_marker(value):
    agent = (value or "")[:MAX_USER_AGENT_LENGTH].lower()
    return next((marker for marker in SCANNER_USER_AGENT_MARKERS if marker in agent), "")


def _eligible_rows(records, field, now, seconds):
    cutoff = now - timezone.timedelta(seconds=seconds)
    rows = {}
    for row in records:
        observed = getattr(row, field, None)
        if not observed or not cutoff <= observed <= now:
            continue
        try:
            source = str(ip_address(row.ip_address))
        except (ValueError, TypeError):
            continue
        if is_trusted_security_ip(source):
            continue
        rows.setdefault((getattr(row, "entity_id", None), row.id), (row, source))
    return sorted(rows.values(), key=lambda pair: (getattr(pair[0], field), pair[0].id))


def _match(rows, rule, family, reason, *, token=False, category="malicious", critical=True):
    field = "created_at" if token else "timestamp"
    return DetectionMatch(
        category=category, rule_code=rule, severity="critical" if critical else "high",
        confidence=0.95 if critical else (0.85 if category == "unauthorized" else 0.90),
        source_ip=rows[0][1], target_family=family, reason=reason,
        observed_at=getattr(rows[-1][0], field),
        access_log_ids=() if token else tuple(row.id for row, _ in rows),
        token_usage_ids=tuple(row.id for row, _ in rows) if token else (),
    )


def classify_access_logs(access_logs, *, now=None) -> list[DetectionMatch]:
    """Return bounded, secret-free matches; trusted sources remain visible."""
    now = now or timezone.now()
    direct = defaultdict(list)
    errors = defaultdict(list)
    denials = defaultdict(list)
    for row, source in _eligible_rows(access_logs, "timestamp", now, WINDOW_MINUTES * 60):
        entity = getattr(row, "entity_id", None)
        path = _decode_path(row.path)
        family = _normalized_family(path)
        # parse_qsl performs the one decoding pass for query components.
        query_values = [component.lower().replace("\\", "/")
                        for pair in parse_qsl((row.query_string or "")[:MAX_QUERY_LENGTH], keep_blank_values=True)
                        for component in pair]
        inspected = [path, *query_values]
        sensitive = next((result for value in inspected if (result := _sensitive_family(value))), None)
        if sensitive:
            rule = "traversal_probe" if sensitive == "traversal" else "sensitive_file_probe"
            direct[(entity, source, rule, sensitive, "Sensitive-file or traversal probe")].append((row, source))
        for rule, pattern in EXPLOIT_SIGNATURES.items():
            if any(pattern.search(value) for value in inspected):
                direct[(entity, source, rule, family, "Decoded exploit signature: " + rule)].append((row, source))
        agent = (row.user_agent or "")[:MAX_USER_AGENT_LENGTH].lower()
        if any(marker in agent for marker in SCANNER_USER_AGENT_MARKERS):
            direct[(entity, source, "known_scanner", family, "Known scanner user agent")].append((row, source))
        if row.timestamp >= now - timezone.timedelta(minutes=ERROR_BURST_MINUTES) and 400 <= row.status_code < 500:
            errors[(entity, source)].append((row, source))
        protected = _protected_family(path)
        if (protected and row.status_code in (401, 403)
                and row.timestamp >= now - timezone.timedelta(seconds=DENIAL_WINDOW_SECONDS)):
            denials[(entity, source, protected)].append((row, source))
    matches = [_match(rows, rule, family, reason)
               for (_, _, rule, family, reason), rows in direct.items()]
    for rows in errors.values():
        if len(rows) >= ERROR_BURST_MINIMUM and len({normalize_target_family(row.path) for row, _ in rows}) >= ERROR_BURST_DISTINCT_PATHS:
            matches.append(_match(rows, "broad_client_error_probe", "broad-client-error",
                                  "High-volume client-error path probing", critical=False))
    for (_, _, family), rows in denials.items():
        if len(rows) >= DENIAL_MINIMUM:
            matches.append(_match(rows, "protected_path_denials", family,
                                  "Repeated unauthorized requests to protected endpoints",
                                  category="unauthorized", critical=False))
    return matches


def classify_token_denials(token_usages, *, now=None) -> list[DetectionMatch]:
    now = now or timezone.now()
    grouped = defaultdict(list)
    for row, source in _eligible_rows(token_usages, "created_at", now, DENIAL_WINDOW_SECONDS):
        if row.outcome == "denied" and row.denial_reason in TOKEN_DENIAL_REASONS:
            grouped[(getattr(row, "entity_id", None), source, normalize_target_family(row.path))].append((row, source))
    return [_match(rows, "api_key_denials", family, "Repeated denied API-key authentication",
                   token=True, category="unauthorized", critical=False)
            for (_, _, family), rows in grouped.items() if len(rows) >= DENIAL_MINIMUM]


def _access_log_alert_reasons(logs, now):
    alerts = {}
    for match in classify_access_logs(logs, now=now):
        for identifier in match.access_log_ids:
            _append_reason(alerts, identifier, match.reason)
    return alerts


def _user_session_alerts(sessions, now):
    alerts = {}
    recent_sessions = _in_window(
        sessions, "last_seen_at", now - timezone.timedelta(minutes=WINDOW_MINUTES)
    )
    sessions_by_user = defaultdict(list)
    for row in recent_sessions:
        sessions_by_user[row.user_id].append(row)
    for rows in sessions_by_user.values():
        session_count = len(rows)
        distinct_ip_count = len({row.ip for row in rows})
        distinct_user_agent_count = len({row.user_agent for row in rows})
        if (
            session_count >= CONCURRENT_SESSION_MINIMUM
            and distinct_ip_count >= CONCURRENT_SESSION_IP_MINIMUM
            and distinct_user_agent_count >= CONCURRENT_SESSION_USER_AGENT_MINIMUM
        ):
            rule_diagnostics = {
                "rule": "concurrent_session_heuristic",
                "window_minutes": WINDOW_MINUTES,
                "session_count": session_count,
                "distinct_ip_count": distinct_ip_count,
                "distinct_user_agent_count": distinct_user_agent_count,
                "required_session_count": CONCURRENT_SESSION_MINIMUM,
                "required_ip_count": CONCURRENT_SESSION_IP_MINIMUM,
                "required_user_agent_count": CONCURRENT_SESSION_USER_AGENT_MINIMUM,
            }
            for row in rows:
                alert = _critical_alert(
                    ["Account has concurrent sessions across multiple networks and clients"]
                )
                alert["rule_diagnostics"] = rule_diagnostics
                alerts[row.id] = alert
    return alerts


def _alert_evidence(logs, sessions, log_alerts, session_alerts):
    evidence = []
    for row in logs:
        alert = log_alerts.get(row.id)
        if alert:
            evidence.append(
                {
                    "source": "access_log",
                    "timestamp": row.timestamp.isoformat(),
                    "ip_address": row.ip_address,
                    "path": normalize_target_family(row.path),
                    "user_agent": _safe_scanner_marker(row.user_agent),
                    "reasons": alert["reasons"],
                }
            )
    for row in sessions:
        alert = session_alerts.get(row.id)
        if alert:
            user = getattr(row, "user", None)
            item = {
                "source": "user_session",
                "timestamp": row.last_seen_at.isoformat(),
                "user": user.get_username() if user else str(row.user_id),
                "ip_address": row.ip,
                "user_agent": _safe_scanner_marker(row.user_agent),
                "reasons": alert["reasons"],
            }
            if alert.get("rule_diagnostics"):
                item["rule_diagnostics"] = alert["rule_diagnostics"]
            evidence.append(item)
    return sorted(evidence, key=lambda item: item["timestamp"], reverse=True)


def analyze_security(access_logs=(), user_sessions=(), now=None):
    """Analyze supplied current collector records without persisting alert state."""
    now = now or timezone.now()
    logs = list(access_logs)
    sessions = list(user_sessions)
    log_reasons = _access_log_alert_reasons(logs, now)
    session_alerts = _user_session_alerts(sessions, now)
    log_alerts = {identifier: _critical_alert(reasons) for identifier, reasons in log_reasons.items()}
    evidence = _alert_evidence(logs, sessions, log_alerts, session_alerts)
    return SecurityAnalysis(
        access_log_alerts=log_alerts,
        user_session_alerts=session_alerts,
        summary={
            "critical_alert_count": len(evidence),
            "latest_alert_at": evidence[0]["timestamp"] if evidence else None,
            "window_minutes": WINDOW_MINUTES,
            "alerts": evidence,
        },
    )
