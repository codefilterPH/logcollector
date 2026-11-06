import hashlib
import ipaddress
import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone


class LogCollectorEntity(models.Model):
    class EntityType(models.TextChoices):
        HOSTING = "hosting", "Hosting app"
        INTEGRATION = "integration", "Integrated system"

    name = models.CharField(max_length=120, unique=True)
    slug = models.SlugField(max_length=120, unique=True)
    entity_type = models.CharField(max_length=20, choices=EntityType.choices)
    is_active = models.BooleanField(default=True)
    api_base_url = models.URLField(blank=True)
    remote_entity_slug = models.SlugField(max_length=120, default="hosting-app")
    remote_api_key = models.CharField(max_length=255, blank=True)
    access_logs_enabled = models.BooleanField(default=True)
    geolocation_enabled = models.BooleanField(default=True)
    user_sessions_enabled = models.BooleanField(default=True)
    enable_api_endpoint = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    @classmethod
    def get_hosting_entity(cls):
        entity, _ = cls.objects.get_or_create(
            entity_type=cls.EntityType.HOSTING,
            defaults={
                "name": "Hosting App",
                "slug": "hosting-app",
                "is_active": True,
            },
        )
        LogCollectorSettings.for_entity(entity)
        return entity

    @property
    def is_hosting(self):
        return self.entity_type == self.EntityType.HOSTING

    def __str__(self):
        return self.name


class LogCollectorApiToken(models.Model):
    TOKEN_NAMESPACE = "lc"

    entity = models.ForeignKey(
        LogCollectorEntity, on_delete=models.CASCADE, related_name="api_tokens"
    )
    name = models.CharField(max_length=120)
    key_prefix = models.CharField(max_length=16, unique=True, db_index=True)
    key_hash = models.CharField(max_length=64, unique=True, editable=False)
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    allowed_ip_address = models.CharField(
        max_length=255,
        blank=True,
        help_text="Optional caller IP or CIDR range.",
    )
    allowed_origin_domain = models.CharField(
        max_length=255,
        blank=True,
        help_text="Optional Origin or Referer domain allowed to use this token.",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_log_collector_api_tokens",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_used_ip = models.GenericIPAddressField(null=True, blank=True)
    last_used_origin_domain = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-created_at", "-id")

    @classmethod
    def _generate_raw_key(cls):
        prefix = secrets.token_hex(4)
        secret = secrets.token_urlsafe(32)
        return prefix, f"{cls.TOKEN_NAMESPACE}_{prefix}_{secret}"

    @classmethod
    def hash_key(cls, raw_key):
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    @classmethod
    def parse_prefix(cls, raw_key):
        parts = (raw_key or "").split("_", 2)
        if len(parts) != 3 or parts[0] != cls.TOKEN_NAMESPACE:
            return None
        return parts[1] if parts[1] and parts[2] else None

    @classmethod
    def create_token(cls, entity, name, created_by=None, **kwargs):
        for _ in range(10):
            prefix, raw_key = cls._generate_raw_key()
            key_hash = cls.hash_key(raw_key)
            if not cls.objects.filter(key_prefix=prefix).exists():
                token = cls.objects.create(
                    entity=entity,
                    name=name,
                    key_prefix=prefix,
                    key_hash=key_hash,
                    created_by=created_by,
                    **kwargs,
                )
                return token, raw_key
        raise RuntimeError("Unable to generate a unique log collector API token.")

    def matches(self, raw_key):
        return secrets.compare_digest(self.key_hash, self.hash_key(raw_key or ""))

    def is_expired(self):
        return bool(self.expires_at and self.expires_at <= timezone.now())

    def is_usable(self):
        return self.is_active and not self.is_expired()

    def allows_ip(self, client_ip):
        if not self.allowed_ip_address:
            return True
        if not client_ip:
            return False
        try:
            network = ipaddress.ip_network(self.allowed_ip_address, strict=False)
            return ipaddress.ip_address(client_ip) in network
        except ValueError:
            return self.allowed_ip_address == client_ip

    def allows_origin_domain(self, origin_domain):
        if not self.allowed_origin_domain:
            return True
        if not origin_domain:
            return False
        allowed = self.allowed_origin_domain.lower().strip()
        supplied = origin_domain.lower().strip()
        return supplied == allowed or supplied.endswith(f".{allowed}")

    def record_usage(self, ip_address=None, origin_domain=""):
        self.last_used_at = timezone.now()
        self.last_used_ip = ip_address or None
        self.last_used_origin_domain = (origin_domain or "")[:255]
        self.save(
            update_fields=(
                "last_used_at",
                "last_used_ip",
                "last_used_origin_domain",
                "updated_at",
            )
        )

    def __str__(self):
        status = "active" if self.is_usable() else "inactive"
        return f"{self.name} ({self.key_prefix}, {status})"


class LogCollectorApiTokenUsage(models.Model):
    token = models.ForeignKey(
        LogCollectorApiToken,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="usage_logs",
    )
    entity = models.ForeignKey(
        LogCollectorEntity,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="api_token_usage",
    )
    token_name = models.CharField(max_length=120, blank=True)
    token_prefix = models.CharField(max_length=16, blank=True, db_index=True)
    path = models.CharField(max_length=500)
    method = models.CharField(max_length=12, blank=True)
    status_code = models.PositiveIntegerField(null=True, blank=True)
    outcome = models.CharField(max_length=32, default="allowed", db_index=True)
    denial_reason = models.CharField(max_length=64, blank=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    request_host = models.CharField(max_length=255, blank=True)
    origin_domain = models.CharField(max_length=255, blank=True, db_index=True)
    user_agent = models.CharField(max_length=512, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        label = self.token_name or self.token_prefix or "unknown token"
        return f"{label} {self.method} {self.path} {self.outcome}"


class LogCollectorIntegratedDomain(models.Model):
    entity = models.ForeignKey(
        LogCollectorEntity, on_delete=models.CASCADE, related_name="integrated_domains"
    )
    name = models.CharField(max_length=120)
    domain = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("domain",)
        constraints = [
            models.UniqueConstraint(
                fields=("entity", "domain"),
                name="unique_entity_domain",
            )
        ]

    def __str__(self):
        return f"{self.entity}: {self.domain}"


class LogCollectorSettings(models.Model):
    THEME_CHOICES = (
        ("light", "Light"),
        ("dark", "Dark"),
        ("green", "Green Log"),
        ("command-center", "Command Center"),
    )

    entity = models.OneToOneField(
        LogCollectorEntity, on_delete=models.CASCADE, related_name="collector_settings"
    )
    display_name = models.CharField(max_length=120, blank=True, default="")
    theme = models.CharField(max_length=20, choices=THEME_CHOICES, default="light")
    nginx_access_log_paths = models.JSONField(default=list, blank=True)
    sync_cooldown_seconds = models.PositiveIntegerField(
        default=getattr(settings, "LOG_COLLECTOR_SYNC_COOLDOWN_SECONDS", 5)
    )
    max_lines_per_sync = models.PositiveIntegerField(
        default=getattr(settings, "LOG_COLLECTOR_MAX_LINES_PER_SYNC", 5000)
    )
    retention_days = models.PositiveIntegerField(
        default=getattr(settings, "LOG_COLLECTOR_RETENTION_DAYS", 90)
    )
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def app_name(self):
        return self.display_name.strip() or "LOG Collector"

    @classmethod
    def for_entity(cls, entity):
        if not entity.is_hosting:
            return None
        return cls.objects.get_or_create(
            entity=entity,
            defaults={
                "nginx_access_log_paths": getattr(
                    settings,
                    "LOG_COLLECTOR_NGINX_ACCESS_LOG_PATHS",
                    ["/var/log/nginx/access.log"],
                )
            },
        )[0]


class LogCollectorFileCursor(models.Model):
    entity = models.ForeignKey(LogCollectorEntity, on_delete=models.CASCADE)
    source_path = models.CharField(max_length=500)
    offset = models.BigIntegerField(default=0)
    observed_size = models.BigIntegerField(default=0)
    last_synced_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("entity", "source_path"), name="unique_entity_log_cursor"
            )
        ]


class NginxAccessLog(models.Model):
    entity = models.ForeignKey(
        LogCollectorEntity, on_delete=models.CASCADE, related_name="access_logs"
    )
    timestamp = models.DateTimeField(db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    method = models.CharField(max_length=16)
    path = models.CharField(max_length=2048, db_index=True)
    query_string = models.TextField(blank=True)
    protocol = models.CharField(max_length=32, blank=True)
    status_code = models.PositiveSmallIntegerField(db_index=True)
    bytes_sent = models.BigIntegerField(null=True, blank=True)
    referrer = models.TextField(blank=True)
    user_agent = models.TextField(blank=True)
    source_path = models.CharField(max_length=500)
    raw_line_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-timestamp", "-id")
        constraints = [
            models.UniqueConstraint(
                fields=("entity", "source_path", "raw_line_hash"),
                name="unique_entity_log_line",
            )
        ]


class SecurityIncident(models.Model):
    class Category(models.TextChoices):
        UNAUTHORIZED = "unauthorized", "Unauthorized"
        MALICIOUS = "malicious", "Malicious"

    class Severity(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    entity = models.ForeignKey(
        LogCollectorEntity, on_delete=models.CASCADE, related_name="security_incidents"
    )
    category = models.CharField(max_length=16, choices=Category.choices)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    confidence_score = models.FloatField()
    source_ip = models.GenericIPAddressField()
    rule_code = models.CharField(max_length=64)
    target_family = models.CharField(max_length=255)
    fingerprint = models.CharField(max_length=64)
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    request_count = models.PositiveBigIntegerField(default=0)
    latest_evidence = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-last_seen_at", "-id")
        indexes = [
            models.Index(
                fields=("entity", "category", "-last_seen_at"),
                name="sec_inc_entity_cat_seen_idx",
            ),
            models.Index(
                fields=("entity", "severity", "-last_seen_at"),
                name="sec_inc_entity_sev_seen_idx",
            ),
            models.Index(
                fields=("source_ip", "-last_seen_at"), name="sec_inc_ip_seen_idx"
            ),
            models.Index(
                fields=("fingerprint", "-last_seen_at"), name="sec_inc_fingerprint_seen_idx"
            ),
        ]


class SecurityIncidentEvidence(models.Model):
    incident = models.ForeignKey(
        SecurityIncident, on_delete=models.CASCADE, related_name="evidence"
    )
    access_log = models.ForeignKey(
        NginxAccessLog,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="security_evidence",
    )
    token_usage = models.ForeignKey(
        LogCollectorApiTokenUsage,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="security_evidence",
    )
    observed_at = models.DateTimeField(default=timezone.now)
    reason = models.TextField(blank=True)
    payload = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("observed_at", "id")
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(access_log__isnull=False, token_usage__isnull=True)
                    | models.Q(access_log__isnull=True, token_usage__isnull=False)
                ),
                name="security_evidence_exactly_one_source",
            ),
            models.UniqueConstraint(
                fields=("access_log",),
                condition=models.Q(access_log__isnull=False),
                name="unique_security_evidence_access_log",
            ),
            models.UniqueConstraint(
                fields=("token_usage",),
                condition=models.Q(token_usage__isnull=False),
                name="unique_security_evidence_token_usage",
            ),
        ]


class SecurityIncidentSMSAlert(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        DISPATCHING = "dispatching", "Dispatching"
        SENT = "sent", "Sent"
        PARTIAL = "partial", "Partially sent"
        FAILED = "failed", "Failed"
        NO_RECIPIENTS = "no_recipients", "No recipients"

    incident = models.OneToOneField(
        SecurityIncident, on_delete=models.CASCADE, related_name="sms_alert"
    )
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.PENDING
    )
    dispatch_queued_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class SecurityIncidentSMSDelivery(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SENDING = "sending", "Sending"
        SENT = "sent", "Sent"
        FAILED = "failed", "Failed"

    alert = models.ForeignKey(
        SecurityIncidentSMSAlert, on_delete=models.CASCADE, related_name="deliveries"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    phone_number = models.CharField(max_length=20)
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.PENDING
    )
    last_error = models.TextField(blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("alert", "user"), name="unique_security_sms_alert_user"
            )
        ]


class BlockedIPAddress(models.Model):
    class Origin(models.TextChoices):
        MANUAL = "manual", "Manual"
        AUTOMATIC = "automatic", "Automatic"

    class DjangoState(models.TextChoices):
        ACTIVE = "active", "Active"
        INACTIVE = "inactive", "Inactive"

    class NginxState(models.TextChoices):
        NOT_CONFIGURED = "not_configured", "Not configured"
        PENDING = "pending", "Pending"
        APPLIED = "applied", "Applied"
        FAILED = "failed", "Failed"
        REMOVED = "removed", "Removed"
        REMOVE_FAILED = "remove_failed", "Removal failed"

    ip_address = models.GenericIPAddressField()
    origin = models.CharField(max_length=16, choices=Origin.choices)
    incident = models.ForeignKey(
        SecurityIncident,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ip_blocks",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_ip_blocks",
    )
    reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    desired_active = models.BooleanField(default=True)
    django_state = models.CharField(
        max_length=16, choices=DjangoState.choices, default=DjangoState.ACTIVE
    )
    nginx_state = models.CharField(
        max_length=16, choices=NginxState.choices, default=NginxState.NOT_CONFIGURED
    )
    last_error = models.TextField(blank=True)
    blocked_request_count = models.PositiveBigIntegerField(default=0)
    last_blocked_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at", "-id")
        constraints = [
            models.UniqueConstraint(
                fields=("ip_address",),
                condition=models.Q(desired_active=True),
                name="unique_active_blocked_ip_address",
            )
        ]
        indexes = [
            models.Index(
                fields=("desired_active", "expires_at"), name="ip_block_active_expiry_idx"
            ),
            models.Index(
                fields=("ip_address", "desired_active"), name="ip_block_ip_active_idx"
            ),
        ]


class IPBlockAuditEvent(models.Model):
    class Action(models.TextChoices):
        REQUESTED = "requested", "Requested"
        APPLIED = "applied", "Applied"
        FAILED = "failed", "Failed"
        EXPIRED = "expired", "Expired"
        UNBLOCKED = "unblocked", "Unblocked"

    block = models.ForeignKey(
        BlockedIPAddress, on_delete=models.CASCADE, related_name="audit_events"
    )
    incident = models.ForeignKey(
        SecurityIncident,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="block_audit_events",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ip_block_audit_events",
    )
    action = models.CharField(max_length=32, choices=Action.choices)
    previous_django_state = models.CharField(
        max_length=16, choices=BlockedIPAddress.DjangoState.choices, blank=True
    )
    new_django_state = models.CharField(
        max_length=16, choices=BlockedIPAddress.DjangoState.choices, blank=True
    )
    previous_nginx_state = models.CharField(
        max_length=16, choices=BlockedIPAddress.NginxState.choices, blank=True
    )
    new_nginx_state = models.CharField(
        max_length=16, choices=BlockedIPAddress.NginxState.choices, blank=True
    )
    reason = models.TextField(blank=True)
    details = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ("-timestamp", "-id")


class LogCollectorAuditEvent(models.Model):
    class EventType(models.TextChoices):
        PAGE_VIEW = "page_view", "Page view"
        TAB_LOAD = "tab_load", "Tab load"
        API_REQUEST = "api_request", "API request"
        SYNC = "sync", "On-demand sync"
        DENIED = "denied", "Denied access"

    entity = models.ForeignKey(
        LogCollectorEntity,
        on_delete=models.CASCADE,
        related_name="audit_events",
        null=True,
        blank=True,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    api_key_name = models.CharField(max_length=255, blank=True)
    event_type = models.CharField(max_length=32, choices=EventType.choices)
    path = models.CharField(max_length=500)
    method = models.CharField(max_length=12, blank=True)
    outcome = models.CharField(max_length=32, default="success")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ("-created_at", "-id")
