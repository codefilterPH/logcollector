import logging
from datetime import timedelta

from django.core.cache import cache
from django.db.models import F, Q
from django.http import HttpResponseForbidden, JsonResponse
from django.utils import timezone

from log_collector.models import BlockedIPAddress
from log_collector.services.client_ip import is_trusted_security_ip, resolve_client_ip


logger = logging.getLogger(__name__)


class SecurityIPBlockMiddleware:
    """Enforce deployment-wide blocks before application views and API logging."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        client_ip = resolve_client_ip(request)
        if not client_ip or is_trusted_security_ip(client_ip):
            return self.get_response(request)

        now = timezone.now()
        block = (
            BlockedIPAddress.objects.filter(ip_address=client_ip, desired_active=True)
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
            .only("pk")
            .first()
        )
        if block is None:
            return self.get_response(request)

        if cache.add(f"log-collector:block-hit:{block.pk}", 1, timeout=60):
            updated = (
                BlockedIPAddress.objects.filter(pk=block.pk)
                .filter(
                    Q(last_blocked_at__isnull=True)
                    | Q(last_blocked_at__lte=now - timedelta(seconds=60))
                )
                .update(
                    blocked_request_count=F("blocked_request_count") + 1,
                    last_blocked_at=now,
                )
            )
            if updated:
                logger.info(
                    "security_ip_block_denied",
                    extra={"block_id": block.pk, "client_ip": client_ip},
                )

        if request.path.startswith(("/api/", "/log-collector/api/")):
            return JsonResponse({"detail": "Forbidden."}, status=403)
        return HttpResponseForbidden("Forbidden.")
