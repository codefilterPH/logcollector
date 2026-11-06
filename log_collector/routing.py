from urllib.parse import urlsplit

from channels.security.websocket import WebsocketDenier
from django.conf import settings
from django.http.request import split_domain_port, validate_host
from django.urls import path

from log_collector.consumers import SecurityEventsConsumer


class SecurityOriginValidator:
    """Require the browser Origin to match this socket's validated Host authority."""

    def __init__(self, application):
        self.application = application

    @staticmethod
    def parse_origin(value):
        if (not isinstance(value, str) or not value
                or any(ord(character) <= 32 or ord(character) >= 127 for character in value)
                or any(delimiter in value for delimiter in ("?", "#", "*", "\\"))):
            raise ValueError("Invalid security socket origin")
        origin = urlsplit(value)
        domain, _ = split_domain_port(origin.netloc.lower())
        if (origin.scheme not in ("http", "https") or not domain or not origin.netloc
                or origin.username is not None or origin.password is not None
                or origin.path or origin.query or origin.fragment or origin.netloc.endswith(":")):
            raise ValueError("An exact HTTP browser origin is required")
        port = origin.port if origin.port is not None else (443 if origin.scheme == "https" else 80)
        return origin.scheme, domain, port

    async def __call__(self, scope, receive, send):
        def header(name):
            values = [value for key, value in scope.get("headers", []) if key.lower() == name]
            if len(values) != 1:
                raise ValueError("Exactly one security socket authority header is required")
            value = values[0].decode("ascii")
            if not value or any(ord(character) <= 32 or ord(character) >= 127 for character in value):
                raise ValueError("Invalid security socket authority header")
            return value

        try:
            origin_value = header(b"origin")
            host_value = header(b"host")
            origin_scheme, origin_domain, origin_port = self.parse_origin(origin_value)
            host = urlsplit("//" + host_value)
            if any(delimiter in host_value for delimiter in ("?", "#", "*", "\\")):
                raise ValueError("An HTTP browser Origin is required")
            for authority in (host,):
                if (not authority.netloc or authority.username is not None or authority.password is not None
                        or authority.path or authority.query or authority.fragment):
                    raise ValueError("Invalid security socket authority")
            host_domain, _ = split_domain_port(host.netloc.lower())
            allowed = getattr(settings, "LOG_COLLECTOR_SECURITY_WEBSOCKET_ALLOWED_ORIGINS", [])
            if not isinstance(allowed, (list, tuple)):
                raise ValueError("Security socket origins must be a list of exact origins")
            configured = {self.parse_origin(value) for value in allowed}
            if configured:
                if (origin_scheme, origin_domain, origin_port) not in configured:
                    raise ValueError("Security socket origin is not configured")
            elif origin_scheme != {"ws": "http", "wss": "https"}.get(scope.get("scheme")):
                raise ValueError("Security socket origin scheme does not match")
            default_port = 443 if origin_scheme == "https" else 80
            host_port = host.port if host.port is not None else default_port
            if (host.netloc.endswith(":") or origin_domain != host_domain or origin_port != host_port
                    or not validate_host(host_domain, settings.ALLOWED_HOSTS)):
                raise ValueError("Security socket Origin does not match its allowed Host")
        except (UnicodeError, ValueError):
            # Reject before the authenticated consumer can accept or join a group.
            return await WebsocketDenier()(scope, receive, send)
        return await self.application(scope, receive, send)


websocket_urlpatterns = [
    path("ws/log-collector/entities/<slug:slug>/security/", SecurityOriginValidator(SecurityEventsConsumer.as_asgi())),
]
