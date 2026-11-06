# Configuration

## Nginx collection

Set `LOG_COLLECTOR_NGINX_ACCESS_LOG_PATHS` to the Nginx access-log files that
the Django and worker processes can read. The default path is
`/var/log/nginx/access.log`; set `[]` when no local file is available. The
reader accepts Nginx common and combined access-log entries. Configure the
hosting entity's paths, cooldown, maximum lines per sync, and retention on its
Manage page. Access-log rotation must leave new files readable by workers.

## ASGI and WebSockets

Set `ASGI_APPLICATION` and a production `CHANNEL_LAYERS` backend, such as
`channels_redis`, in the host project. Include the collector route under the
host's authenticated ASGI WebSocket application:

```python
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
from log_collector.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(URLRouter(websocket_urlpatterns)),
})
```

The route is `/ws/log-collector/entities/<slug>/security/`. Its origin
validator is part of the route. Set the host's `ALLOWED_HOSTS` correctly and
configure `LOG_COLLECTOR_SECURITY_WEBSOCKET_ALLOWED_ORIGINS` when browser
origins differ from the WebSocket host.

## Celery

Configure a Celery broker, worker, and beat scheduler in the host project.
The default queue handles `log_collector.tasks.collect_analyze_and_respond`,
`expire_security_blocks`, and `retry_security_edge_actions`. Schedule the
first task at the desired polling interval (five seconds in the original
deployment) and the latter two at one-minute intervals. An `sms` queue worker
is required when security SMS is enabled; route `queue_security_incident_sms_alert`,
`send_security_incident_sms_chunk`, and `retry_security_incident_sms_alert` there.
Collection can also run on dashboard/API requests, but continuous collection
requires beat and a worker.

## Optional host integrations

The local geolocation and user-session APIs need models supplied by the host:

```python
LOG_COLLECTOR_GEOLOCATION_MODEL = "your_geo_app.UserLocation"
LOG_COLLECTOR_USER_SESSION_MODEL = "your_sessions_app.UserSession"
```

The geolocation model must expose `user`, `captured_at`, `ip_address`,
`latitude`, `longitude`, `country`, and `city`; the session model must expose
`user`, `session_key`, `ip`, `created_at`, `last_seen_at`, and `user_agent`.
Disable the entity's geolocation or user-session feature when no compatible
model exists. With an enabled feature but no model configured, its local API
returns HTTP 503 naming the missing setting; security summaries still work
without session data. Remote entities use the remote collector API instead.


The package does not assume a particular user-profile or SMS provider. Set
the following to importable dotted Python callables when using those actions:

- `LOG_COLLECTOR_ACCOUNT_CONTAINMENT_FUNCTION`: accepts a user and returns an
  object with `as_dict()` describing revoked authentication state.
- `LOG_COLLECTOR_SMS_RECIPIENTS_FUNCTION`: returns iterable
  `SecuritySMSRecipient(user, phone_number)` values from
  `log_collector.integrations`.
- `LOG_COLLECTOR_SMS_SENDER_FUNCTION`: accepts `mobile_number`, `message`, and
  `context` keyword arguments.

`LOG_COLLECTOR_SECURITY_SMS_ENABLED` defaults to false. Enable it only after
the recipient and sender functions, provider, and `sms` worker are configured.
The optional Nginx edge-block helper is supplied and reviewed by the host;
the wheel does not install privileged executables. See [Operations](operations-guide.md).
