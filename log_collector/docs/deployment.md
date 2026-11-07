# Linux deployment: Celery and WebSockets

This guide shows one production pattern for a Django host using Linux, systemd,
Nginx, Redis, and Gunicorn for HTTP. Replace every `<PLACEHOLDER>` with the
host project's value before using the examples. The collector package provides
Django features and Celery tasks; `pip install` does not configure Redis,
systemd, Nginx, Celery, or an ASGI server, and does not start any service.

## Install the Python dependencies

Install the Redis channel-layer and Daphne extras in the same virtual
environment used by Django. Celery itself is a required package dependency;
the `asgi` extra installs Daphne, while `redis` installs the Python Redis
channel backend. These extras do not install or configure a Redis server.

```shell
python -m pip install 'codefilterph-logcollector[redis,asgi]'
```

Make sure the host has a reachable Redis server and replace
`<PROJECT_PACKAGE>` below with the Python package that contains the host
project's `settings.py` and `asgi.py`.

## Configure Channels and Celery

Add the channel layer to the host project's Django settings. This example uses
Redis database 1 for Channels and database 0 as Celery's broker; adjust the
addresses and credentials to match the host's Redis deployment.

```python
# <PROJECT_PACKAGE>/settings.py
ASGI_APPLICATION = "<PROJECT_PACKAGE>.asgi.application"
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {"hosts": ["redis://127.0.0.1:6379/1"]},
    },
}

CELERY_BROKER_URL = "redis://127.0.0.1:6379/0"
CELERY_RESULT_BACKEND = "redis://127.0.0.1:6379/0"
CELERY_TIMEZONE = "UTC"
```

Keep credentials in the host's protected environment or secret store in
production. The result backend is optional for these collector tasks; omit it
if the host does not need task results.

Create the host project's Celery application and schedule the collector's
periodic tasks. This example runs collection every five seconds and block
maintenance every minute.

```python
# <PROJECT_PACKAGE>/celery.py
import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "<PROJECT_PACKAGE>.settings")

app = Celery("<PROJECT_PACKAGE>")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
app.conf.beat_schedule = {
    "log-collector-collect": {
        "task": "log_collector.tasks.collect_analyze_and_respond",
        "schedule": 5.0,
    },
    "log-collector-expire-blocks": {
        "task": "log_collector.tasks.expire_security_blocks",
        "schedule": 60.0,
    },
    "log-collector-retry-edge-actions": {
        "task": "log_collector.tasks.retry_security_edge_actions",
        "schedule": 60.0,
    },
}
```

Expose the Celery app when the host package is imported:

```python
# <PROJECT_PACKAGE>/__init__.py
from .celery import app as celery_app

__all__ = ("celery_app",)
```

The `default` queue needs a continuously running worker for the scheduled
collection and maintenance tasks. If security SMS is enabled and configured,
run an additional worker consuming the `sms` queue. A worker without Beat can
process queued work but does not schedule recurring collection; Beat without a
worker only enqueues work.

## Configure the ASGI application

The host's ASGI app must serve normal HTTP through Django and route the
collector's authenticated WebSocket patterns. Add or adapt the host project's
`asgi.py`:

```python
import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "<PROJECT_PACKAGE>.settings")

django_asgi_app = get_asgi_application()
from log_collector.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(URLRouter(websocket_urlpatterns)),
})
```

The route is `/ws/log-collector/entities/<slug>/security/`. Keep the host's
`ALLOWED_HOSTS` correct. The socket Origin must match its Host, scheme, and
port. If `LOG_COLLECTOR_SECURITY_WEBSOCKET_ALLOWED_ORIGINS` is configured, the
exact browser origin must also be listed. See [Configuration](configuration.md)
for the origin setting details.

## Run services with systemd

The following unit files use a shared environment file and virtual environment.
Create `/etc/<APP_NAME>/environment` readable only by the service account and
administrators; put Django's `DJANGO_SETTINGS_MODULE`, database settings,
secret key, Redis URLs, and other host settings there. Set the project path,
virtual environment, module name, user, and group to real values. Keep this
file out of source control.

Create `/etc/systemd/system/<APP_NAME>-worker.service`:

```ini
[Unit]
Description=<APP_NAME> Celery worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=<SERVICE_USER>
Group=<SERVICE_GROUP>
WorkingDirectory=<PROJECT_ROOT>
EnvironmentFile=/etc/<APP_NAME>/environment
ExecStart=<VENV>/bin/celery -A <PROJECT_PACKAGE> worker --loglevel=INFO --queues=default
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/<APP_NAME>-beat.service`:

```ini
[Unit]
Description=<APP_NAME> Celery Beat scheduler
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=<SERVICE_USER>
Group=<SERVICE_GROUP>
WorkingDirectory=<PROJECT_ROOT>
EnvironmentFile=/etc/<APP_NAME>/environment
StateDirectory=<APP_NAME>-celery
ExecStart=<VENV>/bin/celery -A <PROJECT_PACKAGE> beat --loglevel=INFO --schedule=/var/lib/<APP_NAME>-celery/celerybeat-schedule
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/<APP_NAME>-asgi.service` to serve the ASGI app
with Daphne:

```ini
[Unit]
Description=<APP_NAME> Daphne ASGI server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=<SERVICE_USER>
Group=<SERVICE_GROUP>
WorkingDirectory=<PROJECT_ROOT>
EnvironmentFile=/etc/<APP_NAME>/environment
ExecStart=<VENV>/bin/daphne --proxy-headers -b 127.0.0.1 -p 8001 <PROJECT_PACKAGE>.asgi:application
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

If SMS alerts are enabled, add a unit using the worker unit settings with this
`ExecStart` instead:

```ini
ExecStart=<VENV>/bin/celery -A <PROJECT_PACKAGE> worker --loglevel=INFO --queues=sms --hostname=sms@%H
```

After saving the units, reload systemd, enable the services at boot, and check
their status:

```shell
sudo systemctl daemon-reload
sudo systemctl enable --now <APP_NAME>-worker <APP_NAME>-beat <APP_NAME>-asgi
sudo systemctl status <APP_NAME>-worker <APP_NAME>-beat <APP_NAME>-asgi
```

The host still needs its existing Gunicorn HTTP service. Ensure both Gunicorn
and the Celery worker service accounts can read every configured Nginx access
log. If those accounts differ, grant only the required read access.

## Proxy WebSockets through Nginx

Define the upgrade map once in Nginx's `http` context:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

In the HTTPS `server` block for the host, send the collector WebSocket route to
Daphne. Keep the existing `/` or application location routed to Gunicorn for
HTTP:

```nginx
location /ws/log-collector/ {
    proxy_pass http://127.0.0.1:8001;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 3600s;
    proxy_buffering off;
}
```

`$http_host` preserves a non-default port so the collector's Origin validation
can compare it to the browser Origin. Test the Nginx configuration before
reloading it, then check that the ASGI service is listening on the configured
loopback port.

## Troubleshooting

Use the actual unit names configured above in place of `<APP_NAME>`.

| Symptom | Checks |
| --- | --- |
| Metrics or security-incidents API returns HTTP 500 | Read the Gunicorn/Django traceback (`journalctl -u <APP_NAME>-web -n 200 --no-pager` or the host's configured application log); run `python manage.py check` and `python manage.py migrate`; confirm required host models and settings for optional integrations are configured. A 500 response alone does not identify the cause. |
| WebSocket route returns 404 or does not connect | Confirm `<APP_NAME>-asgi` is active, Daphne serves `<PROJECT_PACKAGE>.asgi:application`, and Nginx sends `/ws/log-collector/` to Daphne rather than Gunicorn. Inspect Nginx and ASGI unit logs; confirm the exact URL, `ALLOWED_HOSTS`, and allowed browser origins. |
| Access log is unreadable or collection imports no new rows | Confirm the hosting entity's path and `LOG_COLLECTOR_NGINX_ACCESS_LOG_PATHS`; check read permission as both the web and worker service users (for example, `sudo -u <SERVICE_USER> test -r /var/log/nginx/access.log`). Check log rotation preserves access for those users. |
| Last-sync cursor stops advancing | Check Beat and worker unit status and logs; verify Beat is scheduling `log_collector.tasks.collect_analyze_and_respond`, the worker consumes `default`, and both use the same Django settings and database as the web process. Confirm the log has new bytes and remains readable. |

View recent service output with:

```shell
sudo journalctl -u <APP_NAME>-worker -u <APP_NAME>-beat -u <APP_NAME>-asgi -n 200 --no-pager
```

See the [Operations guide](operations-guide.md) for ongoing deployment and
upgrade checks.
