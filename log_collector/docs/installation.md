# Installation

LOG Collector supports Python 3.12–3.13 and Django 6.0.x. Use a virtual
environment in the host Django project:

```shell
python -m pip install 'codefilterph-logcollector[redis,asgi]'
```

Add the apps and mount the HTTP URLs:

```python
INSTALLED_APPS += [
    "channels",
    "rest_framework",
    "crowdsec_integration.apps.CrowdSecIntegrationConfig",
    "log_collector.apps.LogCollectorConfig",
]

# In the project's urls.py:
urlpatterns += [path("log-collector/", include("log_collector.urls"))]
```

Keep Django's `auth`, `contenttypes`, and `sessions` apps installed. Apply the
database schema with `python manage.py migrate`. The collector uses
`AUTH_USER_MODEL`, so configure a custom user model before its first migration
if your project needs one.

Add `log_collector.middleware.SecurityIPBlockMiddleware` after Django's
`AuthenticationMiddleware` if application-level IP blocking is wanted. Give
authorized dashboard users membership in the `DATA_CENTER` group. A user also
needs `is_superuser=True` to open the Manage page or change configuration.

The default hosting entity is created on first access and has slug
`hosting-app`. Open `/log-collector/entities/hosting-app/manage/` as a
superuser to set the displayed app name, shared theme, and local collection
paths. An unset name displays **LOG Collector**.

See [Configuration](configuration.md) before enabling collection, WebSockets,
Celery, SMS, or Nginx edge blocking.
