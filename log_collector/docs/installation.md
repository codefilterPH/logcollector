# Installation

LOG Collector supports Python 3.12–3.13 and Django 6.0.x. Use a virtual
environment in the host Django project:

```shell
python -m pip install 'codefilterph-logcollector[redis,asgi]'
```

The distribution includes both `log_collector` and `crowdsec_integration`. If
`manage.py` raises `ModuleNotFoundError: No module named 'crowdsec_integration'`,
confirm the package is installed in the same Python environment used to run
`manage.py`:

```shell
python -m pip show codefilterph-logcollector
python -c "import crowdsec_integration"
```

This release requires Python 3.12–3.13 and Django 6.0.x; it is not compatible
with Python 3.8 / Django 3.2 environments.

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

Before running any Django management command, including `makemigrations` or
`migrate`, define the required security CIDR settings in the host project's
`settings.py`:

```python
LOG_COLLECTOR_TRUSTED_PROXY_CIDRS = []
LOG_COLLECTOR_TRUSTED_IP_CIDRS = ["127.0.0.0/8", "::1/128"]
```

Set `LOG_COLLECTOR_TRUSTED_PROXY_CIDRS` to the CIDRs of proxies that connect
directly to Django. Leave it empty when Django receives requests directly. Set
`LOG_COLLECTOR_TRUSTED_IP_CIDRS` to the IP ranges your security policy trusts;
the example trusts loopback only.

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
