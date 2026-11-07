"""Disposable, host-independent Django settings for package verification."""

SECRET_KEY = "logcollector-consumer-smoke"
DEBUG = True
ALLOWED_HOSTS = ["testserver", "localhost"]
ROOT_URLCONF = "logcollector_smoke_urls"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "rest_framework",
    "channels",
    "crowdsec_integration",
    "log_collector",
]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
"django.middleware.csrf.CsrfViewMiddleware",
    "log_collector.middleware.SecurityIPBlockMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]
CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
LOG_COLLECTOR_NGINX_ACCESS_LOG_PATHS = []
LOG_COLLECTOR_TRUSTED_PROXY_CIDRS = []
LOG_COLLECTOR_TRUSTED_IP_CIDRS = ["127.0.0.0/8", "::1/128"]
LOG_COLLECTOR_NGINX_BLOCK_HELPER = ""
LOG_COLLECTOR_AUTO_BLOCK_ENABLED = False
LOG_COLLECTOR_SECURITY_SMS_ENABLED = False


class DisableMigrations(dict):
    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        return None


MIGRATION_MODULES = DisableMigrations()
