from django.apps import AppConfig


class LogCollectorConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "log_collector"

    def ready(self):
        from django.core.checks import register

        from log_collector.services.client_ip import check_security_cidrs

        register(check_security_cidrs)
