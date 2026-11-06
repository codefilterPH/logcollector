"""Optional host application integrations for collector security actions."""

from dataclasses import dataclass

from django.apps import apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string


@dataclass(frozen=True)
class SecuritySMSRecipient:
    user: object
    phone_number: str


def configured_callable(setting_name):
    dotted_path = getattr(settings, setting_name, "")
    if not dotted_path:
        raise ImproperlyConfigured(f"{setting_name} must be configured to use this feature.")
    try:
        function = import_string(dotted_path)
    except ImportError as exc:
        raise ImproperlyConfigured(f"{setting_name} is not importable.") from exc
    if not callable(function):
        raise ImproperlyConfigured(f"{setting_name} must name a callable.")
    return function


def optional_model(setting_name):
    """Resolve a host model without importing a particular host application."""
    model_label = getattr(settings, setting_name, "")
    if not model_label:
        return None
    try:
        return apps.get_model(model_label)
    except (LookupError, ValueError) as exc:
        raise ImproperlyConfigured(
            f"{setting_name} must name an installed model as 'app_label.ModelName'."
        ) from exc


def contain_user_account(user):
    return configured_callable("LOG_COLLECTOR_ACCOUNT_CONTAINMENT_FUNCTION")(user)


def security_sms_recipients():
    return configured_callable("LOG_COLLECTOR_SMS_RECIPIENTS_FUNCTION")()


def send_mobile_sms(*, mobile_number, message, context):
    return configured_callable("LOG_COLLECTOR_SMS_SENDER_FUNCTION")(
        mobile_number=mobile_number, message=message, context=context
    )
