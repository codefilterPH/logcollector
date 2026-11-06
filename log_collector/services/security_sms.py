from django.conf import settings
from django.db import IntegrityError, transaction

from log_collector.integrations import security_sms_recipients
from log_collector.models import (
    SecurityIncident,
    SecurityIncidentSMSAlert,
    SecurityIncidentSMSDelivery,
)
from log_collector.services.client_ip import is_trusted_security_ip


SECURITY_SMS_MESSAGE = (
    "URGENT: Suspicious brute-force or scanning activity was detected. "
    "Check Log Collector security logs now."
)
QUALIFYING_CATEGORIES = {
    SecurityIncident.Category.UNAUTHORIZED,
    SecurityIncident.Category.MALICIOUS,
}
QUALIFYING_SEVERITIES = {
    SecurityIncident.Severity.HIGH,
    SecurityIncident.Severity.CRITICAL,
}


def eligible_security_sms_recipients():
    return security_sms_recipients()


def is_qualifying_security_sms_incident(incident):
    return (
        incident.entity.is_hosting
        and not is_trusted_security_ip(incident.source_ip)
        and incident.category in QUALIFYING_CATEGORIES
        and incident.severity in QUALIFYING_SEVERITIES
    )


def create_security_sms_alert(incident):
    if not getattr(settings, "LOG_COLLECTOR_SECURITY_SMS_ENABLED", False):
        return None, False
    if not is_qualifying_security_sms_incident(incident):
        return None, False

    try:
        with transaction.atomic():
            alert, created = SecurityIncidentSMSAlert.objects.get_or_create(
                incident=incident
            )
            if not created:
                return alert, False

            deliveries = [
                SecurityIncidentSMSDelivery(
                    alert=alert,
                    user=recipient.user,
                    phone_number=recipient.phone_number,
                )
                for recipient in eligible_security_sms_recipients()
            ]
            SecurityIncidentSMSDelivery.objects.bulk_create(deliveries)
            if not deliveries:
                alert.status = SecurityIncidentSMSAlert.Status.NO_RECIPIENTS
                alert.save(update_fields=("status", "updated_at"))
            return alert, True
    except IntegrityError:
        return SecurityIncidentSMSAlert.objects.get(incident=incident), False


def refresh_security_sms_alert_status(alert_id):
    with transaction.atomic():
        alert = SecurityIncidentSMSAlert.objects.select_for_update().get(pk=alert_id)
        statuses = list(alert.deliveries.values_list("status", flat=True))
        if not statuses:
            status = SecurityIncidentSMSAlert.Status.NO_RECIPIENTS
        elif all(value == SecurityIncidentSMSDelivery.Status.SENT for value in statuses):
            status = SecurityIncidentSMSAlert.Status.SENT
        elif all(value == SecurityIncidentSMSDelivery.Status.FAILED for value in statuses):
            status = SecurityIncidentSMSAlert.Status.FAILED
        elif (
            SecurityIncidentSMSDelivery.Status.SENT in statuses
            and SecurityIncidentSMSDelivery.Status.FAILED in statuses
            and not any(
                value in {
                    SecurityIncidentSMSDelivery.Status.PENDING,
                    SecurityIncidentSMSDelivery.Status.SENDING,
                }
                for value in statuses
            )
        ):
            status = SecurityIncidentSMSAlert.Status.PARTIAL
        else:
            status = SecurityIncidentSMSAlert.Status.DISPATCHING
        if alert.status != status:
            alert.status = status
            alert.save(update_fields=("status", "updated_at"))
        return alert
