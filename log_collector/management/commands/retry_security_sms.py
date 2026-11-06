from django.core.management.base import BaseCommand, CommandError

from log_collector.models import SecurityIncidentSMSAlert, SecurityIncidentSMSDelivery
from log_collector.tasks import retry_security_incident_sms_alert


class Command(BaseCommand):
    help = "Queue an explicit retry for pending or failed security SMS deliveries."

    def add_arguments(self, parser):
        parser.add_argument("--incident-id", type=int, required=True)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        alert = SecurityIncidentSMSAlert.objects.filter(
            incident_id=options["incident_id"]
        ).first()
        if alert is None:
            raise CommandError("No security SMS alert exists for that incident.")
        retryable = alert.deliveries.filter(
            status__in=(
                SecurityIncidentSMSDelivery.Status.PENDING,
                SecurityIncidentSMSDelivery.Status.FAILED,
            )
        ).count()
        self.stdout.write(
            f"{retryable} retryable delivery{'ies' if retryable != 1 else ''} "
            f"for incident {alert.incident_id}."
        )
        if options["dry_run"] or not retryable:
            return
        retry_security_incident_sms_alert.delay(alert.pk)
        self.stdout.write(self.style.SUCCESS("Security SMS retry queued."))
