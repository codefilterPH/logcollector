from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from log_collector.models import LogCollectorEntity
from log_collector.services.incidents import _backfill, backfill_entity_incidents


class Command(BaseCommand):
    help = "Classify historical collector evidence without creating IP blocks."

    def add_arguments(self, parser):
        parser.add_argument("--entity", default="hosting-app")
        parser.add_argument("--since-hours", type=float, default=24)
        parser.add_argument("--batch-size", type=int, default=1000)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        if options["since_hours"] <= 0 or options["batch_size"] < 1:
            raise CommandError("since-hours and batch-size must be positive")
        entity = LogCollectorEntity.objects.filter(slug=options["entity"]).first()
        if entity is None:
            raise CommandError("Collector entity does not exist")
        now = timezone.now()
        kwargs = dict(since=now - timedelta(hours=options["since_hours"]), batch_size=options["batch_size"], now=now)
        totals = (_backfill(entity, dry_run=True, **kwargs) if options["dry_run"]
                  else backfill_entity_incidents(entity, **kwargs))
        prefix = "dry-run " if options["dry_run"] else ""
        self.stdout.write(prefix + " ".join(f"{key}={value}" for key, value in totals.items()))
