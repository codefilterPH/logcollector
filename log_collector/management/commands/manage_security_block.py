from datetime import timedelta
from ipaddress import ip_address
from math import isfinite

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from log_collector.models import BlockedIPAddress
from log_collector.services.blocking import block_ip, unblock_ip


class Command(BaseCommand):
    help = "List, block, or unblock security IPs using the shared audited lifecycle."

    def add_arguments(self, parser):
        commands = parser.add_subparsers(dest="action", required=True)
        commands.add_parser("list")
        block = commands.add_parser("block")
        block.add_argument("ip")
        block.add_argument("--reason", required=True)
        duration = block.add_mutually_exclusive_group()
        duration.add_argument("--hours", type=float)
        duration.add_argument("--permanent", action="store_true")
        unblock = commands.add_parser("unblock")
        unblock.add_argument("ip")
        unblock.add_argument("--reason", required=True)

    def _print_block(self, block):
        self.stdout.write(f"{block.ip_address} desired_active={block.desired_active} "
                          f"django={block.django_state} nginx={block.nginx_state} "
                          f"expires_at={block.expires_at.isoformat() if block.expires_at else 'permanent'}")

    def handle(self, *args, **options):
        if options["action"] == "list":
            for block in BlockedIPAddress.objects.all().iterator(chunk_size=100):
                self._print_block(block)
            return
        try:
            ip = str(ip_address(options["ip"]))
            if options["action"] == "block":
                hours = options.get("hours")
                if hours is not None and (not isfinite(hours) or hours <= 0):
                    raise ValueError("--hours must be positive and finite")
                expiry = None if options.get("permanent") else timezone.now() + timedelta(hours=hours if hours is not None else 24)
                result = block_ip(ip, origin="manual", reason=options["reason"], expires_at=expiry)
                if result.status == "exempt":
                    raise CommandError("Trusted IP is exempt: django=inactive nginx=not_configured")
            else:
                block = BlockedIPAddress.objects.filter(ip_address=ip, desired_active=True).first()
                if block is None:
                    block = BlockedIPAddress.objects.filter(ip_address=ip).first()
                if block is None:
                    self.stdout.write(f"{ip} django=inactive nginx=no_active_block")
                    return
                result = unblock_ip(block, reason=options["reason"])
            self._print_block(result.block)
        except (ValueError, OverflowError) as exc:
            raise CommandError(str(exc)) from exc
