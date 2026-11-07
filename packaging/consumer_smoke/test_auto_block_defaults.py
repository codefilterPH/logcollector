from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from log_collector.models import BlockedIPAddress, LogCollectorEntity, SecurityIncident
from log_collector.services import blocking, response


class AutomaticBlockDefaultTests(TestCase):
    def create_incident(self):
        entity = LogCollectorEntity.get_hosting_entity()
        now = timezone.now()
        incident = SecurityIncident.objects.create(
            entity=entity,
            category=SecurityIncident.Category.MALICIOUS,
            severity=SecurityIncident.Severity.HIGH,
            confidence_score=0.9,
            source_ip="8.8.4.4",
            rule_code="test_rule",
            target_family="/test",
            fingerprint="f" * 64,
            first_seen_at=now,
            last_seen_at=now,
        )
        return incident, now

    def test_missing_setting_enables_automatic_blocking(self):
        with patch.object(blocking, "settings", SimpleNamespace()):
            self.assertTrue(blocking.is_auto_block_enabled())

    def test_missing_evidence_age_uses_nine_hundred_second_default(self):
        with patch.object(blocking, "settings", SimpleNamespace()):
            self.assertEqual(blocking.auto_block_max_evidence_age_seconds(), 900)

    def test_explicit_false_disables_automatic_blocking(self):
        with patch.object(blocking, "settings", SimpleNamespace(
            LOG_COLLECTOR_AUTO_BLOCK_ENABLED=False,
        )):
            self.assertFalse(blocking.is_auto_block_enabled())

    def test_opt_out_skips_direct_block_creation(self):
        incident, now = self.create_incident()
        with patch.object(blocking, "settings", SimpleNamespace(
            LOG_COLLECTOR_AUTO_BLOCK_ENABLED=False,
        )):
            result = blocking.block_ip(
                incident.source_ip,
                origin="automatic",
                reason=incident.rule_code,
                incident=incident,
                now=now,
            )

        self.assertEqual(result.status, "disabled")
        self.assertFalse(result.created)
        self.assertFalse(BlockedIPAddress.objects.filter(ip_address=incident.source_ip).exists())

    def test_reconciliation_runs_without_host_auto_block_settings(self):
        with patch.object(blocking, "settings", SimpleNamespace()):
            result = response.reconcile_recent_security_incidents(now=timezone.now())

        self.assertEqual(result, {"incidents_reconciled": 0, "blocks_created": 0, "exempt": 0})

    def test_automatic_block_applies_without_optional_nginx_helper_setting(self):
        incident, now = self.create_incident()

        with patch.object(blocking, "settings", SimpleNamespace()):
            result = blocking.block_ip(
                incident.source_ip,
                origin="automatic",
                reason=incident.rule_code,
                incident=incident,
                now=now,
            )

        self.assertTrue(result.created)
        self.assertTrue(result.django_applied)
        self.assertEqual(result.nginx_state, BlockedIPAddress.NginxState.NOT_CONFIGURED)
