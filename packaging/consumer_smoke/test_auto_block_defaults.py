from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from log_collector.services import blocking


class AutomaticBlockDefaultTests(TestCase):
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
