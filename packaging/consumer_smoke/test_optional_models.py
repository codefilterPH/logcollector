"""Optional host models must not make the installed collector crash."""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase

from log_collector.models import LogCollectorEntity


class OptionalModelTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        operator = get_user_model().objects.create_superuser(
            username="operator", email="operator@example.test", password="password"
        )
        operator.groups.add(Group.objects.create(name="DATA_CENTER"))
        cls.operator = operator
        cls.hosting = LogCollectorEntity.get_hosting_entity()

    def test_unconfigured_geolocation_returns_actionable_error(self):
        self.client.force_login(self.operator)
        response = self.client.get("/log-collector/api/entities/hosting-app/geolocation/")
        self.assertEqual(response.status_code, 503)
        self.assertIn("LOG_COLLECTOR_GEOLOCATION_MODEL", response.json()["detail"])

    def test_unconfigured_sessions_return_actionable_error(self):
        self.client.force_login(self.operator)
        response = self.client.get("/log-collector/api/entities/hosting-app/user-sessions/")
        self.assertEqual(response.status_code, 503)
        self.assertIn("LOG_COLLECTOR_USER_SESSION_MODEL", response.json()["detail"])

    def test_security_summary_works_without_session_model(self):
        self.client.force_login(self.operator)
        response = self.client.get("/log-collector/api/entities/hosting-app/security-summary/")
        self.assertEqual(response.status_code, 200)
