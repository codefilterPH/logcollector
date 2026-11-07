import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from crowdsec_integration.models import CrowdSecConnection
from crowdsec_integration.services import CrowdSecError, encrypt_password
from log_collector.models import (
    LogCollectorAuditEvent,
    LogCollectorEntity,
    NginxAccessLog,
    SecurityIncident,
)


class DashboardViewsTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.group = Group.objects.create(name="DATA_CENTER")
        cls.operator = get_user_model().objects.create_superuser(
            username="operator", password="password", email="operator@example.test"
        )
        cls.operator.groups.add(cls.group)
        cls.hosting = LogCollectorEntity.get_hosting_entity()

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(self.operator)

    def test_access_and_app_logs_partition_log_collector_paths(self):
        common = {
            "entity": self.hosting,
            "timestamp": timezone.now(),
            "ip_address": "192.0.2.10",
            "method": "GET",
            "status_code": 200,
            "source_path": "/var/log/nginx/access.log",
            "raw_line_hash": "a" * 64,
        }
        NginxAccessLog.objects.create(
            **common, path="/log-collector/api/entities/hosting-app/metrics/"
        )
        NginxAccessLog.objects.create(
            **{**common, "raw_line_hash": "b" * 64}, path="/metrics/"
        )
        url = f"/log-collector/api/entities/{self.hosting.slug}/access-logs/"

        access_paths = {row["path"] for row in self.client.get(url).json()["results"]}
        app_paths = {
            row["path"]
            for row in self.client.get(url, {"source": "app", "q": "metrics"}).json()["results"]
        }

        self.assertIn("/metrics/", access_paths)
        self.assertNotIn("/log-collector/api/entities/hosting-app/metrics/", access_paths)
        self.assertEqual(app_paths, {"/log-collector/api/entities/hosting-app/metrics/"})

    def test_access_alert_search_matches_displayed_latest_target(self):
        SecurityIncident.objects.create(
            entity=self.hosting,
            category=SecurityIncident.Category.MALICIOUS,
            severity=SecurityIncident.Severity.HIGH,
            confidence_score=0.9,
            source_ip="192.0.2.10",
            rule_code="test-rule",
            target_family="test-path",
            fingerprint="search-latest-target",
            first_seen_at=timezone.now(),
            last_seen_at=timezone.now(),
            request_count=1,
            latest_evidence={"path": "/public/search-canary-alpha/"},
        )
        url = f"/log-collector/api/entities/{self.hosting.slug}/security-incidents/"

        response = self.client.get(url, {"q": "search-canary-alpha"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)

    def test_collector_logs_search_uses_existing_audit_feed(self):
        LogCollectorAuditEvent.objects.create(
            entity=self.hosting,
            user=self.operator,
            event_type=LogCollectorAuditEvent.EventType.API_REQUEST,
            outcome="success",
            path="/log-collector/api/entities/hosting-app/metrics/",
            method="GET",
        )
        url = f"/log-collector/api/entities/{self.hosting.slug}/audit-events/"

        response = self.client.get(url, {"q": "metrics"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertIn("metrics", response.json()["results"][0]["path"])
        csv_response = self.client.get(url, {"q": "metrics", "export": "csv"})
        self.assertEqual(csv_response["Content-Type"], "text/csv")
        self.assertIn(b"metrics", csv_response.content)

    def test_dashboard_exposes_separate_views_and_crowdsec_subtabs(self):
        response = self.client.get(
            reverse("log_collector:entity_dashboard", args=[self.hosting.slug])
        )

        self.assertContains(response, 'data-tab="app-logs"')
        self.assertContains(response, 'data-tab="collector-logs"')
        self.assertContains(response, 'data-crowdsec-tab="detections"')
        self.assertContains(response, 'data-crowdsec-tab="decisions"')
        self.assertContains(response, "HOSTING APP")
        self.assertContains(response, self.hosting.name)
        self.assertContains(response, '>Refresh</button>')
        self.assertContains(response, 'id="refresh-status" role="status" aria-live="polite"')
        content = response.content.decode()
        self.assertLess(content.index('aria-label="Dashboard activity charts"'), content.index('id="dashboard-layout"'))
        header_styles = content.split(".header {", 1)[1].split("}", 1)[0]
        self.assertIn("justify-content:space-between", header_styles)
        self.assertIn("flex-wrap:wrap", header_styles)
        actions = content.split('<div class="header-actions">', 1)[1].split("</div>", 1)[0]
        self.assertIn('id="refresh-data"', actions)
        self.assertIn('id="refresh-status"', actions)
        action_styles = content.split(".header-actions {", 1)[1].split("}", 1)[0]
        self.assertIn("max-width:100%", action_styles)
        self.assertIn("flex-wrap:wrap", action_styles)
        narrow_styles = content.split("@media (max-width:760px)", 1)[1].split("</style>", 1)[0]
        self.assertIn(".header { align-items:flex-start; }", narrow_styles)
        self.assertContains(response, "grid-template-columns:repeat(3,minmax(0,1fr))")
        self.assertContains(response, "search.addEventListener('input'")
        self.assertContains(response, "url.searchParams.set('crowdsec'")

    def test_create_decision_requires_csrf_and_reports_api_failure(self):
        url = f"/log-collector/api/entities/{self.hosting.slug}/crowdsec/decisions/"
        CrowdSecConnection.objects.create(
            entity_id=self.hosting.pk,
            api_url="https://crowdsec.example.test",
            machine_id="smoke-test",
            encrypted_password=encrypt_password("test-password"),
        )
        payload = {"ip_address": "198.51.100.24", "duration": "4h", "reason": "smoke test"}
        body = json.dumps(payload)

        with patch("log_collector.views.crowdsec_request") as crowdsec_request:
            denied = self.client.post(url, body, content_type="application/json")
            self.assertEqual(denied.status_code, 403)
            crowdsec_request.assert_not_called()

            self.client.get(
                reverse("log_collector:entity_dashboard", args=[self.hosting.slug])
            )
            csrf_token = self.client.cookies["csrftoken"].value
            crowdsec_request.side_effect = CrowdSecError("upstream unavailable")
            failed = self.client.post(
                url,
                body,
                content_type="application/json",
                HTTP_X_CSRFTOKEN=csrf_token,
            )
            crowdsec_request.side_effect = None
            invalid = self.client.post(
                url,
                json.dumps({**payload, "duration": "soon"}),
                content_type="application/json",
                HTTP_X_CSRFTOKEN=csrf_token,
            )
            created = self.client.post(
                url,
                body,
                content_type="application/json",
                HTTP_X_CSRFTOKEN=csrf_token,
            )

        self.assertEqual(failed.status_code, 502)
        self.assertIn("upstream unavailable", failed.json()["detail"])
        self.assertNotIn("ok", failed.json())
        self.assertEqual(invalid.status_code, 400)
        self.assertNotIn("ok", invalid.json())
        self.assertEqual(created.status_code, 201)
        self.assertTrue(created.json()["ok"])
        self.assertEqual(created.json()["ip_address"], payload["ip_address"])
