from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from log_collector.models import LogCollectorEntity, LogCollectorSettings


class CollectorAppearanceTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.group = Group.objects.create(name="DATA_CENTER")
        cls.superuser = get_user_model().objects.create_superuser(
            username="operator", password="password", email="operator@example.test"
        )
        cls.superuser.groups.add(cls.group)
        cls.viewer = get_user_model().objects.create_user(
            username="viewer", password="password"
        )
        cls.viewer.groups.add(cls.group)
        cls.hosting = LogCollectorEntity.get_hosting_entity()

    def test_unset_name_uses_default_and_credit_is_read_only(self):
        self.client.force_login(self.superuser)
        response = self.client.get(reverse("log_collector:entity_manage", args=[self.hosting.slug]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "LOG Collector")
        self.assertContains(response, "Developed by: CodefilterPH | Euge")
        self.assertNotContains(response, 'name="settings-author"')
        self.assertContains(response, 'aria-label="Collector settings"')
        self.assertContains(response, 'href="#general-settings"')
        self.assertContains(response, 'href="#api-access"')

    def test_browser_submit_saves_shared_appearance(self):
        self.client.force_login(self.superuser)
        response = self.client.post(
            reverse("log_collector:entity_manage", args=[self.hosting.slug]),
            {
                "save_settings": "",
                "settings-display_name": "North Operations",
                "settings-theme": "dark",
                "settings-nginx_access_log_paths": "[]",
                "settings-sync_cooldown_seconds": "5",
                "settings-max_lines_per_sync": "5000",
                "settings-retention_days": "90",
            },
        )
        self.assertEqual(response.status_code, 302)
        saved = LogCollectorSettings.for_entity(self.hosting)
        self.assertEqual((saved.display_name, saved.theme), ("North Operations", "dark"))

    def test_superuser_theme_and_name_are_shared_with_viewer(self):
        self.client.force_login(self.superuser)
        url = reverse("log_collector:entity_manage", args=[self.hosting.slug])
        response = self.client.post(
            url,
            {
                "save_settings": "1",
                "settings-display_name": "North Operations",
                "settings-theme": "dark",
                "settings-nginx_access_log_paths": "[]",
                "settings-sync_cooldown_seconds": "5",
                "settings-max_lines_per_sync": "5000",
                "settings-retention_days": "90",
            },
        )
        self.assertEqual(response.status_code, 302)
        saved = LogCollectorSettings.for_entity(self.hosting)
        saved.refresh_from_db()
        self.assertEqual(saved.display_name, "North Operations")
        self.assertEqual(saved.theme, "dark")

        self.client.force_login(self.viewer)
        selection = self.client.get(reverse("log_collector:entity_selection"))
        self.assertContains(selection, "North Operations")
        self.assertContains(selection, 'data-theme="dark"')
        self.assertNotContains(selection, "data-theme-option")
        forbidden = self.client.post(url, {"save_settings": "1"})
        self.assertEqual(forbidden.status_code, 403)
