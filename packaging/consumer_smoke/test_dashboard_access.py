from asgiref.sync import async_to_sync
from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import path, reverse

from log_collector.access import has_dashboard_access
from log_collector.consumers import SecurityEventsConsumer
from log_collector.models import LogCollectorEntity


class UserScopeApplication:
    def __init__(self, user):
        self.user = user
        self.application = URLRouter(
            [path("ws/<slug:slug>/", SecurityEventsConsumer.as_asgi())]
        )

    async def __call__(self, scope, receive, send):
        await self.application({**scope, "user": self.user}, receive, send)


async def websocket_connects_for(user):
    communicator = WebsocketCommunicator(
        UserScopeApplication(user), "/ws/hosting-app/"
    )
    connected, _ = await communicator.connect()
    if connected:
        await communicator.disconnect()
    return connected


class DashboardAccessTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.cybersecurity, _ = Group.objects.get_or_create(name="CYBERSECURITY")
        cls.data_center, _ = Group.objects.get_or_create(name="DATA_CENTER")
        cls.cybersecurity_user = get_user_model().objects.create_user(
            username="cybersecurity-operator", password="password"
        )
        cls.cybersecurity_user.groups.add(cls.cybersecurity)
        cls.data_center_user = get_user_model().objects.create_user(
            username="data-center-operator", password="password"
        )
        cls.data_center_user.groups.add(cls.data_center)
        cls.unassigned_user = get_user_model().objects.create_user(
            username="unassigned-operator", password="password"
        )
        cls.hosting = LogCollectorEntity.get_hosting_entity()

    def test_either_group_grants_dashboard_and_session_api_access(self):
        for user in (self.cybersecurity_user, self.data_center_user):
            self.client.force_login(user)
            dashboard = self.client.get(
                reverse("log_collector:entity_dashboard", args=[self.hosting.slug])
            )
            metrics = self.client.get(
                reverse("log_collector:api_metrics", args=[self.hosting.slug])
            )
            self.assertEqual(dashboard.status_code, 200)
            self.assertEqual(metrics.status_code, 200)

    def test_user_without_either_group_is_denied_dashboard_access(self):
        self.client.force_login(self.unassigned_user)
        response = self.client.get(
            reverse("log_collector:entity_dashboard", args=[self.hosting.slug])
        )
        self.assertEqual(response.status_code, 403)

    def test_cybersecurity_membership_does_not_grant_superuser_actions(self):
        self.client.force_login(self.cybersecurity_user)
        response = self.client.get(
            reverse("log_collector:entity_manage", args=[self.hosting.slug])
        )
        self.assertEqual(response.status_code, 403)

    def test_access_helper_accepts_only_the_two_access_groups(self):
        self.assertTrue(has_dashboard_access(self.cybersecurity_user))
        self.assertTrue(has_dashboard_access(self.data_center_user))
        self.assertFalse(has_dashboard_access(self.unassigned_user))

    def test_cybersecurity_member_can_connect_to_security_websocket(self):
        self.assertTrue(async_to_sync(websocket_connects_for)(self.cybersecurity_user))

    def test_data_center_member_can_connect_to_security_websocket(self):
        self.assertTrue(async_to_sync(websocket_connects_for)(self.data_center_user))

    def test_unassigned_user_cannot_connect_to_security_websocket(self):
        self.assertFalse(async_to_sync(websocket_connects_for)(self.unassigned_user))
