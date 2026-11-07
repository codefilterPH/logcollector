"""Authenticated, read-only security incident and block notifications."""

import json
from urllib.parse import parse_qsl

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from log_collector.access import has_dashboard_access

from log_collector.models import LogCollectorEntity
from log_collector.security_events import sanitize_security_event, security_group_name


class SecurityEventsConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.security_group = None
        user = self.scope.get("user")
        credentials = {"token", "api_key", "api_token", "access_token", "authorization", "key"}
        query = self.scope.get("query_string", b"").decode("utf-8", errors="replace")
        if (not user or not user.is_authenticated or not user.is_active
                or any(key.lower() in credentials for key, _ in parse_qsl(query, keep_blank_values=True))):
            await self.close(code=4401)
            return
        if not await self.is_dashboard_member(user):
            await self.close(code=4403)
            return
        self.entity_id = await self.active_entity_id(self.scope["url_route"]["kwargs"]["slug"])
        if self.entity_id is None:
            await self.close(code=4404)
            return
        self.security_group = security_group_name(self.entity_id)
        await self.channel_layer.group_add(self.security_group, self.channel_name)
        await self.accept()

    @database_sync_to_async
    def is_dashboard_member(self, user):
        return has_dashboard_access(user)

    @database_sync_to_async
    def active_entity_id(self, slug):
        return LogCollectorEntity.objects.filter(slug=slug, is_active=True).values_list("pk", flat=True).first()

    async def disconnect(self, close_code):
        if self.security_group:
            await self.channel_layer.group_discard(self.security_group, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        # No client protocol: text, JSON actions and binary input have no effects.
        pass

    async def security_event(self, message):
        payload = message.get("event", {})
        if payload.get("entity_id") != self.entity_id:
            return
        event = sanitize_security_event(self.entity_id, payload.get("type"), payload)
        if event is not None:
            await self.send(text_data=json.dumps(event))
