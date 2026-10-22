"""Server -> client event stream. Clients never send events (CONTRACTS section 6)."""
import json

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer


class _EventConsumer(AsyncWebsocketConsumer):
    group = None

    def get_group(self) -> str:
        raise NotImplementedError

    async def connect(self):
        user = self.scope.get("user")
        if user is None or not user.is_authenticated:
            await self.close()  # handshake rejected (HTTP 403) -> client treats it as "not logged in"
            return
        self.group = self.get_group()
        await self.channel_layer.group_add(self.group, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        if self.group:
            await self.channel_layer.group_discard(self.group, self.channel_name)

    async def sentinel_event(self, message):  # handles {"type": "sentinel.event", "payload": {...}}
        await self.send(text_data=json.dumps(message["payload"]))


class DashboardConsumer(_EventConsumer):
    def get_group(self):
        return "dashboard"


class SubmissionConsumer(_EventConsumer):
    def get_group(self):
        return f"submission.{self.scope['url_route']['kwargs']['sid']}"


@database_sync_to_async
def _device_for_headers(headers):
    from devices.auth import hash_token
    from devices.models import Device

    raw = dict(headers).get(b"authorization", b"").decode("utf-8", "replace")
    keyword, _, token = raw.partition(" ")
    if keyword != "Device" or not token.strip():
        return None
    return Device.objects.filter(token_hash=hash_token(token.strip()), revoked=False).first()


class DeviceConsumer(AsyncWebsocketConsumer):
    """Phone push channel: `Authorization: Device <token>` on the handshake; pipeline events for this device's
    submissions, so the phone reacts the moment a verdict or an analyst request exists (polling stays as fallback)."""

    group = None

    async def connect(self):
        device = await _device_for_headers(self.scope.get("headers", []))
        if device is None:
            await self.close()
            return
        self.group = f"device.{device.id}"
        await self.channel_layer.group_add(self.group, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        if self.group:
            await self.channel_layer.group_discard(self.group, self.channel_name)

    async def sentinel_event(self, message):
        await self.send(text_data=json.dumps(message["payload"]))
