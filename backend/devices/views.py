from django.db import transaction
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from pipeline.events import emit
from sentinel.errors import ApiError

from .auth import DeviceTokenAuthentication, hash_token, new_token
from .models import Command, Device
from .pairing import consume_pairing_code


class RegisterSerializer(serializers.Serializer):
    pairing_code = serializers.RegexField(r"^\d{6}$")
    device_name = serializers.CharField(max_length=120, default="Unnamed phone")
    android_version = serializers.CharField(max_length=20, required=False, allow_blank=True, default="")
    app_version = serializers.CharField(max_length=40, required=False, allow_blank=True, default="")


class RegisterView(APIView):
    """POST /api/v1/devices/register (no auth; throttled by the `pairing` scope)."""

    authentication_classes = []
    permission_classes = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "pairing"

    def post(self, request):
        ser = RegisterSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        data = ser.validated_data
        with transaction.atomic():
            code = consume_pairing_code(data["pairing_code"])
            if code is None:
                raise ApiError("pairing_failed", "That code is wrong or expired. Generate a new one.", 400)
            token = new_token()
            device = Device.objects.create(
                name=data["device_name"], android_version=data["android_version"],
                app_version=data["app_version"], token_hash=hash_token(token), last_seen=timezone.now())
        emit(None, "device", "registered", f"Device {device.name} paired", data={"device_id": str(device.id)})
        return Response({"device_id": str(device.id), "device_token": token}, status=status.HTTP_201_CREATED)


class HeartbeatView(APIView):
    authentication_classes = [DeviceTokenAuthentication]

    def post(self, request):
        device: Device = request.user
        previous = device.last_seen
        device.app_version = str(request.data.get("app_version", device.app_version))[:40]
        device.protection_on = bool(request.data.get("protection_on", device.protection_on))
        device.last_seen = timezone.now()
        device.save(update_fields=["app_version", "protection_on", "last_seen"])
        # Stored at most once per 30 s per device so the evidence chain is not flooded.
        if previous is None or (device.last_seen - previous).total_seconds() >= 30:
            emit(None, "device", "heartbeat", f"Heartbeat from {device.name}", level="debug",
                 data={"device_id": str(device.id), "protection_on": device.protection_on})
        return Response(status=status.HTTP_204_NO_CONTENT)


class CommandsView(APIView):
    """GET /api/v1/devices/me/commands?cursor=N -> commands with id > N (max 50)."""

    authentication_classes = [DeviceTokenAuthentication]

    def get(self, request):
        device: Device = request.user
        try:
            cursor = int(request.query_params.get("cursor", 0))
        except ValueError:
            raise ApiError("validation_error", "cursor must be an integer", 400)
        device.last_seen = timezone.now()
        device.save(update_fields=["last_seen"])
        commands = list(Command.objects.filter(device=device, id__gt=cursor).order_by("id")[:50])
        body = [{"id": c.id, "type": c.type, "payload": c.payload, "created_at": c.created_at.strftime("%Y-%m-%dT%H:%M:%SZ")}
                for c in commands]
        next_cursor = commands[-1].id if commands else cursor
        return Response({"commands": body, "next_cursor": next_cursor})


class AckCommandView(APIView):
    authentication_classes = [DeviceTokenAuthentication]

    def post(self, request, command_id: int):
        device: Device = request.user
        command = Command.objects.filter(pk=command_id, device=device).first()
        if command is None:
            raise ApiError("not_found", "No such command.", 404)
        if command.acked_at is None:
            command.acked_at = timezone.now()
            command.save(update_fields=["acked_at"])
            if command.type == "uninstall_proposed":
                from remediation.services import mark_delivered

                mark_delivered(command)
        return Response(status=status.HTTP_204_NO_CONTENT)
