import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class Device(models.Model):
    """A paired phone. The raw token is shown once at pairing; only its SHA-256 is stored."""

    is_authenticated = True  # DRF permission checks treat a paired device as an authenticated principal

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120, default="Unnamed phone")
    android_version = models.CharField(max_length=20, blank=True, default="")
    app_version = models.CharField(max_length=40, blank=True, default="")
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(null=True, blank=True)
    protection_on = models.BooleanField(default=True)
    revoked = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.name} ({str(self.id)[:8]})"

    @property
    def is_online(self) -> bool:
        return bool(self.last_seen) and (timezone.now() - self.last_seen).total_seconds() < 90


class PairingCode(models.Model):
    code = models.CharField(max_length=6)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    @property
    def is_usable(self) -> bool:
        return self.used_at is None and self.expires_at > timezone.now()


class Command(models.Model):
    """Server -> phone message, delivered by polling (CONTRACTS section 5)."""

    TYPES = ("verdict_notify", "uninstall_proposed", "uninstall_cancelled")

    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="commands")
    type = models.CharField(max_length=32)
    payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)
    acked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["id"]
