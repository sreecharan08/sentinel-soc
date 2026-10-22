import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class RemediationRequest(models.Model):
    """Ask one phone to uninstall one package. The user always confirms in Android (CONTRACTS section 4)."""

    STATES = ("pending", "delivered", "completed", "declined", "failed", "cancelled", "expired")
    OPEN_STATES = ("pending", "delivered")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    submission = models.ForeignKey("submissions.Submission", on_delete=models.CASCADE, related_name="remediations")
    device = models.ForeignKey("devices.Device", on_delete=models.CASCADE, related_name="remediations")
    package_name = models.CharField(max_length=255)
    app_label = models.CharField(max_length=200, blank=True, default="")
    action = models.CharField(max_length=32, default="uninstall")
    origin = models.CharField(max_length=16, choices=[("auto", "auto"), ("analyst", "analyst")])
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    state = models.CharField(max_length=16, default="pending")
    command = models.ForeignKey("devices.Command", null=True, blank=True, on_delete=models.SET_NULL)
    policy_snapshot = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    delivered_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    outcome_detail = models.TextField(blank=True, default="")
    note = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["device", "package_name", "state"])]

    @property
    def is_open(self) -> bool:
        return self.state in self.OPEN_STATES
