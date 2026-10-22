import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from pipeline.state import STATUS_LABELS


class Sample(models.Model):
    """One APK by content. The same file from two phones is analysed once (Stage 2 section 7)."""

    sha256 = models.CharField(primary_key=True, max_length=64)
    size_bytes = models.BigIntegerField(default=0)
    file_path = models.CharField(max_length=500, blank=True, default="")
    first_seen = models.DateTimeField(default=timezone.now)

    def __str__(self) -> str:
        return self.sha256[:12]


class Submission(models.Model):
    """One device x install event (CONTRACTS section 3)."""

    STATUSES = tuple(STATUS_LABELS.keys())

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey("devices.Device", on_delete=models.CASCADE, related_name="submissions")
    sample = models.ForeignKey(Sample, on_delete=models.PROTECT, related_name="submissions")
    package_name = models.CharField(max_length=255)
    app_label = models.CharField(max_length=200, blank=True, default="")
    version_name = models.CharField(max_length=100, blank=True, default="")
    version_code = models.BigIntegerField(default=0)
    installer_package = models.CharField(max_length=255, null=True, blank=True)
    first_install_time = models.DateTimeField(null=True, blank=True)
    requested_permissions = models.JSONField(default=list, blank=True)
    split_count = models.IntegerField(default=0)
    status = models.CharField(max_length=32, choices=[(s, s) for s in STATUSES], default="received")
    error_code = models.CharField(max_length=64, blank=True, default="")
    error_detail = models.TextField(blank=True, default="")
    loop_count = models.IntegerField(default=0)
    remediation_hold = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["-created_at"]),
            models.Index(fields=["package_name"]),
        ]

    def __str__(self) -> str:
        return f"{self.package_name} ({str(self.id)[:8]})"

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)


class Verdict(models.Model):
    """Verdict history for a submission. `is_current` marks the one that is shown and notified."""

    submission = models.ForeignKey(Submission, on_delete=models.CASCADE, related_name="verdicts")
    analysis = models.ForeignKey("analysis.Analysis", null=True, blank=True, on_delete=models.SET_NULL,
                                 related_name="verdicts")
    label = models.CharField(max_length=16)
    score = models.FloatField(default=0.0)
    confidence = models.FloatField(default=0.0)
    payload = models.JSONField(default=dict)
    provider_name = models.CharField(max_length=64)
    provider_version = models.CharField(max_length=32)
    fallback_from = models.CharField(max_length=64, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    is_current = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at", "-id"]


class AnalystAction(models.Model):
    """Append-only audit of analyst decisions (override, reanalyze, remediation, hold, note)."""

    KINDS = ("override", "reanalyze", "remediation", "remediation_cancel", "hold", "note")

    submission = models.ForeignKey(Submission, on_delete=models.CASCADE, related_name="analyst_actions")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    kind = models.CharField(max_length=32)
    from_label = models.CharField(max_length=16, null=True, blank=True)
    to_label = models.CharField(max_length=16, null=True, blank=True)
    note = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at", "-id"]
