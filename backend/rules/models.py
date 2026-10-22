import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class GeneratedRule(models.Model):
    """A YARA or Sigma rule drafted from a verdict. Edits create a new draft version; approved rules never mutate."""

    KINDS = (("yara", "yara"), ("sigma", "sigma"))
    STATUSES = (("draft", "draft"), ("approved", "approved"), ("retired", "retired"))

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=8, choices=KINDS)
    name = models.CharField(max_length=80)
    content = models.TextField()
    status = models.CharField(max_length=10, choices=STATUSES, default="draft")
    level = models.CharField(max_length=8, default="medium")
    source_submission = models.ForeignKey("submissions.Submission", null=True, blank=True,
                                          on_delete=models.SET_NULL, related_name="rules")
    source_sha256 = models.CharField(max_length=64)
    verdict = models.ForeignKey("submissions.Verdict", null=True, blank=True, on_delete=models.SET_NULL)
    version = models.IntegerField(default=1)
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL, related_name="children")
    meta = models.JSONField(default=dict, blank=True)
    fp_test = models.JSONField(default=dict, blank=True)
    needs_review = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
                                    related_name="approved_rules")
    approved_at = models.DateTimeField(null=True, blank=True)
    retired_at = models.DateTimeField(null=True, blank=True)
    approve_note = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-created_at"]
        unique_together = [("name", "version")]

    def __str__(self) -> str:
        return f"{self.name} v{self.version} ({self.status})"


class RuleMatch(models.Model):
    rule = models.ForeignKey(GeneratedRule, on_delete=models.CASCADE, related_name="matches")
    submission = models.ForeignKey("submissions.Submission", on_delete=models.CASCADE, related_name="rule_matches")
    ts = models.DateTimeField(default=timezone.now)
    false_positive = models.BooleanField(default=False)
    marked_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ["-ts"]
