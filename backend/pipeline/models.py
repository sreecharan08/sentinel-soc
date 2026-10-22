from django.db import models
from django.utils import timezone


class PipelineEvent(models.Model):
    """Append-only evidence chain. `id` is the WebSocket `event_id` (CONTRACTS section 6)."""

    STAGES = ("intake", "static_analysis", "dynamic_analysis", "reasoning", "verdict",
              "remediation", "rules", "device", "system")
    LEVELS = ("debug", "info", "warn", "error")

    submission = models.ForeignKey("submissions.Submission", null=True, blank=True,
                                   on_delete=models.CASCADE, related_name="events")
    stage = models.CharField(max_length=32)
    step = models.CharField(max_length=64)
    level = models.CharField(max_length=8, default="info")
    message = models.TextField()
    data = models.JSONField(default=dict, blank=True)
    ts = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["id"]
        indexes = [models.Index(fields=["submission", "id"])]

    def __str__(self) -> str:
        return f"{self.stage}/{self.step}: {self.message}"
