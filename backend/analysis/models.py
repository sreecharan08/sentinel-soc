from django.db import models
from django.utils import timezone


class Analysis(models.Model):
    """Stored Evidence for one sample at one ANALYSIS_VERSION (Stage 2 section 4, Stage 3 section 7)."""

    sample = models.ForeignKey("submissions.Sample", on_delete=models.CASCADE, related_name="analyses")
    analysis_version = models.IntegerField()
    evidence = models.JSONField(default=dict)
    partial = models.BooleanField(default=False)
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = [("sample", "analysis_version")]
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"analysis {self.sample_id[:8]} v{self.analysis_version}"
