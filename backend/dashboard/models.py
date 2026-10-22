from django.conf import settings
from django.db import models
from django.utils import timezone


class SiteSetting(models.Model):
    """Runtime settings changed from the dashboard (Stage 5 section 5). Every change is also an event."""

    key = models.CharField(max_length=64, primary_key=True)
    value = models.JSONField(default=dict)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    updated_at = models.DateTimeField(default=timezone.now)

    def __str__(self) -> str:
        return self.key
