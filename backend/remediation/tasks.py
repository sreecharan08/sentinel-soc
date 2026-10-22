from celery import shared_task


@shared_task(name="remediation.tasks.expire_remediations")
def expire_remediations() -> int:
    """Beat, every 10 min: open requests past REMEDIATION_TTL_HOURS become `expired` (Stage 6 section 3)."""
    from .services import expire_stale

    return expire_stale()
