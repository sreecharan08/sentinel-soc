"""Pairing codes: 6 digits, single-use, short TTL (CONTRACTS section 11: SENTINEL_PAIRING_TTL_MIN)."""
import secrets
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from .models import PairingCode


def create_pairing_code(user=None) -> PairingCode:
    ttl = settings.SENTINEL["PAIRING_TTL_MIN"]
    return PairingCode.objects.create(
        code=f"{secrets.randbelow(10**6):06d}",
        created_by=user,
        expires_at=timezone.now() + timedelta(minutes=ttl),
    )


def consume_pairing_code(code: str) -> PairingCode | None:
    """Return the usable code and mark it used, or None if unknown / expired / already used."""
    candidate = PairingCode.objects.filter(code=code, used_at__isnull=True, expires_at__gt=timezone.now()).first()
    if candidate is None:
        return None
    updated = PairingCode.objects.filter(pk=candidate.pk, used_at__isnull=True).update(used_at=timezone.now())
    return candidate if updated == 1 else None
