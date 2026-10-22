import hashlib
import secrets

from rest_framework import authentication, exceptions

from .models import Device


def new_token() -> str:
    return secrets.token_urlsafe(32)  # 43 URL-safe characters


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class DeviceTokenAuthentication(authentication.BaseAuthentication):
    """`Authorization: Device <token>` (CONTRACTS section 5)."""

    keyword = "Device"

    def authenticate(self, request):
        header = authentication.get_authorization_header(request).decode("utf-8", "replace")
        if not header:
            return None
        parts = header.split(" ", 1)
        if len(parts) != 2 or parts[0] != self.keyword:
            return None
        device = Device.objects.filter(token_hash=hash_token(parts[1].strip()), revoked=False).first()
        if device is None:
            raise exceptions.AuthenticationFailed("invalid_token")
        return (device, parts[1])

    def authenticate_header(self, request):
        return self.keyword
