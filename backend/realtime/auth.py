"""WebSocket auth for the Next.js dashboard: `?token=<access JWT>` on the handshake URL.

Falls back to the session-based scope user (legacy dashboard) when no token is given. An invalid or expired token
leaves the user anonymous, so the consumer closes the handshake exactly as it does for a missing session.
"""
from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from django.contrib.auth.models import AnonymousUser


@database_sync_to_async
def _user_for_token(raw: str):
    from rest_framework_simplejwt.authentication import JWTAuthentication
    from rest_framework_simplejwt.exceptions import TokenError

    auth = JWTAuthentication()
    try:
        return auth.get_user(auth.get_validated_token(raw))
    except (TokenError, Exception):  # noqa: BLE001 - anything wrong with the token means "not signed in"
        return AnonymousUser()


class JWTQueryAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        token = parse_qs(scope.get("query_string", b"").decode()).get("token", [None])[0]
        if token:
            scope = dict(scope)
            scope["user"] = await _user_for_token(token)
        return await super().__call__(scope, receive, send)
