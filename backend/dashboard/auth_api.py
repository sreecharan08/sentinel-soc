"""Token auth for the Next.js dashboard (API.md section 2): login, refresh, me.

Access tokens are short-lived and sent as `Authorization: Bearer <access>`. The same access token authenticates
the WebSocket handshake via `?token=` (browsers cannot set headers on a WebSocket); see realtime/auth.py.
"""
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .permissions import is_analyst


def user_out(user) -> dict:
    return {"username": user.get_username(), "role": "analyst" if is_analyst(user) else "viewer"}


class LoginView(TokenObtainPairView):
    """POST {username, password} -> {access, refresh, user}."""

    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            from django.contrib.auth import get_user_model

            user = get_user_model().objects.get(username=request.data.get("username"))
            response.data["user"] = user_out(user)
        return response


class RefreshView(TokenRefreshView):
    """POST {refresh} -> {access}."""

    permission_classes = [AllowAny]
    authentication_classes: list = []


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(user_out(request.user))
