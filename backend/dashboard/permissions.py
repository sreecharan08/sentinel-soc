from rest_framework.permissions import SAFE_METHODS, BasePermission


def is_analyst(user) -> bool:
    return bool(user and user.is_authenticated and (user.is_superuser or user.groups.filter(name="analyst").exists()))


def is_viewer(user) -> bool:
    return bool(user and user.is_authenticated)


class AnalystWriteOrReadOnly(BasePermission):
    """Viewers may GET; analysts may POST/PUT (Stage 5 section 5, CONTRACTS roles)."""

    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return is_viewer(request.user)
        return is_analyst(request.user)
