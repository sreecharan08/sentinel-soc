"""Contract error body (CONTRACTS section 2): {"error": {"code", "message", "details"}}."""
from rest_framework import status
from rest_framework.exceptions import APIException, AuthenticationFailed, NotAuthenticated, PermissionDenied, Throttled
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler


class ApiError(APIException):
    def __init__(self, code: str, message: str, http_status: int = status.HTTP_400_BAD_REQUEST, details=None):
        self.status_code = http_status
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(detail=message)


def error_body(code: str, message: str, details=None) -> dict:
    return {"error": {"code": code, "message": message, "details": details or {}}}


def _device_view(context) -> bool:
    from devices.auth import DeviceTokenAuthentication

    view = (context or {}).get("view")
    return view is not None and any(isinstance(a, DeviceTokenAuthentication) or a is DeviceTokenAuthentication
                                    for a in getattr(view, "authentication_classes", []))


def exception_handler(exc, context):
    if isinstance(exc, ApiError):
        return _response(exc.status_code, exc.code, exc.message, exc.details)
    from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

    if isinstance(exc, (InvalidToken, TokenError)):
        return _response(401, "token_invalid", "Your session expired. Sign in again.")
    if isinstance(exc, AuthenticationFailed) and not _device_view(context):
        return _response(401, "invalid_credentials", "Incorrect username or password.")
    if isinstance(exc, AuthenticationFailed):
        return _response(401, "invalid_token", "This device is no longer paired. Pair it again.")
    if isinstance(exc, NotAuthenticated):
        if _device_view(context):
            return _response(401, "invalid_token", "This device is no longer paired. Pair it again.")
        return _response(403, "forbidden", "Sign in to continue.")
    if isinstance(exc, PermissionDenied):
        return _response(403, "forbidden", "You don't have permission to do that.")
    if isinstance(exc, Throttled):
        return _response(429, "rate_limited", "Too many requests. Wait a moment.", {"wait": exc.wait})
    response = drf_exception_handler(exc, context)
    if response is None:
        return None
    if response.status_code == 404:
        return _response(404, "not_found", "Not found.")
    if response.status_code == 400:
        return _response(400, "validation_error", str(response.data), _field_errors(response.data))
    return _response(response.status_code, "internal_error", str(response.data))


def _field_errors(data) -> dict:
    if isinstance(data, dict):
        return {k: [str(x) for x in v] if isinstance(v, list) else str(v) for k, v in data.items()}
    return {}


def _response(http_status, code, message, details=None):
    return Response(error_body(code, message, details), status=http_status)
