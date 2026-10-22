from django.shortcuts import get_object_or_404  # noqa: F401 - kept for symmetry with other apps
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from devices.auth import DeviceTokenAuthentication
from sentinel.errors import ApiError

from .models import RemediationRequest
from .services import handle_result


class ResultSerializer(serializers.Serializer):
    outcome = serializers.ChoiceField(choices=["uninstalled", "declined", "failed"])
    detail = serializers.CharField(max_length=500, required=False, allow_blank=True, default="")


class DeviceRemediationResultView(APIView):
    """POST /api/v1/remediations/{id}/result (device auth). Returns 204; 409 if the outcome conflicts."""

    authentication_classes = [DeviceTokenAuthentication]

    def post(self, request, rid):
        ser = ResultSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        rem = RemediationRequest.objects.filter(pk=rid, device=request.user).first()
        if rem is None:
            raise ApiError("not_found", "No such remediation request.", 404)
        handle_result(rem, ser.validated_data["outcome"], ser.validated_data["detail"])
        return Response(status=status.HTTP_204_NO_CONTENT)
