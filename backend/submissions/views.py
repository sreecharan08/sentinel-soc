from django.conf import settings
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from devices.auth import DeviceTokenAuthentication
from sentinel.errors import ApiError

from .models import Submission
from .services import create_submission, current_verdict, effective_label, summary_of
from .upload import receive_apk

PKG_RE = r"^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*$"


class SubmissionCreateSerializer(serializers.Serializer):
    package_name = serializers.RegexField(PKG_RE, max_length=255)
    app_label = serializers.CharField(max_length=200, required=False, allow_blank=True, default="")
    version_name = serializers.CharField(max_length=100, required=False, allow_blank=True, default="")
    version_code = serializers.IntegerField(min_value=0, required=False, default=0)
    installer_package = serializers.CharField(max_length=255, required=False, allow_null=True, allow_blank=True)
    first_install_time = serializers.DateTimeField(required=False, allow_null=True)
    requested_permissions = serializers.ListField(child=serializers.CharField(max_length=200),
                                                  max_length=1000, required=False, default=list)
    apk_sha256 = serializers.RegexField(r"^[0-9a-f]{64}$")
    apk_size_bytes = serializers.IntegerField(min_value=0)
    split_count = serializers.IntegerField(min_value=0, required=False, default=0)


class SubmissionCreateView(APIView):
    authentication_classes = [DeviceTokenAuthentication]

    def post(self, request):
        ser = SubmissionCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        data = ser.validated_data
        if data["apk_size_bytes"] > settings.SENTINEL["MAX_APK_MB"] * 1024 * 1024:
            raise ApiError("apk_too_large", "The app file is larger than the allowed limit.", 413)
        sub, need_upload, cached = create_submission(request.user, data)
        return Response({"submission_id": str(sub.id), "status": sub.status, "need_upload": need_upload,
                         "cached_verdict": cached}, status=status.HTTP_201_CREATED)


class SubmissionUploadView(APIView):
    authentication_classes = [DeviceTokenAuthentication]

    def put(self, request, sid):
        sub = Submission.objects.select_related("sample").filter(pk=sid, device=request.user).first()
        if sub is None:
            raise ApiError("not_found", "No such submission.", 404)
        declared = request.META.get("HTTP_X_CONTENT_SHA256", "").strip().lower()
        if not declared:
            raise ApiError("validation_error", "X-Content-SHA256 header is required.", 400)
        length = request.META.get("CONTENT_LENGTH")
        receive_apk(sub, request, declared, int(length) if length and length.isdigit() else None)
        return Response(status=status.HTTP_202_ACCEPTED)


_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _evidence_for_device(verdict) -> dict:
    """The signals and network indicators behind a verdict, for the phone's "why" screen and threat graph."""
    evidence = verdict.analysis.evidence if verdict.analysis else {}
    signals = sorted(evidence.get("signals") or [], key=lambda s: _SEVERITY_ORDER.get(s.get("severity"), 9))
    strings = ((evidence.get("static") or {}).get("strings") or {})
    return {
        "signals": [{"id": s.get("id", ""), "name": s.get("name", ""), "severity": s.get("severity", "info"),
                     "category": s.get("category", ""), "detail": (s.get("detail") or "")[:160]} for s in signals[:40]],
        "iocs": {
            "urls": (strings.get("urls") or [])[:20],
            "domains": (strings.get("domains") or [])[:20],
            "ips": (strings.get("ips") or [])[:20],
            "flagged_hosts": strings.get("flagged_hosts") or {},
            "telegram_bot": bool(strings.get("telegram_bot")),
        },
    }


class DeviceSubmissionView(APIView):
    """GET /api/v1/submissions/{id} (device-scoped)."""

    authentication_classes = [DeviceTokenAuthentication]

    def get(self, request, sid):
        sub = Submission.objects.filter(pk=sid, device=request.user).first()
        if sub is None:
            raise ApiError("not_found", "No such submission.", 404)
        verdict = current_verdict(sub)
        from pipeline.models import PipelineEvent

        events = list(PipelineEvent.objects.filter(submission=sub).order_by("-id")[:80])[::-1]
        body = {"submission_id": str(sub.id), "status": sub.status, "status_label": sub.status_label,
                "verdict": None, "remediation": None,
                # The pipeline steps so far, oldest first, for the phone's live scan timeline.
                "timeline": [{"stage": e.stage, "step": e.step, "level": e.level, "message": e.message,
                              "ts": e.ts.strftime("%Y-%m-%dT%H:%M:%SZ")} for e in events]}
        if verdict is not None:
            body["verdict"] = {
                "label": effective_label(sub) or verdict.label,
                "confidence": verdict.confidence,
                "summary": summary_of(verdict.payload.get("explanation", "")),
                "recommended_action": verdict.payload.get("recommended_action", "none"),
                "techniques": [{"id": t["id"], "name": t["name"], "tactic": t.get("tactic", ""),
                                "confidence": t.get("confidence", 0.0), "evidence_ids": t.get("evidence_ids", [])}
                               for t in verdict.payload.get("techniques", [])],
                "provider": f'{verdict.provider_name} v{verdict.provider_version}',
                "score": verdict.score,
                **_evidence_for_device(verdict),
            }
        from remediation.models import RemediationRequest

        rem = RemediationRequest.objects.filter(submission=sub).order_by("-created_at").first()
        if rem is not None:
            body["remediation"] = {"id": str(rem.id), "state": rem.state, "package_name": rem.package_name}
        return Response(body)
