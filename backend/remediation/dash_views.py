"""Dashboard remediation endpoints (CONTRACTS section 5, Stage 6 section 4). GET: viewer. POST: analyst."""
from datetime import timedelta

from django.core.paginator import Paginator
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from dashboard.permissions import AnalystWriteOrReadOnly
from dashboard.settings_store import effective_settings
from sentinel.errors import ApiError
from submissions.models import Submission
from submissions.services import current_verdict, effective_label

from .models import RemediationRequest
from .policy import evaluate, is_protected
from .services import cancel, create_request, set_hold


def remediation_row(rem: RemediationRequest) -> dict:
    return {
        "id": str(rem.id), "submission_id": str(rem.submission_id), "package_name": rem.package_name,
        "app_label": rem.app_label, "device": {"id": str(rem.device_id), "name": rem.device.name},
        "origin": rem.origin, "state": rem.state, "created_at": rem.created_at.isoformat(),
        "expires_at": rem.expires_at.isoformat(), "resolved_at": rem.resolved_at.isoformat() if rem.resolved_at else None,
        "created_by": rem.created_by.get_username() if rem.created_by else None,
        "outcome_detail": rem.outcome_detail, "checks": rem.policy_snapshot.get("checks", []),
    }


class RemediationListView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        qs = RemediationRequest.objects.select_related("device", "created_by").all()
        state = request.query_params.get("state")
        if state:
            qs = qs.filter(state=state)
        page = Paginator(qs, 25).get_page(request.query_params.get("page", 1))
        return Response({"count": page.paginator.count, "results": [remediation_row(r) for r in page.object_list],
                         "next": None, "previous": None})


class ProposeView(APIView):
    """POST /dash/submissions/{id}/remediation  {action, note} (analyst). Guardrails for analysts are safety only."""

    permission_classes = [AnalystWriteOrReadOnly]

    class Body(serializers.Serializer):
        action = serializers.ChoiceField(choices=["uninstall"])
        note = serializers.CharField(max_length=500, required=False, allow_blank=True, default="")

    def post(self, request, sid):
        ser = self.Body(data=request.data)
        ser.is_valid(raise_exception=True)
        sub = Submission.objects.select_related("device").filter(pk=sid).first()
        if sub is None:
            raise ApiError("not_found", "No such submission.", 404)
        if current_verdict(sub) is None:
            raise ApiError("state_conflict", "That can't be done in the current state.", 409, {"status": sub.status})
        cfg = effective_settings()
        protected = set(cfg.get("protected_packages", []))
        if is_protected(sub.package_name, protected, cfg.get("own_package", "com.sentinel.soc")):
            raise ApiError("validation_error", f"{sub.package_name} is protected and cannot be targeted.", 400,
                           {"checks": [{"id": "not_protected", "passed": False}]})
        verdict = current_verdict(sub)
        now = timezone.now()
        decision = evaluate(
            "analyst", package=sub.package_name, label=effective_label(sub) or verdict.label,
            confidence=verdict.confidence, recommended_action=verdict.payload.get("recommended_action", "none"),
            settings=cfg, hold=sub.remediation_hold, device_last_seen=sub.device.last_seen,
            device_revoked=sub.device.revoked,
            open_request_exists=RemediationRequest.objects.filter(
                device=sub.device, package_name=sub.package_name, state__in=RemediationRequest.OPEN_STATES).exists(),
            recent_declined=RemediationRequest.objects.filter(
                device=sub.device, package_name=sub.package_name, state="declined",
                resolved_at__gte=now - timedelta(hours=24)).exists(),
            recent_count=0, protected=protected, own_package=cfg.get("own_package", "com.sentinel.soc"), now=now)
        if not decision.allowed:
            failed = [c for c in decision.checks if not c.passed and c.id in ("not_protected", "no_open_request", "device_active")]
            raise ApiError("state_conflict", "That can't be done in the current state.", 409,
                           {"status": "open_request_exists" if failed and failed[0].id == "no_open_request" else "blocked",
                            "checks": [{"id": c.id, "passed": c.passed, "detail": c.detail} for c in decision.checks]})
        rem = create_request(sub, origin="analyst", user=request.user, snapshot=decision.as_snapshot(),
                             note=ser.validated_data["note"])
        return Response({"remediation_id": str(rem.id), "state": rem.state,
                         "checks": decision.as_snapshot()["checks"]}, status=status.HTTP_201_CREATED)


class CancelView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request, rid):
        rem = RemediationRequest.objects.select_related("device", "submission").filter(pk=rid).first()
        if rem is None:
            raise ApiError("not_found", "No such remediation request.", 404)
        cancel(rem, request.user, request.data.get("note", "") if isinstance(request.data, dict) else "")
        return Response({"state": rem.state})


class HoldView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request, sid):
        sub = Submission.objects.filter(pk=sid).first()
        if sub is None:
            raise ApiError("not_found", "No such submission.", 404)
        hold = request.data.get("hold")
        if not isinstance(hold, bool):
            raise ApiError("validation_error", "hold must be true or false", 400)
        set_hold(sub, hold, request.user)
        return Response({"remediation_hold": sub.remediation_hold})
