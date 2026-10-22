"""/api/v1/dash/* - the only endpoints the dashboard uses (Stage 5 section 1, principle 2). GET: viewer. POST: analyst."""
from __future__ import annotations

import re

from django.conf import settings
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponse
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from devices.models import Command, Device
from devices.pairing import create_pairing_code
from pipeline.events import emit
from pipeline.state import set_status
from pipeline.tasks import enqueue_pipeline
from rules import services as rule_services
from rules.generators import generate_for
from rules.models import GeneratedRule, RuleMatch
from sentinel.errors import ApiError
from submissions.models import AnalystAction, Submission
from submissions.services import current_verdict, effective_label

from . import payloads
from .permissions import AnalystWriteOrReadOnly
from .settings_store import set_setting

VALID_LABELS = ("malicious", "suspicious", "benign", "unknown")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _page(request, qs, row_fn):
    try:
        size = min(int(request.query_params.get("page_size", 25)), 100)
    except ValueError:
        size = 25
    page = Paginator(qs, size).get_page(request.query_params.get("page", 1))
    return Response({"count": page.paginator.count,
                     "next": None if not page.has_next() else f"?page={page.next_page_number()}",
                     "previous": None if not page.has_previous() else f"?page={page.previous_page_number()}",
                     "results": [row_fn(o) for o in page.object_list]})


def _get_sub(sid) -> Submission:
    sub = Submission.objects.select_related("device", "sample").filter(pk=sid).first()
    if sub is None:
        raise ApiError("not_found", "No such submission.", 404)
    return sub


class StatsView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        return Response(payloads.stats())


class SubmissionListView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        qs = Submission.objects.select_related("device").order_by("-created_at")
        status_f = request.query_params.get("status")
        if status_f == "in_progress":
            from pipeline.state import IN_PROGRESS

            qs = qs.filter(status__in=IN_PROGRESS)
        elif status_f:
            qs = qs.filter(status=status_f)
        device = request.query_params.get("device")
        if device:
            qs = qs.filter(device_id=device)
        q = request.query_params.get("q", "").strip()
        if q:
            qs = qs.filter(Q(package_name__icontains=q) | Q(app_label__icontains=q))
        label = request.query_params.get("label")
        if label in VALID_LABELS:
            ids = [s.id for s in qs[:500] if effective_label(s) == label]
            qs = qs.filter(id__in=ids)
        return _page(request, qs, payloads.submission_row)


class SubmissionDetailView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request, sid):
        return Response(payloads.submission_detail(_get_sub(sid)))


class SubmissionEventsView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request, sid):
        sub = _get_sub(sid)
        try:
            since = int(request.query_params.get("since_event_id", 0))
        except ValueError:
            raise ApiError("validation_error", "since_event_id must be an integer", 400)
        return Response({"events": payloads.events_since(sub, since)})


class OverrideView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    class Body(serializers.Serializer):
        label = serializers.ChoiceField(choices=VALID_LABELS)
        note = serializers.CharField(min_length=5, max_length=500)
        notify = serializers.BooleanField(required=False, default=True)

    def post(self, request, sid):
        ser = self.Body(data=request.data)
        ser.is_valid(raise_exception=True)
        sub = _get_sub(sid)
        if current_verdict(sub) is None:
            raise ApiError("state_conflict", "That can't be done in the current state.", 409, {"status": sub.status})
        before = effective_label(sub)
        AnalystAction.objects.create(submission=sub, user=request.user, kind="override", from_label=before,
                                     to_label=ser.validated_data["label"], note=ser.validated_data["note"])
        verdict = current_verdict(sub)
        label = ser.validated_data["label"]
        emit(sub, "verdict", "analyst_override", f"Analyst set the verdict to {label}",
             level="warn", data={"from": before, "to": label, "user": request.user.get_username()})
        if ser.validated_data["notify"]:
            Command.objects.create(device=sub.device, type="verdict_notify", payload={
                "submission_id": str(sub.id), "package_name": sub.package_name, "app_label": sub.app_label,
                "label": label, "confidence": verdict.confidence,
                "summary": f"Analyst review: {label}."})
            emit(sub, "verdict", "notified_device", "The phone was told about the new verdict",
                 data={"command": "verdict_notify"})
        return Response(payloads.submission_row(_get_sub(sid)))


class ReanalyzeView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request, sid):
        sub = _get_sub(sid)
        if sub.status not in ("verdict_ready", "error"):
            raise ApiError("state_conflict", "That can't be done in the current state.", 409, {"status": sub.status})
        if not sub.sample.file_path:
            raise ApiError("state_conflict", "The app file is no longer stored.", 409, {"status": "sample_missing"})
        AnalystAction.objects.create(submission=sub, user=request.user, kind="reanalyze")
        set_status(sub, "queued", error_code="", error_detail="")
        emit(sub, "system", "reanalyze", "Analyst requested a new analysis")
        enqueue_pipeline(sub.id)
        return Response({"status": "queued"}, status=status.HTTP_202_ACCEPTED)


class DeviceListView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        return Response({"devices": [payloads.device_row(d) for d in Device.objects.all()[:200]]})


class PairingCodeView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request):
        code = create_pairing_code(request.user)
        return Response({"code": code.code, "expires_at": payloads.iso(code.expires_at)},
                        status=status.HTTP_201_CREATED)


class SettingsView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        return Response(payloads.settings_out())

    def post(self, request):
        key, value = request.data.get("key"), request.data.get("value")
        try:
            set_setting(str(key), value, request.user)
        except KeyError:
            raise ApiError("validation_error", f"Unknown setting {key}", 400)
        except ValueError as exc:
            raise ApiError("validation_error", str(exc), 400)
        return Response(payloads.settings_out())


class ReputationView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]
    FILES = {"bad_hash": "bad_sha256.txt", "good_hash": "good_sha256.txt", "bad_signer": "bad_signers.txt"}

    def post(self, request):
        kind, value = request.data.get("kind"), str(request.data.get("value", "")).strip().lower()
        if kind not in self.FILES:
            raise ApiError("validation_error", "kind must be bad_hash, good_hash or bad_signer", 400)
        if not HEX64.match(value):
            raise ApiError("validation_error", "value must be a 64-character lowercase SHA-256", 400)
        path = settings.SENTINEL["REPUTATION_DIR"] / self.FILES[kind]
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        if value not in [line.strip().lower() for line in existing]:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(value + "\n")
        emit(None, "system", "settings_changed", f"Reputation list {kind} updated",
             data={"kind": kind, "value_prefix": value[:12], "user": request.user.get_username()})
        return Response(payloads.settings_out(), status=status.HTTP_201_CREATED)


class RuleListView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        qs = GeneratedRule.objects.all()
        for field in ("status", "kind"):
            value = request.query_params.get(field)
            if value:
                qs = qs.filter(**{field: value})
        q = request.query_params.get("q", "").strip()
        if q:
            qs = qs.filter(name__icontains=q)
        return _page(request, qs, payloads.rule_out)


class RuleDetailView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request, rid):
        rule = _get_rule(rid)
        versions = GeneratedRule.objects.filter(name=rule.name).order_by("-version")
        matches = RuleMatch.objects.filter(rule=rule).select_related("submission")[:20]
        return Response({
            "rule": {**payloads.rule_out(rule), "content": rule.content, "meta": rule.meta,
                     "approve_note": rule.approve_note, "needs_review": rule.needs_review},
            "versions": [payloads.rule_out(v) for v in versions],
            "matches": [{"id": m.id, "submission_id": str(m.submission_id),
                         "package_name": m.submission.package_name, "ts": payloads.iso(m.ts),
                         "false_positive": m.false_positive} for m in matches],
        })

    def put(self, request, rid):
        rule = _get_rule(rid)
        content = request.data.get("content", "")
        if not isinstance(content, str) or not content.strip():
            raise ApiError("validation_error", "content is required", 400)
        new = rule_services.edit_as_new_version(rule, content, request.user)
        return Response(payloads.rule_out(new), status=status.HTTP_201_CREATED)


class RuleApproveView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request, rid):
        rule = rule_services.approve(_get_rule(rid), request.user, str(request.data.get("note", "")).strip())
        return Response(payloads.rule_out(rule))


class RuleRetireView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request, rid):
        rule = rule_services.retire(_get_rule(rid), request.user, str(request.data.get("note", "")).strip())
        return Response(payloads.rule_out(rule))


class RuleValidateView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request, rid):
        rule = _get_rule(rid)
        content = request.data.get("content", rule.content)
        errors = []
        try:
            if rule.kind == "yara":
                from rules.generators import validate_yara_text

                validate_yara_text(content)
            else:
                from rules.sigma import UnsupportedSigma, load

                try:
                    load(content)
                except UnsupportedSigma as exc:
                    errors.append(str(exc))
        except ApiError as exc:
            errors.append(exc.message)
        return Response({"valid": not errors, "errors": errors})


class RuleFpTestView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request, rid):
        rule = rule_services.run_fp_test(_get_rule(rid))
        return Response(payloads.rule_out(rule))


class MatchFalsePositiveView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request, mid):
        match = RuleMatch.objects.select_related("rule").filter(pk=mid).first()
        if match is None:
            raise ApiError("not_found", "No such match.", 404)
        rule_services.mark_false_positive(match, request.user)
        return Response({"id": match.id, "false_positive": True, "rule_needs_review": True})


class RulesExportView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        resp = HttpResponse(rule_services.export_zip(), content_type="application/zip")
        resp["Content-Disposition"] = 'attachment; filename="sentinel-rules.zip"'
        return resp


class GenerateRulesView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request, sid):
        sub = _get_sub(sid)
        created = generate_for(sub, force=True)
        return Response({"created": [str(r.id) for r in created]}, status=status.HTTP_202_ACCEPTED)


def _get_rule(rid) -> GeneratedRule:
    rule = GeneratedRule.objects.filter(pk=rid).first()
    if rule is None:
        raise ApiError("not_found", "No such rule.", 404)
    return rule


class DemoPreflightView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        from evalkit.preflight import run_preflight

        return Response(run_preflight())


class DemoResetView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request):
        if request.data.get("confirm") != "reset":
            raise ApiError("validation_error", 'Send {"confirm": "reset"} to reset demo data.', 400)
        from evalkit.demo import reset_demo

        reset_demo(user=request.user)
        return Response({"status": "reset"}, status=status.HTTP_202_ACCEPTED)


class DemoMarkerView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request):
        label = str(request.data.get("label", "")).strip()[:120]
        if not label:
            raise ApiError("validation_error", "label is required", 400)
        emit(None, "system", "marker", label, data={"user": request.user.get_username()})
        return Response({"label": label}, status=status.HTTP_201_CREATED)


class DemoFaultView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request):
        if not settings.SENTINEL["DEV_FAULTS"]:
            raise ApiError("forbidden", "Fault drills are disabled on this server.", 403)
        fault = request.data.get("fault")
        if fault not in (None, "reasoner_error", "analysis_timeout", "slow_reasoner", "upload_drop"):
            raise ApiError("validation_error", "unknown fault", 400)
        set_setting("fault", fault, request.user)
        return Response({"fault": fault})


class EvalLatestView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        from evalkit.report import latest_summary

        return Response(latest_summary())


class EvidencePackView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        from evalkit.evidence_pack import build_zip

        resp = HttpResponse(build_zip(), content_type="application/zip")
        resp["Content-Disposition"] = 'attachment; filename="sentinel-evidence-pack.zip"'
        return resp


class DemoSimulateView(APIView):
    """POST /dash/demo/simulate: push the two fixed demo APKs to the USB-connected phone (works offline)."""

    permission_classes = [AnalystWriteOrReadOnly]

    def post(self, request):
        from evalkit.simulate import simulate

        result = simulate(port=int(request.get_port() or 9000), user=request.user)
        return Response(result, status=status.HTTP_200_OK if result["delivered"] else status.HTTP_502_BAD_GATEWAY)
