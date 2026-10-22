"""Server-rendered pages. Each page embeds the same payload its API returns (json_script), and soc.js renders it.

Authentication: Django session. Writes are enforced by the API (AnalystWriteOrReadOnly); the templates only hide
write controls for viewers as a convenience.
"""
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_GET

from devices.models import Device
from remediation.models import RemediationRequest
from rules.models import GeneratedRule
from submissions.models import Submission

from . import payloads
from .permissions import is_analyst
from .settings_store import effective_settings


def _render(request, page: str, heading: str, data: dict):
    return render(request, "app.html", {"page_name": page, "heading": heading,
                                        "page_data": data, "is_analyst_flag": is_analyst(request.user)})


@login_required
@require_GET
def overview(request):
    subs = Submission.objects.select_related("device").order_by("-created_at")[:10]
    recent = list(reversed(payloads.recent_events(50)))
    return _render(request, "overview", "Overview", {
        "stats": payloads.stats(),
        "recent_submissions": [payloads.submission_row(s) for s in subs],
        "recent_events": recent,
    })


@login_required
@require_GET
def submissions(request):
    rows = [payloads.submission_row(s) for s in Submission.objects.select_related("device")[:25]]
    return _render(request, "submissions", "Submissions", {
        "page": {"count": Submission.objects.count(), "results": rows},
        "filters": {k: request.GET.get(k, "") for k in ("label", "status", "q", "device", "page")},
    })


@login_required
@require_GET
def submission_detail(request, sid):
    sub = get_object_or_404(Submission.objects.select_related("device", "sample"), pk=sid)
    return _render(request, "submission", f"{sub.app_label or sub.package_name}",
                   {"detail": payloads.submission_detail(sub), "submission_id": str(sub.id)})


@login_required
@require_GET
def devices(request):
    return _render(request, "devices", "Devices", {
        "devices": [payloads.device_row(d) for d in Device.objects.all()[:200]],
    })


@login_required
@require_GET
def remediation(request):
    from remediation.dash_views import remediation_row

    rows = [remediation_row(r) for r in RemediationRequest.objects.select_related("device", "created_by")[:100]]
    return _render(request, "remediation", "Remediation", {"requests": rows})


@login_required
@require_GET
def rules(request):
    qs = GeneratedRule.objects.all()[:100]
    return _render(request, "rules", "Rules", {"rules": [payloads.rule_out(r) for r in qs]})


@login_required
@require_GET
def rule_detail(request, rid):
    rule = get_object_or_404(GeneratedRule, pk=rid)
    return _render(request, "rule", rule.name, {"rule_id": str(rule.id)})


@login_required
@require_GET
def settings_page(request):
    return _render(request, "settings", "Settings", payloads.settings_out())


@login_required
@require_GET
def demo(request):
    return _render(request, "demo", "Demo console", {"show": effective_settings().get("show_demo_console")})


@login_required
@require_GET
def pipeline_console(request):
    return _render(request, "pipeline", "Pipeline console", {"events": list(reversed(payloads.recent_events(200)))})
