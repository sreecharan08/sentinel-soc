"""Aggregate read endpoints added for the Next.js dashboard (API.md section 5). All GET, viewer role.

Everything here is derived from stored data (pipeline events, evidence, verdicts, devices, rules). Nothing is
simulated: when there is no data the lists are empty and the counters are zero.
"""
from __future__ import annotations

import os
from collections import Counter
from datetime import timedelta
from urllib.parse import urlparse

from django.conf import settings
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from devices.models import Device
from pipeline.health import health_report
from pipeline.models import PipelineEvent
from pipeline.state import IN_PROGRESS
from remediation.models import RemediationRequest
from rules.models import GeneratedRule, RuleMatch
from sentinel.errors import ApiError
from submissions.models import Sample, Submission, Verdict
from submissions.services import effective_label

from . import payloads
from .permissions import AnalystWriteOrReadOnly
from .settings_store import effective_settings

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
LEVEL_MAP = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "low"}


class EventsView(APIView):
    """GET /dash/events?since_event_id=&limit= -> latest pipeline events across all submissions (the live feed)."""

    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        try:
            since = int(request.query_params.get("since_event_id", 0))
            limit = max(1, min(int(request.query_params.get("limit", 50)), 200))
        except ValueError:
            raise ApiError("validation_error", "since_event_id and limit must be integers", 400)
        if since:
            return Response({"events": payloads.events_since(None, since, limit)})
        return Response({"events": list(reversed(payloads.recent_events(limit)))})


def _ioc_rows(limit_samples: int = 200) -> list[dict]:
    """IOCs (URLs, IPs, flagged hosts) across the latest analyses, with how many distinct samples reference each."""
    from analysis.models import Analysis

    seen: dict[str, dict] = {}
    rows = Analysis.objects.select_related("sample").order_by("-id")[:limit_samples]
    for row in rows:
        strings = (row.evidence or {}).get("static", {}).get("strings", {}) or {}
        sha = row.sample.sha256
        flagged = strings.get("flagged_hosts", {}) or {}
        for kind, values in (("url", strings.get("urls", [])), ("ip", strings.get("ips", [])),
                             ("host", list(flagged.keys()))):
            for value in values:
                entry = seen.setdefault(value, {"value": value, "kind": kind, "flagged": False, "samples": set()})
                entry["samples"].add(sha)
                entry["flagged"] = entry["flagged"] or value in flagged
    out = [{**e, "samples": len(e["samples"])} for e in seen.values()]
    out.sort(key=lambda e: (-e["samples"], e["value"]))
    return out


class NetworkView(APIView):
    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        now = timezone.now()
        day_ago = now - timedelta(hours=24)

        # events per minute over the last hour (pipeline throughput)
        buckets = [0] * 60
        for ts in PipelineEvent.objects.filter(ts__gte=now - timedelta(minutes=60)).values_list("ts", flat=True):
            idx = 59 - int((now - ts).total_seconds() // 60)
            if 0 <= idx < 60:
                buckets[idx] += 1

        alerts = []
        matches = RuleMatch.objects.filter(ts__gte=day_ago, false_positive=False).select_related(
            "rule", "submission")[:60]
        for m in matches:
            alerts.append({"ts": payloads.iso(m.ts), "level": LEVEL_MAP.get(m.rule.level, "med"),
                           "rule": m.rule.name, "message": f"Rule matched {m.submission.package_name}",
                           "source": "rules", "submission_id": str(m.submission_id)})
        for ev in PipelineEvent.objects.filter(ts__gte=day_ago, level__in=("warn", "error")).order_by("-id")[:60]:
            alerts.append({"ts": payloads.iso(ev.ts), "level": "high" if ev.level == "error" else "med",
                           "rule": None, "message": ev.message, "source": ev.stage,
                           "submission_id": str(ev.submission_id) if ev.submission_id else None})
        alerts.sort(key=lambda a: a["ts"], reverse=True)

        health = health_report()
        agents = [
            {"name": "api", "role": "Django / DRF + Channels", "online": health["db"],
             "detail": "database reachable" if health["db"] else "database unreachable"},
            {"name": "workers", "role": "Celery analysis + reasoning queues", "online": health["workers"] >= 1,
             "detail": f"{health['workers']} worker(s) responding"},
            {"name": "redis", "role": "Broker + channel layer", "online": health["redis"] is not False,
             "detail": "not configured (in-memory)" if health["redis"] is None else
             ("reachable" if health["redis"] else "unreachable")},
        ]
        for d in Device.objects.filter(revoked=False)[:50]:
            agents.append({"name": d.name, "role": "Watcher client", "online": d.is_online,
                           "detail": f"last seen {payloads.iso(d.last_seen)}" if d.last_seen else "never seen"})

        iocs = _ioc_rows()
        top = iocs[:6]
        max_samples = max((i["samples"] for i in top), default=1)
        talkers = [{**i, "pct": round(100 * i["samples"] / max_samples)} for i in top]

        tactics: Counter = Counter()
        for v in Verdict.objects.filter(is_current=True, created_at__gte=day_ago):
            for t in (v.payload or {}).get("techniques", []):
                tactics[t.get("tactic") or "unspecified"] += 1

        return Response({
            "generated_at": payloads.iso(now),
            "kpis": {
                "events_last_minute": buckets[-1],
                "warn_error_24h": PipelineEvent.objects.filter(ts__gte=day_ago, level__in=("warn", "error")).count(),
                "ioc_endpoints": len(iocs),
                "flagged_endpoints": sum(1 for i in iocs if i["flagged"]),
                "rule_matches_24h": RuleMatch.objects.filter(ts__gte=day_ago, false_positive=False).count(),
            },
            "events_per_minute": buckets,
            "alerts": alerts[:40],
            "agents": agents,
            "talkers": talkers,
            "iocs": iocs[:40],
            "attck": [{"tactic": k, "count": v} for k, v in tactics.most_common()],
        })


class GraphView(APIView):
    """Devices -> apps -> signals, from the latest current verdict per (device, package)."""

    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        devices = list(Device.objects.filter(revoked=False)[:30])
        device_ids = {d.id for d in devices}
        latest: dict[tuple, Submission] = {}
        for sub in Submission.objects.filter(device_id__in=device_ids, status="verdict_ready").select_related(
                "device").order_by("-created_at")[:400]:
            latest.setdefault((sub.device_id, sub.package_name), sub)
        apps, signals = [], []
        ioc_apps: dict[tuple[str, str], dict] = {}   # (kind, value) -> {"apps": set(app ids), "flagged": bool}
        for (device_id, package), sub in list(latest.items())[:60]:
            verdict = Verdict.objects.filter(submission=sub, is_current=True).select_related("analysis").first()
            label = effective_label(sub) or (verdict.label if verdict else "unknown")
            apps.append({"id": str(sub.id), "device_id": str(device_id), "package_name": package,
                         "app_label": sub.app_label, "label": label,
                         "confidence": verdict.confidence if verdict else None, **payloads.provider_info(verdict)})
            sigs = verdict.analysis.evidence.get("signals", []) if verdict and verdict.analysis else []
            notable = sorted((s for s in sigs if s.get("severity") in ("medium", "high", "critical")),
                             key=lambda s: SEV_RANK[s["severity"]])[:4]
            for s in notable:
                signals.append({"id": f"{sub.id}:{s['id']}", "app_id": str(sub.id), "name": s["name"],
                                "severity": s["severity"]})
            strings = (verdict.analysis.evidence.get("static", {}).get("strings", {}) or {}) \
                if verdict and verdict.analysis else {}
            flagged = strings.get("flagged_hosts", {}) or {}
            found = [("host", h, True) for h in flagged] + [("ip", ip, True) for ip in strings.get("ips", [])]
            for url in strings.get("urls", []):
                host = urlparse(url).hostname
                if host and host not in flagged:
                    found.append(("host", host, False))
            for kind, value, is_flagged in found:
                entry = ioc_apps.setdefault((kind, value), {"apps": set(), "flagged": False})
                entry["apps"].add(str(sub.id))
                entry["flagged"] = entry["flagged"] or is_flagged

        # IOC nodes: anything flagged (shortener/dyn-DNS/paste host, hard-coded IP) or referenced by 2+ apps, i.e. the
        # endpoints that actually correlate samples. A host seen in a single app and not flagged stays out of the graph.
        iocs = [{"id": f"{kind}:{value}", "value": value, "kind": kind, "flagged": e["flagged"],
                 "app_ids": sorted(e["apps"])}
                for (kind, value), e in ioc_apps.items() if e["flagged"] or len(e["apps"]) >= 2]
        iocs.sort(key=lambda i: (not i["flagged"], -len(i["app_ids"]), i["value"]))
        iocs = iocs[:30]
        return Response({
            "devices": [{"id": str(d.id), "name": d.name, "online": d.is_online} for d in devices],
            "apps": apps, "signals": signals, "iocs": iocs,
            "shared_iocs": sum(1 for i in iocs if len(i["app_ids"]) >= 2),
            "active_threats": sum(1 for a in apps if a["label"] in ("malicious", "suspicious")),
        })


class PipelineView(APIView):
    """Stage-by-stage status for the Pipeline page, from live configuration and counters."""

    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        cfg = effective_settings()
        health = health_report()
        backend = cfg.get("reasoner_backend", "rules")
        llm_model = os.environ.get("STAGE4_LLM_MODEL") if os.environ.get("STAGE4_LLM_BASE_URL") else None
        by_status = dict(Counter(Submission.objects.values_list("status", flat=True)))
        devices = list(Device.objects.filter(revoked=False))
        online = sum(1 for d in devices if d.is_online)
        reasoning_desc = ("Deterministic rule engine only." if backend == "rules" else
                          "Rule engine + active lists; borderline cases go to the agentic LLM loop "
                          + (f"({llm_model})." if llm_model else "(mock LLM: no model configured)."))
        stages = [
            {"key": "android", "name": "Android App", "status": "active" if online else "idle",
             "description": "Watches installs, hashes APKs, uploads for analysis, confirms uninstalls on-device.",
             "metric": f"{online}/{len(devices)} devices online"},
            {"key": "backend", "name": "Backend & Orchestration", "status": "active" if health["ok"] else "degraded",
             "description": "Django/DRF + Celery pipeline, Channels broadcast, the shared Evidence/Verdict contract.",
             "metric": f"{health['workers']} worker(s) · {sum(by_status.get(s, 0) for s in IN_PROGRESS)} in progress"},
            {"key": "analysis", "name": "Static Analysis", "status": "active",
             "description": "androguard manifest + signing, DEX string pool, YARA, entropy, API signatures.",
             "metric": f"analysis v{settings.SENTINEL['ANALYSIS_VERSION']} · {Sample.objects.count()} samples"},
            {"key": "dynamic", "name": "Dynamic Analysis",
             "status": "active" if cfg.get("dynamic_enabled") else "disabled",
             "description": "Emulator behaviour trace for borderline samples.",
             "metric": "enabled" if cfg.get("dynamic_enabled") else "disabled on this server"},
            {"key": "reasoning", "name": "Reasoning", "status": "active", "description": reasoning_desc,
             "metric": f"backend: {backend}" + (f" · {llm_model}" if backend == "hybrid" and llm_model else "")},
            {"key": "dashboard", "name": "SOC Dashboard", "status": "active",
             "description": "This console: live feed, verdicts, submissions, devices, graph, network.",
             "metric": f"{Submission.objects.count()} submissions"},
            {"key": "remediation", "name": "Remediation & Rules", "status": "active",
             "description": "Guardrailed on-device actions and the YARA/Sigma rules generated from verdicts.",
             "metric": f"{RemediationRequest.objects.filter(state__in=RemediationRequest.OPEN_STATES).count()} open · "
                       f"{GeneratedRule.objects.filter(status='approved').count()} active rules"},
        ]
        return Response({"stages": stages, "health": health, "reasoner_backend": backend,
                         "llm_model": llm_model, "submissions_by_status": by_status})


class RemediationQueueView(APIView):
    """Open requests (pending/delivered) plus malicious/suspicious submissions with no open request yet."""

    permission_classes = [AnalystWriteOrReadOnly]

    def get(self, request):
        from remediation.dash_views import remediation_row
        from remediation.policy import is_protected

        cfg = effective_settings()
        protected = set(cfg.get("protected_packages", []))
        open_qs = list(RemediationRequest.objects.filter(state__in=RemediationRequest.OPEN_STATES).select_related(
            "device", "created_by").order_by("-created_at")[:100])
        open_pairs = {(r.device_id, r.package_name) for r in open_qs}
        candidates = []
        subs = Submission.objects.filter(status="verdict_ready", remediation_hold=False,
                                         created_at__gte=timezone.now() - timedelta(days=7)).select_related(
            "device").order_by("-created_at")[:200]
        for sub in subs:
            if (sub.device_id, sub.package_name) in open_pairs:
                continue
            if is_protected(sub.package_name, protected, cfg.get("own_package", "com.sentinel.soc")):
                continue
            verdict = Verdict.objects.filter(submission=sub, is_current=True).first()
            if verdict is None:
                continue
            label = effective_label(sub) or verdict.label
            if label not in ("malicious", "suspicious"):
                continue
            candidates.append({
                "submission_id": str(sub.id), "package_name": sub.package_name, "app_label": sub.app_label,
                "device": {"id": str(sub.device_id), "name": sub.device.name}, "label": label,
                "confidence": verdict.confidence, "explanation": verdict.payload.get("explanation", ""),
                "recommended_action": verdict.payload.get("recommended_action", "none"),
                **payloads.provider_info(verdict), "created_at": payloads.iso(sub.created_at)})
            open_pairs.add((sub.device_id, sub.package_name))
        return Response({"open": [remediation_row(r) for r in open_qs], "candidates": candidates[:50],
                         "auto_remediation_enabled": bool(cfg.get("auto_remediation_enabled"))})
