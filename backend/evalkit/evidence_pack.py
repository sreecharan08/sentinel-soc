"""Evidence pack (Stage 7 section 7): evidence, verdicts, timelines, approved rules, eval results, environment."""
from __future__ import annotations

import io
import json
import platform
import sys
import zipfile
from datetime import datetime, timezone as dt_timezone

from django.conf import settings

from analysis.models import Analysis
from pipeline.models import PipelineEvent
from rules.models import GeneratedRule
from submissions.models import Submission

from .report import reports_dir


def build_zip() -> bytes:
    buf = io.BytesIO()
    now = datetime.now(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for sub in Submission.objects.select_related("sample", "device")[:500]:
            sha8 = sub.sample.sha256[:8]
            lines = []
            for ev in PipelineEvent.objects.filter(submission=sub).order_by("id"):
                lines.append(f"{ev.ts.isoformat()} {ev.stage}/{ev.step} [{ev.level}] {ev.message}")
            zf.writestr(f"timelines/{sub.id}.txt", "\n".join(lines) + "\n")
            analysis = Analysis.objects.filter(sample=sub.sample).first()
            if analysis:
                zf.writestr(f"evidence/{sha8}.json", json.dumps(analysis.evidence, indent=2))
            verdict = sub.verdicts.filter(is_current=True).first()
            if verdict:
                zf.writestr(f"verdicts/{sha8}.json", json.dumps(verdict.payload, indent=2))
        approved = GeneratedRule.objects.filter(status="approved")
        manifest = []
        for rule in approved:
            zf.writestr(f"rules/{rule.kind}/{rule.name}{'.yar' if rule.kind == 'yara' else '.yml'}", rule.content)
            manifest.append({"name": rule.name, "kind": rule.kind, "version": rule.version,
                             "fp_test": rule.fp_test.get("status")})
        zf.writestr("rules/manifest.json", json.dumps(manifest, indent=2))
        runs = sorted((p for p in reports_dir().glob("*") if p.is_dir()), reverse=True) if reports_dir().exists() else []
        if runs:
            for name in ("results.csv", "summary.json", "report.md"):
                f = runs[0] / name
                if f.exists():
                    zf.writestr(f"eval/{name}", f.read_bytes())
        env = {
            "generated_at": now, "python": sys.version, "platform": platform.platform(),
            "analysis_version": settings.SENTINEL["ANALYSIS_VERSION"],
            "reasoner": settings.SENTINEL["REASONER_BACKEND"], "dynamic_enabled": settings.SENTINEL["DYNAMIC_ENABLED"],
            "auto_remediation_enabled": settings.SENTINEL["AUTO_REMEDIATION_ENABLED"],
        }
        zf.writestr("environment.json", json.dumps(env, indent=2))
    return buf.getvalue()
