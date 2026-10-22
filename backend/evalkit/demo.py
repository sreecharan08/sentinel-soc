"""Demo data management (Stage 7 section 9). Users, devices, settings and stored samples are kept on reset."""
from __future__ import annotations

import shutil

from django.conf import settings
from django.db import transaction

from devices.models import Command
from pipeline.events import emit
from pipeline.models import PipelineEvent
from remediation.models import RemediationRequest
from rules.models import GeneratedRule, RuleMatch
from analysis.models import Analysis
from submissions.models import AnalystAction, Submission, Verdict


def reset_demo(user=None) -> dict:
    with transaction.atomic():
        counts = {
            "submissions": Submission.objects.count(),
            "rules": GeneratedRule.objects.count(),
        }
        RuleMatch.objects.all().delete()
        RemediationRequest.objects.all().delete()
        Command.objects.all().delete()
        AnalystAction.objects.all().delete()
        Verdict.objects.all().delete()
        Analysis.objects.all().delete()
        PipelineEvent.objects.all().delete()
        Submission.objects.all().delete()
        GeneratedRule.objects.all().delete()
        from submissions.models import Sample

        Sample.objects.update(file_path="")  # samples stay on disk; they are re-linked on next upload
        emit(None, "system", "demo_reset", "Demo data reset",
             data={"user": user.get_username() if user else None, "removed": counts})
    for kind in ("yara", "sigma"):
        folder = settings.SENTINEL["RULES_DIR"] / "active" / kind
        if folder.exists():
            shutil.rmtree(folder)
    work = settings.SENTINEL["WORK_DIR"]
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    return counts
