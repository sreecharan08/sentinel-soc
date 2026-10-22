"""Latest evaluation summary (Stage 7 section 3 outputs), read from reports/<timestamp>/summary.json."""
from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings


def reports_dir() -> Path:
    return Path(settings.BASE_DIR) / "reports"


def latest_summary() -> dict:
    root = reports_dir()
    if not root.exists():
        return {"available": False, "summary": None, "message": "No evaluation has been run yet."}
    runs = sorted((p for p in root.iterdir() if (p / "summary.json").exists()), reverse=True)
    if not runs:
        return {"available": False, "summary": None, "message": "No evaluation has been run yet."}
    summary = json.loads((runs[0] / "summary.json").read_text(encoding="utf-8"))
    return {"available": True, "run": runs[0].name, "summary": summary}
