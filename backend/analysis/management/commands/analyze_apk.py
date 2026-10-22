"""python manage.py analyze_apk path/to/app.apk [--json out.json] [--pretty]  (Stage 3 section 8; no Celery needed)."""
import hashlib
import json
import sys
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from analysis.engine import new_context, run_static
from analysis.signals import SEVERITY_RANK


class Command(BaseCommand):
    help = "Run static analysis on one APK and print the signals."

    def add_arguments(self, parser):
        parser.add_argument("apk")
        parser.add_argument("--json", dest="json_out")
        parser.add_argument("--pretty", action="store_true")

    def handle(self, *args, **opts):
        path = Path(opts["apk"])
        if not path.exists():
            raise CommandError(f"no such file: {path}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        workdir = Path(settings.SENTINEL["WORK_DIR"]) / digest
        workdir.mkdir(parents=True, exist_ok=True)

        def emit(stage, step, message, level="info", data=None):
            self.stderr.write(f"[{stage}/{step}] {message}")

        ctx = new_context(digest, str(path), str(workdir), {"package_name": path.stem}, emit)
        evidence = run_static(ctx)
        self.stdout.write(f"sha256 {digest}")
        self.stdout.write(f"signals: {len(evidence['signals'])}  partial: {evidence['partial']}")
        for sig in sorted(evidence["signals"], key=lambda s: (SEVERITY_RANK[s["severity"]], s["code"])):
            self.stdout.write(f"  {sig['id']:7} {sig['severity']:8} {sig['code']:13} {sig['detail']}")
        if opts["json_out"]:
            Path(opts["json_out"]).write_text(json.dumps(evidence, indent=2 if opts["pretty"] else None),
                                              encoding="utf-8")
            self.stdout.write(f"evidence written to {opts['json_out']}")
        sys.stdout.flush()
