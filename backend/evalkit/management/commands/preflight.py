import json
import sys

from django.core.management.base import BaseCommand

from evalkit.preflight import run_preflight


class Command(BaseCommand):
    help = "Demo readiness checks. Exit code 0 only when everything passes."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **opts):
        report = run_preflight()
        if opts["json"]:
            self.stdout.write(json.dumps(report, indent=2))
        else:
            for c in report["checks"]:
                self.stdout.write(f"[{c['status']:4}] {c['label']}: {c['detail']}")
            self.stdout.write(f"overall: {report['overall']}")
        if report["overall"] != "ready":
            sys.exit(1)
