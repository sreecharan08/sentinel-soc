from django.core.management.base import BaseCommand, CommandError

from evalkit.demo import reset_demo


class Command(BaseCommand):
    help = "Delete submissions, verdicts, commands, remediations, events and generated rules. Keeps users and devices."

    def add_arguments(self, parser):
        parser.add_argument("--yes", action="store_true", help="required: confirms the reset")

    def handle(self, *args, **opts):
        if not opts["yes"]:
            raise CommandError("Refusing to reset without --yes")
        counts = reset_demo()
        self.stdout.write(f"reset: {counts}")
