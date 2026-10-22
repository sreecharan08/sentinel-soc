from django.core.management.base import BaseCommand

from devices.pairing import create_pairing_code


class Command(BaseCommand):
    help = "Print a fresh pairing code (CLI alternative to the dashboard)."

    def handle(self, *args, **opts):
        code = create_pairing_code()
        self.stdout.write(code.code)
        self.stdout.write(f"valid until {code.expires_at.isoformat()}")
