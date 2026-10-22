"""python manage.py seed_demo  -- creates the analyst and viewer demo users (DEV ONLY).

Passwords are printed once. Change them before any shared deployment.
"""
import secrets

from django.contrib.auth.models import Group, User
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create analyst and viewer demo users (dev only)."

    def handle(self, *args, **opts):
        analyst_g, _ = Group.objects.get_or_create(name="analyst")
        Group.objects.get_or_create(name="viewer")
        for username, group in (("analyst", analyst_g), ("viewer", None)):
            user, created = User.objects.get_or_create(username=username)
            if created:
                password = secrets.token_urlsafe(12)
                user.set_password(password)
                user.save()
                self.stdout.write(f"created {username}: password {password} (shown once)")
            else:
                self.stdout.write(f"{username} already exists (password unchanged)")
            if group is not None:
                user.groups.add(group)
