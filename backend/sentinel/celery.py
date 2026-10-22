import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sentinel.settings")

app = Celery("sentinel")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.set_default()  # shared_task() tasks must dispatch through this app (and its eager/broker settings)
app.autodiscover_tasks()
