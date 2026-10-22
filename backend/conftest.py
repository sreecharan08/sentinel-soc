"""Loaded before Django settings are read: eager Celery, in-memory channels, and a throw-away data directory."""
import os
import tempfile
from pathlib import Path

_DATA = Path(tempfile.mkdtemp(prefix="sentinel-test-"))
os.environ["SENTINEL_DATA_DIR"] = str(_DATA)
os.environ["SENTINEL_DB_PATH"] = str(_DATA / "test.sqlite3")
os.environ["SENTINEL_EAGER"] = "1"
os.environ.pop("REDIS_URL", None)
os.environ.setdefault("SENTINEL_DEBUG", "1")
