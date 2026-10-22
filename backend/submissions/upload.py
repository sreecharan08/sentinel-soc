"""APK upload: stream to a temp file, hash, check magic bytes and size, then move into the sample store.

Samples are stored read-only and outside any web-served directory; they are never executed (analysis-safety rule 1).
"""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from pipeline.events import emit
from pipeline.state import set_status
from pipeline.tasks import enqueue_pipeline
from sentinel.errors import ApiError

from .models import Sample, Submission
from .services import sample_path

ZIP_MAGIC = b"PK\x03\x04"
CHUNK = 64 * 1024


def _reject(sub: Submission, code: str, message: str, status: int, tmp: Path | None = None):
    if tmp is not None:
        try:
            os.remove(tmp)
        except OSError:
            pass
    emit(sub, "intake", "upload_rejected", message, level="warn", data={"code": code})
    raise ApiError(code, message, status)


def receive_apk(sub: Submission, stream, declared_sha: str, content_length: int | None) -> None:
    max_bytes = settings.SENTINEL["MAX_APK_MB"] * 1024 * 1024
    if declared_sha != sub.sample.sha256:
        raise ApiError("hash_mismatch", "X-Content-SHA256 does not match this submission.", 400)

    existing = Sample.objects.get(pk=sub.sample.sha256)
    if existing.file_path and Path(existing.file_path).exists():
        return  # a concurrent upload already stored the bytes; do not rewrite them

    if sub.status != "awaiting_upload":
        raise ApiError("state_conflict", "That can't be done in the current state.", 409,
                       {"status": sub.status})
    if content_length is not None and content_length > max_bytes:
        _reject(sub, "apk_too_large", "The app file is larger than the allowed limit.", 413)

    tmp_dir = settings.SENTINEL["DATA_DIR"] / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp = tmp_dir / f"{uuid.uuid4()}.part"
    digest = hashlib.sha256()
    size = 0
    with open(tmp, "wb") as out:
        first = True
        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                break
            if first:
                first = False
                if not chunk.startswith(ZIP_MAGIC) and len(chunk) >= 4:
                    _reject(sub, "not_an_apk", "That file isn't an Android app package.", 400, tmp)
            size += len(chunk)
            if size > max_bytes:
                _reject(sub, "apk_too_large", "The app file is larger than the allowed limit.", 413, tmp)
            digest.update(chunk)
            out.write(chunk)

    if size < 4:
        _reject(sub, "not_an_apk", "That file isn't an Android app package.", 400, tmp)
    if digest.hexdigest() != sub.sample.sha256:
        _reject(sub, "hash_mismatch", "The uploaded file did not match its fingerprint. Try again.", 400, tmp)

    dest = sample_path(sub.sample.sha256)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with transaction.atomic():
        if not dest.exists():
            os.replace(tmp, dest)
            try:
                os.chmod(dest, 0o444)
            except OSError:
                pass
        else:
            os.remove(tmp)
        sample = Sample.objects.select_for_update().get(pk=sub.sample.sha256)
        sample.file_path = str(dest)
        sample.size_bytes = size
        sample.save(update_fields=["file_path", "size_bytes"])
        set_status(sub, "queued")
        emit(sub, "intake", "upload_received", f"App file received ({size} bytes), hash verified",
             data={"size_bytes": size, "sha256": sub.sample.sha256})
    enqueue_pipeline(sub.id)
    _touch_now(sub)


def _touch_now(sub: Submission) -> None:
    Submission.objects.filter(pk=sub.pk).update(updated_at=timezone.now())
