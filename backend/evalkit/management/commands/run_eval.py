"""python manage.py run_eval --base-url http://127.0.0.1:8000 --corpus corpus/manifest.csv   (Stage 7 section 3)

Runs every corpus file through the live API and pipeline, then writes results.csv, summary.json and report.md.
"""
import csv
import hashlib
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone as dt_timezone
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from devices.pairing import create_pairing_code


def _call(base, method, path, body=None, token=None, raw=None, headers=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Accept", "application/json")
    if body is not None and raw is None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Device {token}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode() or "{}"
            return resp.status, json.loads(text)
    except urllib.error.HTTPError as exc:
        text = exc.read().decode() or "{}"
        try:
            return exc.code, json.loads(text)
        except json.JSONDecodeError:
            return exc.code, {"error": {"code": "internal_error", "message": text}}


def _wilson(success: int, n: int, z: float = 1.96):
    if n == 0:
        return (0.0, 0.0)
    p = success / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    return (round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3))


class Command(BaseCommand):
    help = "Evaluate the detection pipeline on a corpus through the live API."

    def add_arguments(self, parser):
        parser.add_argument("--base-url", default="http://127.0.0.1:8000")
        parser.add_argument("--corpus", default=None, help="manifest.csv (default: backend/corpus/manifest.csv)")
        parser.add_argument("--out", default=None)
        parser.add_argument("--timeout", type=int, default=180)

    def handle(self, *args, **opts):
        base = opts["base_url"].rstrip("/")
        corpus_path = Path(opts["corpus"] or Path(settings.BASE_DIR) / "corpus" / "manifest.csv")
        if not corpus_path.exists():
            raise CommandError(f"corpus manifest not found: {corpus_path}")
        rows = list(csv.DictReader(corpus_path.open(encoding="utf-8")))
        root = corpus_path.parent
        code = create_pairing_code().code
        status, reg = _call(base, "POST", "/api/v1/devices/register",
                            {"pairing_code": code, "device_name": "eval-runner", "app_version": "eval"})
        if status != 201:
            raise CommandError(f"could not register the eval device: {reg}")
        token = reg["device_token"]

        results = []
        for row in rows:
            path = root / row["file"]
            data = path.read_bytes()
            sha = hashlib.sha256(data).hexdigest()
            meta = {"package_name": row.get("package", "com.eval.sample"), "app_label": path.stem,
                    "apk_sha256": sha, "apk_size_bytes": len(data), "requested_permissions": [],
                    "installer_package": None}
            started = time.monotonic()
            status, sub = _call(base, "POST", "/api/v1/submissions", meta, token=token)
            if status != 201:
                results.append({**row, "label": "error", "status": "rejected", "ttv_s": ""})
                continue
            if sub.get("need_upload"):
                _call(base, "PUT", f"/api/v1/submissions/{sub['submission_id']}/apk", raw=data, token=token,
                      headers={"Content-Type": "application/octet-stream", "X-Content-SHA256": sha})
            final = {}
            deadline = started + opts["timeout"]
            while time.monotonic() < deadline:
                _, final = _call(base, "GET", f"/api/v1/submissions/{sub['submission_id']}", token=token)
                if final.get("status") in ("verdict_ready", "error"):
                    break
                time.sleep(1)
            ttv = round(time.monotonic() - started, 2)
            verdict = final.get("verdict") or {}
            results.append({**row, "label": verdict.get("label", "unknown"), "confidence": verdict.get("confidence"),
                            "status": final.get("status", "timeout"), "ttv_s": ttv})

        out_dir = Path(opts["out"] or Path(settings.BASE_DIR) / "reports") / datetime.now(dt_timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_dir.mkdir(parents=True, exist_ok=True)
        fields = ["file", "expected", "category", "pair_id", "variant", "label", "confidence", "status", "ttv_s"]
        with (out_dir / "results.csv").open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(results)

        tp = sum(1 for r in results if r["expected"] == "malicious_fixture" and r["label"] in ("malicious", "suspicious"))
        fn = sum(1 for r in results if r["expected"] == "malicious_fixture" and r["label"] not in ("malicious", "suspicious"))
        fp = sum(1 for r in results if r["expected"] == "benign" and r["label"] in ("malicious", "suspicious"))
        tn = sum(1 for r in results if r["expected"] == "benign" and r["label"] not in ("malicious", "suspicious"))
        times = sorted(float(r["ttv_s"]) for r in results if r.get("ttv_s") not in ("", None))
        summary = {
            "corpus": {"total": len(results), "fixtures": tp + fn, "benign": fp + tn},
            "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "recall_wilson_95": _wilson(tp, tp + fn),
            "time_to_verdict": {"p50": times[len(times) // 2] if times else None,
                                "max": times[-1] if times else None},
            "analysis_version": settings.SENTINEL["ANALYSIS_VERSION"],
            "generated_at": datetime.now(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        report = [f"# Evaluation report {summary['generated_at']}",
                  f"Corpus: {summary['corpus']['total']} files ({summary['corpus']['fixtures']} fixtures, "
                  f"{summary['corpus']['benign']} benign).",
                  f"TP {tp}  FP {fp}  TN {tn}  FN {fn}  (lenient: malicious or suspicious counts as positive).",
                  f"Precision {summary['precision']}  Recall {summary['recall']}  "
                  f"Recall 95% Wilson interval {summary['recall_wilson_95']}.",
                  f"Time to verdict p50 {summary['time_to_verdict']['p50']} s, max {summary['time_to_verdict']['max']} s.",
                  "Small corpus: read counts with the interval, not the percentage alone."]
        (out_dir / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
        self.stdout.write(f"wrote {out_dir}")
        self.stdout.write(json.dumps(summary["confusion"]))
