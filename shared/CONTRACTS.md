# Sentinel SOC - Shared Contracts

**Contract version: 1.0 (2026-10-05)**
This file is identical in every stage zip. It is the single source of truth for names, states, APIs, events and data shapes that cross stage boundaries. If a stage doc and this file disagree, this file wins.

Project: *An Agentic AI Framework for Autonomous Threat Detection, Analysis, and Remediation in a Mobile-Integrated Security Operations Center* (codebase: `sentinel-soc`).

---

## 1. Stage map

| # | Stage | Owns |
|---|-------|------|
| S1 | Android app | Install detection, hashing, upload, notifications, user-confirmed uninstall |
| S2 | Backend & orchestration | REST API, Celery pipeline, state machines, WebSockets, persistence |
| S3 | Analysis | Static (MVP) and dynamic (stretch) analysis, signal extraction -> **Evidence** |
| S4 | Reasoning (**decision deferred**) | Anything that turns Evidence into a **Verdict** via the `Reasoner` interface (section 9) |
| S5 | SOC dashboard | Server-rendered analyst UI, live feed, overrides |
| S6 | Remediation & rules | Remediation policy/state machine, YARA + Sigma generation and lifecycle |
| S7 | Validation & demo | Test corpus, eval kit, demo console, demo script, viva prep |

S4 is deliberately not specified yet. Every other stage only depends on the **Evidence** shape (section 7), the **Verdict** shape (section 8) and the `Reasoner` interface (section 9). Swapping the S4 implementation must not require changes anywhere else.

## 2. Conventions

- IDs: `device_id`, `submission_id`, `remediation_id`, `rule_id` are UUID v4 strings. `sample_sha256` is lowercase 64-char hex of the **base APK file bytes**.
- Timestamps: ISO-8601 UTC with `Z`, e.g. `2026-10-05T09:30:00Z`.
- JSON keys: `snake_case`. Enum values: lowercase `snake_case`.
- Base path: `/api/v1/`. Content type: `application/json` unless stated (APK upload is `application/octet-stream`).
- Pagination (dashboard lists): `?page=1&page_size=25` -> `{ "count": int, "next": url|null, "previous": url|null, "results": [...] }`.
- Error body (all non-2xx): `{ "error": { "code": "<code>", "message": "<human text>", "details": { } } }`
  Codes: `invalid_token`, `pairing_failed`, `validation_error`, `not_found`, `apk_too_large`, `hash_mismatch`, `not_an_apk`, `rate_limited`, `state_conflict`, `forbidden`, `internal_error`.

## 3. Submission state machine

`Submission.status` (one row per device x install event):

| Status | Meaning | Next |
|--------|---------|------|
| `received` | Metadata accepted | `awaiting_upload` or `queued` (cache hit / file already present) |
| `awaiting_upload` | Backend does not have the APK bytes | `queued` after valid upload |
| `queued` | Waiting for a Celery worker | `static_analysis` |
| `static_analysis` | S3 static analyzers running | `dynamic_analysis` (only if requested) or `reasoning` |
| `dynamic_analysis` | S3 dynamic run (stretch, optional) | `reasoning` |
| `reasoning` | Reasoner running | `verdict_ready` (or back to `dynamic_analysis` if `needs_more_verification`, max `MAX_VERIFICATION_LOOPS`) |
| `verdict_ready` | Verdict stored and pushed to dashboard/device | terminal for analysis |
| `error` | Unrecoverable failure; `error_code` and `error_detail` set | analyst can `reanalyze` -> `queued` |

User-facing text for each status is in the S2 frontend doc (section "Status labels").

## 4. Remediation state machine

`RemediationRequest.state`:

`pending` -> `delivered` -> `completed` | `declined` | `failed`
plus `cancelled` (analyst, from `pending` or `delivered`) and `expired` (no user action within `REMEDIATION_TTL_HOURS`).

- Only action in v1: `uninstall` of exactly one package. The user **always** confirms in the Android system dialog. No root, no device-admin, no silent removal.
- `origin`: `auto` (policy engine) or `analyst`.

## 5. REST API summary

Auth: devices send `Authorization: Device <token>`; analysts use Django session auth (+ CSRF on POST). Full request/response bodies live in the S2 backend doc.

**Device-facing**

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/devices/register` | Pairing code -> `device_id` + `device_token` |
| POST | `/api/v1/devices/me/heartbeat` | Liveness + app version |
| POST | `/api/v1/submissions` | Create submission (metadata + sha256). Response says `need_upload` |
| PUT | `/api/v1/submissions/{id}/apk` | Stream APK bytes (`application/octet-stream`, header `X-Content-SHA256`) |
| GET | `/api/v1/submissions/{id}` | Status + verdict summary (device-scoped) |
| GET | `/api/v1/devices/me/commands?cursor=<n>` | Poll for commands |
| POST | `/api/v1/devices/me/commands/{id}/ack` | Acknowledge a command |
| POST | `/api/v1/remediations/{id}/result` | Report `uninstalled` / `declined` / `failed` |

**Command types** (`Command.type`): `verdict_notify`, `uninstall_proposed`, `uninstall_cancelled`.
`uninstall_proposed.payload` = `{ "remediation_id", "submission_id", "package_name", "app_label", "label", "confidence", "summary" }`.
`verdict_notify.payload` = `{ "submission_id", "package_name", "app_label", "label", "confidence", "summary" }`.

**Dashboard-facing** (analyst session)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/dash/stats` | Overview counters |
| GET | `/api/v1/dash/submissions` | List (filters: `status` - also the pseudo-value `in_progress` = every non-terminal status, `label`, `q`, `device`) |
| GET | `/api/v1/dash/submissions/{id}` | Full detail: submission, evidence, verdict, remediation, rules |
| GET | `/api/v1/dash/submissions/{id}/events` | Pipeline events (`?since_event_id=`) |
| POST | `/api/v1/dash/submissions/{id}/override` | Analyst label override `{label, note}` |
| POST | `/api/v1/dash/submissions/{id}/reanalyze` | Re-queue |
| POST | `/api/v1/dash/submissions/{id}/remediation` | Analyst proposes uninstall |
| POST | `/api/v1/dash/remediations/{id}/cancel` | Cancel remediation |
| GET | `/api/v1/dash/rules` | List generated rules |
| POST | `/api/v1/dash/rules/{id}/approve` · `/retire` | Lifecycle |
| GET | `/api/v1/dash/rules/export` | Zip of approved rules |
| GET/POST | `/api/v1/dash/devices`, `/api/v1/dash/pairing-code` | Devices and pairing |
| GET | `/api/v1/dash/remediations` | Remediation queue (`?state=`) (S6) |
| POST | `/api/v1/dash/submissions/{id}/hold` | Hold automatic remediation `{hold}` (S6) |
| GET | `/api/v1/dash/rules/{id}` | Rule detail, versions, FP test, matches (S6) |
| PUT | `/api/v1/dash/rules/{id}` | Edit rule -> new draft version (S6) |
| POST | `/api/v1/dash/rules/{id}/validate` · `/fp-test` | Validate content / re-run false-positive test (S6) |
| POST | `/api/v1/dash/matches/{id}/false-positive` | Mark a rule match as false positive (S6) |
| POST | `/api/v1/dash/submissions/{id}/generate-rules` | Generate rules on demand (S6) |
| GET/POST | `/api/v1/dash/settings` | Read / change site settings `{key, value}` (S5) |
| POST | `/api/v1/dash/reputation` | Add known-bad / known-good hash or signer (S3/S5) |
| GET | `/api/v1/dash/demo/preflight` | Demo readiness checks (S7) |
| POST | `/api/v1/dash/demo/reset` · `/marker` · `/fault` | Reset demo data, add timeline marker, fault drill (S7; fault only if `SENTINEL_DEV_FAULTS=1`) |
| GET | `/api/v1/dash/demo/evidence-pack` | Zip of evidence (S7) |
| GET | `/api/v1/dash/eval/latest` | Latest evaluation summary (S7) |
| GET | `/healthz` | Liveness (no auth) |

## 6. Real-time events (WebSocket)

Endpoints: `/ws/dashboard/` (all events) and `/ws/submissions/<submission_id>/` (one submission). Session-authenticated. Server -> client only (clients never send events).

Envelope:
```json
{ "v": 1, "event_id": 1042, "type": "pipeline.event", "ts": "2026-10-05T09:30:01Z",
  "submission_id": "uuid-or-null", "stage": "static_analysis", "step": "manifest_parsed",
  "level": "info", "message": "Manifest parsed: 14 permissions", "data": { } }
```
- `type`: `submission.created`, `submission.status_changed`, `pipeline.event`, `verdict.ready`, `remediation.updated`, `rule.generated`, `device.heartbeat`.
- `stage`: `intake`, `static_analysis`, `dynamic_analysis`, `reasoning`, `verdict`, `remediation`, `rules`, `device`, `system`.
- `level`: `debug`, `info`, `warn`, `error`.
- `event_id` is a monotonically increasing integer (the `PipelineEvent` primary key) so clients can dedupe and resume.

## 7. Evidence (S3 -> S4/S5/S6)

Produced by S3 only. Schema: `evidence.schema.json`. Example: `examples/evidence.example.json`.
Top level: `schema_version`, `sample_sha256`, `analysis_version`, `static`, `dynamic` (null if not run), `reputation`, `signals[]`, `partial` (bool), `partial_reasons[]`.
`signals[]` is the normalised, **reasoner-facing** list: `{ id: "sig_N", code: "SIG-PERM-001", name, severity: info|low|medium|high|critical, category, source: manifest|signing|code|files|strings|reputation|dynamic, detail, attck: [..] }`. Reasoners and the UI reference signals by `id`.

## 8. Verdict (S4 -> S2/S5/S6)

Schema: `verdict.schema.json`. Example: `examples/verdict.example.json`.
Fields: `label` (`malicious|suspicious|benign|unknown`), `score` 0-1 (risk), `confidence` 0-1, `techniques[]` (ATT&CK Mobile, each with `evidence_ids`), `explanation` (analyst-style text), `needs_more_verification`, `verification_requests[]`, `recommended_action` (`none|monitor|uninstall`), `provider` (`name`, `version`, optional `fallback_from`), `generated_at`.

## 9. Reasoner interface (the S4 seam)

```python
# reasoning/interface.py  (skeleton is in the S2 zip, extras/)
class Reasoner(Protocol):
    name: str
    version: str
    def reason(self, evidence: dict, ctx: "ReasonContext") -> dict: ...   # returns a Verdict dict
```
Rules every implementation must follow:
1. Never raise. On internal failure return `label="unknown"`, `confidence=0.0`, and explain the failure in `explanation`.
2. Finish within `ctx.budget_seconds` or return `unknown`.
3. Only reference `evidence_ids` that exist in the evidence it was given.
4. Set `provider.name` honestly (`rule_engine`, `ml_classifier`, `slm:<model>`, `hybrid`).
5. May ask for more checking through `verification_requests`; the orchestrator (S2) owns the loop and its bound.

Selected implementation: `REASONER_BACKEND` setting (`rules` | `ml` | `slm` | `hybrid`). Default until S4 is decided: `rules`.

## 10. Integrity rules

- Every row in the live feed is emitted by code that actually ran. No scripted or simulated events outside an explicitly labelled demo-data seed.
- Every verdict shown anywhere displays its `provider` (name + version).
- If a fallback reasoner was used, the verdict and the UI say so (`provider.fallback_from`).
- Remediation always needs the user's on-device confirmation.

## 11. Shared configuration keys

| Key | Default | Used by |
|-----|---------|---------|
| `SENTINEL_BASE_URL` | `http://<laptop-ip>:8000` | S1, S5 |
| `SENTINEL_PAIRING_TTL_MIN` | `10` | S2, S5 |
| `MAX_APK_MB` | `100` | S1, S2 |
| `ANALYSIS_VERSION` | `1` | S2, S3 (bump to invalidate cache) |
| `DYNAMIC_ENABLED` | `false` | S2, S3 |
| `MAX_VERIFICATION_LOOPS` | `2` | S2 |
| `REASONER_BACKEND` | `rules` | S2 |
| `REASONER_TIMEOUT_S` | `60` | S2 |
| `AUTO_REMEDIATION_ENABLED` | `false` | S6 |
| `AUTO_REMEDIATION_MIN_CONFIDENCE` | `0.85` | S6 |
| `REMEDIATION_TTL_HOURS` | `24` | S6 |
| `REMEDIATION_RATE_LIMIT_PER_DEVICE_HOUR` | `3` | S6 |
| `DEVICE_POLL_SECONDS` | `5` | S1 |

## 12. Technology baseline (existing project facts)

Django + DRF + Celery + Channels, Redis, SQLite (dev) / Postgres. Dashboard is server-rendered (`templates/`, `static/soc.css`, `static/soc.js`) with **no JS framework**. Android app is Kotlin under `android/`, **no Compose, no Material components**, `minSdk 26`. Everything runs locally; no cloud dependency in the default configuration.

## 13. Shared visual language

Dashboard and app share the same palette (details in S1 and S5 frontend docs): dark graphite surfaces; verdict colours `malicious #F0524F`, `suspicious #F5A524`, `benign #2FBF71`, `unknown #8B98A8`, info `#4C9AFF`. Verdicts are never communicated by colour alone (always icon + text).
