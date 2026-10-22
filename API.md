# Sentinel SOC: Django <-> Next.js contract

Backend: Django + DRF + Channels (`backend/`). Frontend: Next.js App Router, TypeScript (`web/`).
Base URL: `NEXT_PUBLIC_API_URL` (default `http://localhost:9000`). REST under `/api/v1`, WebSocket under `/ws`.

## 1. Decisions

| Topic | Choice | Why |
|---|---|---|
| Layout | Separate top-level dir `sentinel-soc/web/` next to `backend/` and `android/` | One repo, independent toolchains (npm vs pip/gradle), no workspace tooling to maintain. |
| Auth | **JWT bearer tokens** (DRF SimpleJWT) + `django-cors-headers` | Next.js is a separate origin/process; no reverse proxy to share cookies, and it keeps CSRF out of the picture. Session auth is kept for the legacy Django pages and `/admin`. |
| Realtime | Existing Channels consumers, native browser `WebSocket`, `?token=<access JWT>` | Browsers cannot set headers on a WebSocket. No shim was needed. |
| State | Small `useApi` hook; one WebSocket provider bumps a tick that refetches live pages | No extra dependencies. |

Token storage: access + refresh JWT in `localStorage` (key `sentinel.session`). That is readable by any script on the
origin (XSS risk); the app ships no third-party scripts. Access tokens live 15 min (`SENTINEL_ACCESS_TOKEN_MIN`), refresh
tokens 7 days (`SENTINEL_REFRESH_TOKEN_DAYS`). The `?token=` WebSocket URL can appear in server logs; the token is short-lived.

Environment (backend): `SENTINEL_WEB_ORIGINS` (comma-separated allowed origins, default `http://localhost:3000,http://127.0.0.1:3000`).

## 2. Auth

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/api/v1/auth/token/` | `{username, password}` | `200 {access, refresh, user:{username, role}}`; `401 invalid_credentials`; `429` after 10/min |
| POST | `/api/v1/auth/refresh/` | `{refresh}` | `200 {access}`; `401 token_invalid` |
| GET | `/api/v1/auth/me/` | none | `{username, role}` where role is `analyst` or `viewer` |

Send `Authorization: Bearer <access>` on every `/api/v1/dash/*` call. GET needs any signed-in user, POST/PUT needs the
`analyst` role.

Error body for every failure: `{"error": {"code", "message", "details"}}`. Auth-related codes: `401 token_invalid`
(expired or malformed bearer token: refresh once, then sign out), `401 invalid_credentials`, `403 forbidden`
("Sign in to continue." when no credentials, or "You don't have permission" for a viewer write).

## 3. Realtime

`ws(s)://<host>/ws/dashboard/?token=<access>` streams every pipeline event (server -> client only).
`ws(s)://<host>/ws/submissions/<uuid>/?token=<access>` streams one submission's events.
A bad or missing token closes the handshake (HTTP 403). Frame:

```json
{"v":1,"event_id":1165,"type":"pipeline.event","ts":"2026-10-11T13:39:42Z","submission_id":"<uuid>|null",
 "stage":"reasoning","step":"finished","level":"info","message":"...","data":{}}
```

The client reconnects with exponential backoff (1s to 15s), refreshes the token first, and refetches visible data on
every (re)connect.

## 4. Provider / agentic distinction (Stage 4)

Every place a verdict is returned carries which path produced it. Never merge these into one "AI" label.

| Field | Values |
|---|---|
| `provider_path` | `rule_engine` (deterministic rules), `agentic` (rule engine then LLM tool loop), `active_list` (previously convicted hash/package/IOC), `fallback` (configured reasoner failed, rule engine answered) |
| `provider_detail` | honest string: `rule_engine v0.1`, `rule_engine v0.1 + <model> (agentic, N tool calls)`, `active_list_match v0.1` |
| `tool_calls` | number of `tool_call` steps in the trace |
| `verdict.agentic_trace[]` | `{type: tool_call|conclude|malformed_json|invalid_tool_call|turn_limit_reached, tool, args, reason, result, ...}` |

Present on: submission rows, `submissions/{id}` (`verdict.provider.{name,version,detail,path,fallback_from}` and
`verdict.agentic_trace`, plus `verdict_history[]`), `remediation-queue.candidates[]`, `graph.apps[]`.

## 5. Endpoints (`/api/v1/dash/`)

Pagination: `?page=&page_size=` (max 100) returning `{count, next, previous, results}`.

| Page | Method + path | Notes |
|---|---|---|
| Overview | `GET stats` | `devices_online, devices_total, submissions_today, submissions_yesterday, submissions_total, by_label{malicious,suspicious,benign,unknown}, in_progress, avg_time_to_verdict_s, ttv_p95_s, pending_remediations, ttv_series[{at,seconds}], malicious_24h` |
| Overview | `GET events?limit=&since_event_id=` | `{events:[PipelineEvent]}` newest-last; the live feed |
| Submissions | `GET submissions?label=&status=&q=&device=&page=` | `status=in_progress` is a virtual filter. Row: `id, package_name, app_label, version_name, device{id,name}, status, status_label, label, confidence, provider, provider_detail, provider_path, tool_calls, fallback_from, overridden, remediation_hold, created_at, updated_at, in_progress` |
| Submission detail | `GET submissions/{id}` | `{submission, sample, evidence, verdict, verdict_history, effective_label, analyst_actions, remediation, remediations, rules, events_count}` |
| | `GET submissions/{id}/events?since_event_id=` | evidence chain |
| | `POST submissions/{id}/override` | `{label, note(5+ chars), notify?}` |
| | `POST submissions/{id}/reanalyze` | 202 |
| | `POST submissions/{id}/remediation` | `{action:"uninstall", note?}` 201; `409 state_conflict` with failing guardrail `checks` |
| | `POST submissions/{id}/hold` | `{hold: bool}` |
| | `POST submissions/{id}/generate-rules` | 202 |
| Devices | `GET devices` | `{devices:[{id,name,android_version,app_version,last_seen,online,protection_on,revoked,scans,paired_at}]}` |
| | `POST pairing-code` | 201 `{code, expires_at}` |
| Network Monitor | `GET network` | `kpis, events_per_minute[60], alerts[], agents[], talkers[], iocs[], attck[{tactic,count}]` |
| Threat Graph | `GET graph` | `devices[], apps[], signals[], iocs[{id,value,kind:host\|ip,flagged,app_ids[]}], shared_iocs, active_threats`. `iocs` holds only endpoints that are flagged (shortener / dyn-DNS / paste host, hard-coded IP) or referenced by 2+ apps; each one links to every app that references it. `shared_iocs` = how many of those are referenced by 2+ apps. Capped at 30. |
| Pipeline | `GET pipeline` | `stages[{key,name,status,description,metric}], health, reasoner_backend, llm_model, submissions_by_status` |
| Remediation | `GET remediation-queue` | `open[]` (pending/delivered requests), `candidates[]` (malicious/suspicious, no open request), `auto_remediation_enabled` |
| | `GET remediations?state=` | full history |
| | `POST remediations/{id}/cancel` | |
| Rules | `GET rules?status=&kind=&q=` | row adds `hits`, `attck[{id,name,tactic}]`, `package_name` |
| | `POST rules/{id}/approve` `{note?}` / `retire` `{note?}` | switch on = approved. A draft whose FP test did not pass needs a note. Retired rules cannot be re-approved (edit creates a new version) |
| Simulate (hidden button on Overview) | `POST demo/simulate` | Analyst only. Installs 2 fixed harmless test APKs (`backend/evalkit/demo_apks/`) on the USB-connected phone with `adb install -r -t`, first (re)creating the `adb reverse` tunnel so the phone reaches this server with no internet. Opens a 10-minute "fresh analysis" window so these two packages bypass the same-file dedupe and run the full pipeline. `200 {device_serial, tunnel, delivered, results[]}`; `409 no_device`; `503 adb_missing`; `502` if none were delivered. Env: `SENTINEL_ADB`, `SENTINEL_ADB_SERIAL`. |
| Settings | `GET settings` | `{settings, reputation_counts, env:{dynamic_available, reasoner_options, analysis_version}}` |
| | `POST settings` | `{key, value}`; keys: `auto_remediation_enabled, auto_remediation_min_confidence (0.5-0.99), remediation_rate_limit_per_device_hour (1-100), protected_packages, reasoner_backend (rules|hybrid), dynamic_enabled, show_demo_console` |

### Data honesty notes

- **Network Monitor** has no packet/firewall telemetry in this deployment. It shows what exists: pipeline event
  throughput, warn/error events and rule matches as alerts, API/worker/Redis health plus paired devices as agents,
  IOC endpoints extracted from analysed samples, and ATT&CK tactics cited by verdicts. IOC positions on the globe are a
  stable hash of the value, not geolocation.
- **Design controls without a backend setting** ("Notify device users", "Require on-device confirmation", "Device poll
  interval") are not rendered; they would not be backed by anything.
- Remediation "Approve" in the mock maps to "Request uninstall": the device user still confirms on the phone.
