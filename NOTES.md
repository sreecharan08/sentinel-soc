# Sentinel SOC - build notes (working log)

Source specs: the six stage zips in `AD(3-1)/` (extracted to `%TEMP%\claude\stages\`). `shared/` is a copy of
`CONTRACTS.md` + JSON schemas (identical in every zip).

## Scope
| Stage | Status | Where |
|---|---|---|
| S1 Android app | building | `android/` |
| S2 Backend & orchestration | building | `backend/devices`, `backend/submissions`, `backend/pipeline`, `backend/reasoning` |
| S3 Analysis (static) | building | `backend/analysis` |
| S4 Reasoning | built, opt-in via `REASONER_BACKEND=hybrid` (default stays `rules`) | `backend/stage4_reasoning`, adapter `backend/reasoning/hybrid_reasoner.py` |
| S5 SOC dashboard | building | `backend/dashboard` |
| S6 Remediation & rules | building | `backend/remediation`, `backend/rules` |
| S7 Validation & demo | building | `backend/evalkit`, fixtures in `fixtures/` |

## Decisions (deviations from the specs, with reasons)
- **Stage 4 = `stage4_reasoning/` (rule engine + active lists + agentic loop) behind the existing seam.** Selected with
  `REASONER_BACKEND=hybrid` or the dashboard setting; `rules` remains the default and the fallback when the hybrid
  reasoner fails or times out. Changes vs the delivered module: imports made relative (its flat `rules`/`schema`
  module names collide with the Django `rules` app) and the three `tools.py` stubs wired to stored evidence/history.
  Static evidence is mapped to behaviour tags only where it directly shows the capability (accessibility gestures,
  SMS send + SEND_SMS, runtime code loading + embedded executable); Stage 3 emits no native-lib entropy yet, so
  STG4-003 does not fire. Dynamic re-trace tool reports "unavailable".
- **Dynamic analysis (S3 stretch) not built.** `DYNAMIC_ENABLED=false`. The step is recorded as `skipped` in the
  evidence chain. `run_dynamic_analysis_impl` returns False, so the verification loop never runs.
- **Redis via Docker** (`redis:7`, container `sentinel-redis`, port 6379). Celery worker runs with `-P solo` (Windows).
- **Androguard 4.1.4** for manifest + certificates. DEX is read with a small pure-Python string-pool parser
  (`analysis/dexfile.py`) so API references and identifier statistics do not need decompilation.
  API patterns count as present when class descriptor and member name are both in the string pool.
- **Signal SIG-REP-003 (YARA)** uses a fixed `medium` severity (spec says per-rule meta). Simplification.
- **Sigma rules** are evaluated in `post_verdict` (after the verdict), not at submission creation.
- **Phone connection:** USB + `adb reverse tcp:9000 tcp:9000` (and `tcp:8000 tcp:9000` for apps paired against the old default), so the phone reaches the laptop at
  `http://127.0.0.1:9000`. LAN IP works too (`http://<laptop-ip>:9000`). Cleartext is allowed for 127.0.0.1 / 10.0.2.2 / LAN in the demo build.
- **Fixture calibration** (S7 exp-apk spec): exp_plain would score `suspicious` (0.65). To exercise the
  malicious->uninstall path, the fixture also declares SYSTEM_ALERT_WINDOW + REQUEST_INSTALL_PACKAGES (two medium signals).

## Running (dev)
- Redis: `docker start sentinel-redis` (first time: `docker run -d --name sentinel-redis -p 6379:6379 redis:7`)
- Backend venv: `backend/.venv` (Python 3.13). Env: `REDIS_URL=redis://127.0.0.1:6379/0`
- Web (ASGI/daphne): `python -m daphne -b 0.0.0.0 -p 9000 sentinel.asgi:application` (or `scripts/start-stack.ps1`)
- Worker: `celery -A sentinel worker -l info -Q default,analysis,reasoning -P solo`
- Phone: `adb reverse tcp:9000 tcp:9000` (scripts/usb-tunnel-watch.ps1 keeps it alive)

## Stage 4 local LLM (Ollama)
`ollama pull qwen2.5:3b-instruct`, then set for the web + worker processes:
`REASONER_BACKEND=hybrid STAGE4_LLM_BASE_URL=http://localhost:11434/v1 STAGE4_LLM_API_KEY=ollama STAGE4_LLM_MODEL=qwen2.5:3b-instruct`.
Without the STAGE4_LLM_* vars the loop uses a deterministic mock. Demo: `cd backend && python -m stage4_reasoning.demo`.
Active lists persist in `DATA_DIR/stage4_active_lists.json`.

## Progress log
- [x] Repo skeleton, settings, Celery app, ASGI routing, contract error body
- [x] devices (register, heartbeat, commands, ack)
- [x] submissions (create, upload with hash/magic/size checks, device GET)
- [x] pipeline (events, state machine, chain, health)
- [x] reasoning seam + rule_engine
- [x] analysis (safe zip, dex parser, manifest, signing, code, native, files, strings/IOCs, reputation, YARA, signals, engine, tasks, CLI)
- [x] remediation (policy, services, device result, analyst propose/cancel/hold)
- [ ] rules (YARA + Sigma generators, evaluator, approve/retire, dash endpoints)
- [ ] dashboard (settings store, perms, API, pages, CSS, JS)
- [ ] evalkit + demo tooling (seed/reset/preflight/run_eval/evidence pack)
- [ ] migrations, first run, unit tests
- [ ] fixtures (exp_plain etc.) built with Gradle
- [ ] Android app (Gradle, screens, WatchService, SubmitWorker, notifications, uninstall)
- [ ] end-to-end on the connected phone
