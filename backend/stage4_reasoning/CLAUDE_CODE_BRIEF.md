# Stage 4 (Reasoning Layer) — build brief for Claude Code

## Do not redesign this

Every file in this folder (`schema.py`, `rules.py`, `active_lists.py`, `llm_client.py`,
`tools.py`, `agent.py`, `demo.py`, `requirements.txt`) is final as written. Do not
rewrite the rule engine, the severity scale, the confidence thresholds, the active-list
logic, or the agentic loop's control flow. Your job is to **set this up and wire it into
the existing project exactly as designed**, not to improve or restructure it.

The one thing you may legitimately need to change is `tools.py`'s three stub functions
(`request_dynamic_trace`, `request_similar_samples`, `request_manifest_detail`) --
each is marked `TODO` where it needs a real call into the existing Stage 2/3 pipeline
instead of returning placeholder data. Everything else stays as-is.

## What this is

This is Stage 4 of a 7-stage project ("Sentinel SOC" / "clg proj"): an Android app
reports newly-installed packages to a Django backend, which runs them through static +
dynamic analysis (Stage 3), and this module decides the verdict (malicious / suspicious
/ benign / unknown) with a MITRE ATT&CK mapping and a confidence score.

It is a **hybrid** design, not a single classifier:
1. A deterministic rule engine (`rules.py`) runs first, Wazuh-inspired: 0-16 severity
   per rule, plus device-level correlation (3+ medium findings on one device escalates).
2. An active-lists cache (`active_lists.py`) short-circuits repeat samples/IOCs that
   were already convicted.
3. Only when the rule engine's own confidence is borderline (0.35-0.75) does a real
   agentic LLM loop (`agent.py`'s `run_agentic_loop`) get invoked -- it calls genuine
   tools (`tools.py`) that change what it sees next, and only concludes once it has
   enough evidence.

**This split is a hard constraint, not a style choice:** the rule engine must never be
presented or logged as "AI" or "agentic" -- it's deterministic if/then logic. Every
verdict already carries an honest `provider` string (`rule_engine v0.1` vs
`rule_engine v0.1 + <model> (agentic, N tool calls)`) -- preserve that distinction
anywhere this surfaces in the dashboard, logs, or docs. Do not blur it.

## Integration target

Existing repo: Django + DRF + Celery + Channels backend, dir `sentinel-soc`, no JS
framework on the dashboard (`templates/` + `static/soc.css` + `static/soc.js`).

Drop this folder in as its own Django app, e.g. `sentinel-soc/stage4_reasoning/`
(the module's internal imports are flat/relative already -- `from schema import ...`
etc. -- so it works as a plain package; add an `__init__.py` if Django's app loader
needs one, don't otherwise restructure the imports).

Wire `agent.analyze()` as the function Stage 3's pipeline calls once analysis finishes
for a sample (Celery task), passing an `AnalysisRecord` (see `schema.py`) built from
whatever Stage 3 actually outputs. The returned `Stage4Verdict` is what gets persisted
and pushed to the dashboard over Channels.

## Running it locally (the whole point of this design)

This is built to run against a **local Ollama model, free, no cloud dependency**, which
matters directly for the project's own abstract ("entire stack runs without cloud
dependencies... air-gapped/resource-constrained environments") and for a ~1-week
continuous college demo with zero ongoing cost:

```
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:3b-instruct      # or qwen2.5:1.5b-instruct if storage is tighter
```

Then set these three env vars wherever the Django/Celery process runs (`.env`, systemd
unit, or however the project already manages config):

```
STAGE4_LLM_BASE_URL=http://localhost:11434/v1
STAGE4_LLM_API_KEY=ollama
STAGE4_LLM_MODEL=qwen2.5:3b-instruct
```

With no env vars set at all, `llm_client.py` falls back to a deterministic mock --
useful for running `demo.py` and any tests without Ollama installed, but **the actual
demo must run with Ollama configured**, not the mock, since the mock doesn't do real
reasoning.

## Verify before considering this done

Run `python demo.py` from inside this folder and confirm:
- It prints `LLM backend: qwen2.5:...` (not `MOCK`) once Ollama is wired up.
- All sample verdicts print with no traceback.
- At least one borderline-confidence sample in real usage shows a `provider` string
  containing `(agentic, N tool calls)` with N >= 1 -- if every verdict ever shows
  `rule_engine v0.1` alone, the agentic path isn't actually being exercised and that's
  worth flagging back, not silently accepting.

`requirements.txt` has exactly one dependency (`openai` -- used for its client against
Ollama's OpenAI-compatible endpoint, not against OpenAI itself). Install it in whatever
virtualenv the Django project already uses.
