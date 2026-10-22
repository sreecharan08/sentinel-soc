"""
Stage 4 entry point. This is the hybrid design: deterministic rules run
first and are trusted outright when they're confident; the LLM loop is
only invoked -- and only ever does real work -- when the rule engine's own
confidence is borderline. That split is what keeps the "agentic" label
honest: the agent isn't decoration on top of a rule engine, it's the part
that actually runs the cases the rule engine can't resolve on its own, by
calling real tools and changing its next decision based on what comes back.

Every verdict carries an honest `provider` string so the dashboard can show
analysts exactly which path produced it -- "rule_engine v0.1" alone, or
"rule_engine v0.1 + qwen-turbo (agentic, N tool calls)". Never collapse
that distinction in the UI.
"""

from __future__ import annotations

import json

from .active_lists import CorrelationWindow, JSONActiveLists
from .llm_client import LLMClient
from .rules import aggregate_confidence, evaluate
from .schema import AnalysisRecord, RuleHit, Stage4Verdict
from .tools import TOOLS

BORDERLINE_BAND = (0.35, 0.75)  # outside this range, the rule engine's own call stands
MAX_AGENT_TURNS = 4

SYSTEM_PROMPT = """You are a malware-triage reasoning assistant inside a mobile-SOC pipeline.
You are given a sample's static/dynamic analysis signals and a deterministic rule engine's
first-pass hits. The rule engine was not confident enough to conclude on its own -- that is
exactly why you were invoked. Decide what additional evidence would actually change the
verdict, request it with a tool call, and only conclude once you have enough to justify a
specific verdict and MITRE ATT&CK mapping.

Reply with EXACTLY one JSON object per turn, no prose outside it. Either:
  {"action": "<tool_name>", "args": {...}, "reason": "<why this check, specifically>"}
or, when you have enough to decide:
  {"action": "conclude", "verdict": "malicious|suspicious|benign|unknown",
   "confidence": <0.0-1.0>, "attck": ["T...", ...], "rationale": "<short analyst-style justification>"}

Available tools: request_dynamic_trace(focus), request_similar_samples(ioc), request_manifest_detail().
Never call the same tool with the same args twice. If nothing more would change your answer,
conclude instead of stalling.
"""


def _record_to_context(record: AnalysisRecord, hits: list[RuleHit]) -> str:
    return json.dumps({
        "sample_id": record.sample_id,
        "package_name": record.package_name,
        "dangerous_permissions": record.dangerous_permissions,
        "dynamic_behaviors": record.dynamic_behaviors,
        "network_iocs": vars(record.network),
        "max_native_entropy": record.max_native_entropy(),
        "cert_self_signed": record.cert.is_self_signed,
        "rule_engine_hits": [
            {"rule_id": h.rule_id, "level": h.level, "description": h.description, "attck": h.attck}
            for h in hits
        ],
    }, indent=2)


def run_agentic_loop(record: AnalysisRecord, hits: list[RuleHit], llm: LLMClient) -> dict:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _record_to_context(record, hits)},
    ]
    trace: list[dict] = []

    for _ in range(MAX_AGENT_TURNS):
        try:
            reply = llm.chat_json(messages)
        except ValueError as e:
            # Malformed JSON from the model -- the known failure mode on
            # small models like qwen2.5:1.5b under load. Tell the model
            # what it did wrong and give it another turn instead of
            # crashing the whole pipeline on a bad response.
            messages.append({"role": "tool", "content": json.dumps(
                {"error": f"your last reply was not valid JSON: {e}. Reply with exactly one JSON object."}
            )})
            trace.append({"type": "malformed_json", "detail": str(e)})
            continue

        if reply.get("action") == "conclude":
            trace.append({"type": "conclude", **reply})
            return {"final": reply, "trace": trace}

        tool_name = reply.get("action")
        args = reply.get("args", {})
        tool_fn = TOOLS.get(tool_name)
        if tool_fn is None:
            # model asked for a tool that doesn't exist -- tell it so and
            # let it recover instead of crashing the pipeline
            messages.append({"role": "assistant", "content": json.dumps(reply)})
            messages.append({"role": "tool", "content": json.dumps({"error": f"no such tool: {tool_name}"})})
            trace.append({"type": "invalid_tool_call", "requested": tool_name})
            continue

        result = tool_fn(record, **{k: v for k, v in args.items() if k != "record"})
        trace.append({"type": "tool_call", "tool": tool_name, "args": args, "reason": reply.get("reason"), "result": result})
        messages.append({"role": "assistant", "content": json.dumps(reply)})
        messages.append({"role": "tool", "content": json.dumps(result)})

    # ran out of turns without a conclusion -- fail safe to "unknown", never
    # silently promote to a confident verdict just because the loop ended
    trace.append({"type": "turn_limit_reached"})
    return {
        "final": {"verdict": "unknown", "confidence": 0.3, "attck": [],
                   "rationale": "agentic loop reached its turn limit without converging; routed to analyst review"},
        "trace": trace,
    }


def analyze(record: AnalysisRecord, active_lists: JSONActiveLists, correlation: CorrelationWindow,
            llm: LLMClient | None = None) -> Stage4Verdict:
    llm = llm or LLMClient()

    # 1. Active-list short-circuit: have we already convicted this exact
    #    sample, this package, or shared infra before? Skip straight to a
    #    verdict -- this is the "seen it before" fast path, not reasoning.
    known = active_lists.is_known_bad(
        sha256=record.sha256, package_name=record.package_name,
        iocs=record.network.urls + record.network.domains + record.network.ips,
    )
    if known:
        return Stage4Verdict(
            sample_id=record.sample_id, verdict=known.verdict, confidence=known.confidence,
            attck=[], rationale=f"Matched existing active-list entry ({known.hit_count} prior hits).",
            rule_hits=[], provider="active_list_match v0.1",
        )

    # 2. Deterministic rule engine, always runs.
    hits = evaluate(record, correlation)
    bucket, confidence = aggregate_confidence(hits)

    if not (BORDERLINE_BAND[0] <= confidence <= BORDERLINE_BAND[1]):
        verdict = Stage4Verdict(
            sample_id=record.sample_id, verdict=bucket, confidence=confidence,
            attck=sorted({a for h in hits for a in h.attck}),
            rationale=f"Rule engine confident ({confidence}); agentic review not triggered.",
            rule_hits=hits, provider="rule_engine v0.1",
        )
    else:
        # 3. Borderline -- hand off to the real agentic loop.
        result = run_agentic_loop(record, hits, llm)
        final = result["final"]
        verdict = Stage4Verdict(
            sample_id=record.sample_id, verdict=final["verdict"], confidence=float(final["confidence"]),
            attck=final.get("attck", []), rationale=final["rationale"], rule_hits=hits,
            provider=f"rule_engine v0.1 + {llm.model} (agentic, {sum(1 for t in result['trace'] if t['type'] == 'tool_call')} tool calls)",
            agentic_trace=result["trace"],
        )

    active_lists.record_verdict(
        sha256=record.sha256, package_name=record.package_name,
        verdict=verdict.verdict, confidence=verdict.confidence,
        iocs=record.network.urls + record.network.domains,
    )
    return verdict
