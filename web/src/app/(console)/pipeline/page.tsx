"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Card, ErrorBox, ProviderBadge, StatusPill, VerdictChip } from "@/components/ui";
import { Chamber } from "@/components/webgl/Chamber";
import { buildPipelineStack, STAGE_COLOR, type StackUi } from "@/components/webgl/pipelineStack";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/auth";
import { ago, clock } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { useRealtime } from "@/lib/realtime";
import type { Page, PipelineData, PipelineEvent, SubmissionRow } from "@/lib/types";

/** Which of the 7 stack stages a pipeline event belongs to (event.stage -> stage key from /dash/pipeline). */
const EVENT_STAGE: Record<string, string> = {
  device: "android", intake: "backend", system: "backend", static_analysis: "analysis", dynamic_analysis: "dynamic",
  reasoning: "reasoning", verdict: "dashboard", rules: "dashboard", remediation: "remediation",
};
const LEGEND: [string, string][] = [["#39ff9a", "active"], ["#9fb4c9", "idle"], ["#56677a", "disabled"]];
const hex = (n: number) => `#${n.toString(16).padStart(6, "0")}`;

export default function PipelinePage() {
  const { data, error } = useApi<PipelineData>("/dash/pipeline", { live: true });
  const subs = useApi<Page<SubmissionRow>>("/dash/submissions?page_size=30", { live: true });
  const evs = useApi<{ events: PipelineEvent[] }>("/dash/events?limit=40", { live: true });
  const { subscribe } = useRealtime();
  const session = useSession();
  const analyst = session?.user.role === "analyst";

  const ui = useRef<StackUi>({ spacing: 0.8, selected: -1, flash: {} });
  const [selected, setSelectedState] = useState(-1);
  const [spacing, setSpacingState] = useState(0.8);
  const [sampleId, setSampleId] = useState("");
  const [extra, setExtra] = useState<PipelineEvent[]>([]);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const setSelected = useCallback((i: number) => { ui.current.selected = i; setSelectedState(i); }, []);
  const key = useMemo(() => (data ? JSON.stringify(data.stages.map((s) => [s.key, s.status])) : ""), [data]);
  const stages = data?.stages ?? [];

  // live events: flash the stack stage each one belongs to, and keep them for the stream
  useEffect(() => subscribe((ev) => {
    const k = EVENT_STAGE[ev.stage];
    if (k) ui.current.flash[k] = 1;
    setExtra((c) => [...c.slice(-80), ev]);
  }), [subscribe]);

  const rows = useMemo(() => subs.data?.results ?? [], [subs.data]);
  useEffect(() => { if (!sampleId && rows.length) setSampleId(rows[0].id); }, [rows, sampleId]);
  const sample = rows.find((r) => r.id === sampleId) ?? null;
  const lastVerdict = [...rows].filter((r) => r.label && !r.in_progress)
    .sort((a, b) => b.updated_at.localeCompare(a.updated_at))[0] ?? null;

  const stream = useMemo(() => {
    const seen = new Set<number>();
    return [...(evs.data?.events ?? []), ...extra]
      .filter((e) => (e.level !== "debug" && !seen.has(e.event_id) ? (seen.add(e.event_id), true) : false))
      .sort((a, b) => b.event_id - a.event_id).slice(0, 40);
  }, [evs.data, extra]);

  const run = useCallback(async () => {
    if (!analyst || !sampleId || busy) return;
    setBusy(true);
    setMsg(null);
    try {
      await api(`/dash/submissions/${sampleId}/reanalyze`, { method: "POST", body: {} });
      setMsg({ ok: true, text: "Re-analysis queued. Watch the stack and the event stream." });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof ApiError ? e.message : "Re-analysis failed" });
    } finally {
      setBusy(false);
    }
  }, [analyst, sampleId, busy]);

  // keyboard: 1-N selects a stage, R re-runs the chosen sample
  const runRef = useRef(run);
  runRef.current = run;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (e.ctrlKey || e.metaKey || e.altKey || (t && /^(INPUT|SELECT|TEXTAREA)$/.test(t.tagName))) return;
      const d = Number(e.key);
      if (d >= 1 && d <= stages.length) setSelected(ui.current.selected === d - 1 ? -1 : d - 1);
      else if (e.key === "r" || e.key === "R") void runRef.current();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [stages.length, setSelected]);

  const pick = selected >= 0 ? stages[selected] : null;

  return (
    <>
      <div className="ghead">
        <h2>Pipeline</h2>
        <div className="gsub">Analysis stack &middot; exploded view &middot; stage 1 at the bottom, stage {stages.length || 7} on top</div>
      </div>
      {error ? <ErrorBox message={error.message} /> : null}
      {data ? (
        <>
          <Chamber size="sm" deps={[key]} unavailable="This browser could not start WebGL, so the exploded view is unavailable."
            build={(canvas, chamber) => buildPipelineStack(canvas, chamber, data.stages, ui.current, setSelected)}>
            <div className="ghud ghud-top">
              <span className="gbadge"><span className="dot" />{data.health.ok ? "Healthy" : "Degraded"}</span>
              <div className="gstats">
                <span className="gstat"><b>{data.health.workers}</b>{data.health.workers === 1 ? "worker" : "workers"}</span>
                <span className="gstat"><b>{data.reasoner_backend}</b>reasoner</span>
              </div>
            </div>
            <div className="glegend stack-legend ghud">
              {LEGEND.map(([c, l]) => (
                <div className="glegend-row" key={l}><span className="glegend-dot" style={{ background: c, color: c }} /><span className="lbl">{l}</span></div>
              ))}
            </div>
            <div className="ghint ghud">drag to rotate &middot; keys 1&ndash;{stages.length} select &middot; R runs</div>
          </Chamber>

          <div className="card">
            <div className="form-row" style={{ alignItems: "center" }}>
              <label className="field-control" style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span className="provider-tag">Sample to re-analyze</span>
                <select value={sampleId} onChange={(e) => setSampleId(e.target.value)} aria-label="Sample to re-analyze" disabled={rows.length === 0}>
                  {rows.length === 0 ? <option value="">No submissions yet</option> : null}
                  {rows.map((r) => <option key={r.id} value={r.id}>{(r.app_label || r.package_name)} &middot; {r.label ?? r.status_label}</option>)}
                </select>
              </label>
              <button className="btn accent" type="button" onClick={() => void run()} disabled={!analyst || !sampleId || busy}
                title={analyst ? "Re-run the whole pipeline on the stored file (R)" : "Viewers cannot run analyses"}>
                {busy ? "Queuing…" : "Run (R)"}
              </button>
              <label className="field-control" style={{ display: "flex", gap: 8, alignItems: "center", marginLeft: "auto" }}>
                <span className="provider-tag">Spacing</span>
                <input type="range" min={0.3} max={1.6} step={0.05} value={spacing} aria-label="Spacing"
                  onChange={(e) => { const v = Number(e.target.value); ui.current.spacing = v; setSpacingState(v); }} />
              </label>
            </div>
            {msg ? <div className={msg.ok ? "provider-tag" : "error-box"} role="status" style={{ marginTop: 8 }}>{msg.text}</div> : null}
            {!analyst ? <div className="provider-tag" style={{ marginTop: 8 }}>Your role is viewer; running an analysis needs the analyst role.</div> : null}
            <div className="provider-tag" style={{ marginTop: 8 }}>
              Re-analysis re-runs the stored APK through the real pipeline (no new upload). New files arrive from paired phones.
            </div>
          </div>

          <div className="detail-grid">
            <Card title="Event stream" link={<span className="provider-tag">live &middot; {stream.length} recent</span>}>
              <div className="feed-list">
                {stream.length === 0 ? <div className="empty">No events yet.</div> : null}
                {stream.map((e) => (
                  <div key={e.event_id} className={`feed-row lvl-${e.level}`}>
                    <span className="feed-time">{clock(e.ts)}</span>
                    <span className="feed-step" style={{ color: hex(STAGE_COLOR[EVENT_STAGE[e.stage]] ?? 0x6fa8c9) }}>{e.stage}</span>
                    <span className="feed-msg" title={e.message}>{e.message}</span>
                  </div>
                ))}
              </div>
            </Card>

            <Card title="Last verdict">
              {!lastVerdict ? <div className="empty">No verdicts yet.</div> : (
                <div className="stack">
                  <div>
                    <div style={{ fontWeight: 600 }}>{lastVerdict.app_label || lastVerdict.package_name}</div>
                    <div className="provider-tag mono">{lastVerdict.package_name}</div>
                  </div>
                  <VerdictChip label={lastVerdict.label} confidence={lastVerdict.confidence} />
                  <ProviderBadge p={lastVerdict} />
                  <div className="provider-tag">{lastVerdict.device.name} &middot; {ago(lastVerdict.updated_at)}</div>
                  <Link className="back-link" href={`/submissions/${lastVerdict.id}`}>Open submission &rarr;</Link>
                </div>
              )}
              {sample && sample.id !== lastVerdict?.id ? (
                <div className="provider-tag" style={{ marginTop: 10 }}>
                  Selected sample: {sample.app_label || sample.package_name} ({sample.status_label})
                </div>
              ) : null}
            </Card>
          </div>

          {pick ? (
            <div className="card" style={{ borderColor: hex(STAGE_COLOR[pick.key] ?? 0x6fa8c9) }}>
              <div className="card-head">
                <span className="card-title">Stage {selected + 1} &middot; {pick.name}</span>
                <span className={`pipe-step`} style={{ padding: 0, border: 0, background: "none" }}>
                  <span className={`st ${pick.status}`}>{pick.status}</span>
                </span>
              </div>
              <p style={{ margin: "0 0 6px", fontSize: 13 }}>{pick.description}</p>
              <div className="provider-tag mono">{pick.metric}</div>
            </div>
          ) : null}

          <div className="pipe-steps">
            {data.stages.map((s, i) => (
              <button key={s.key} type="button" onClick={() => setSelected(selected === i ? -1 : i)}
                className={`pipe-step${s.status === "disabled" ? " deferred" : ""}${selected === i ? " sel" : ""}`}
                style={{ textAlign: "left", cursor: "pointer", color: "inherit", font: "inherit" }}>
                <div className="n">STAGE {i + 1}<span className={`st ${s.status}`}>{s.status}</span></div>
                <div className="t">{s.name}</div>
                <div className="d">{s.description}</div>
                <div className="m">{s.metric}</div>
              </button>
            ))}
          </div>

          <div className="card">
            <div className="card-head"><span className="card-title">Submissions by status</span></div>
            <div className="form-row">
              {Object.keys(data.submissions_by_status).length === 0 ? <span className="provider-tag">No submissions yet.</span> : null}
              {Object.entries(data.submissions_by_status).map(([k, v]) => (
                <StatusPill key={k} kind={k === "error" ? "err" : k === "verdict_ready" ? "done" : "working"}>{k.replace(/_/g, " ")} &middot; {v}</StatusPill>
              ))}
            </div>
          </div>
        </>
      ) : null}
    </>
  );
}
