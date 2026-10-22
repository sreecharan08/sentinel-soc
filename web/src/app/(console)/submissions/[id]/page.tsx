"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { AgenticTrace, Card, ErrorBox, ProviderBadge, StatusPill, VerdictChip } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/auth";
import { ago, bytes, clock, pct } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { useRealtime } from "@/lib/realtime";
import type { Label, PipelineEvent, SubmissionDetail } from "@/lib/types";

const LABELS: Label[] = ["malicious", "suspicious", "benign", "unknown"];

function Actions({ detail, reload }: { detail: SubmissionDetail; reload: () => void }) {
  const session = useSession();
  const analyst = session?.user.role === "analyst";
  const [label, setLabel] = useState<Label>("benign");
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const id = detail.submission.id;

  async function run(label_: string, fn: () => Promise<unknown>) {
    setMsg(null);
    try {
      await fn();
      setMsg({ ok: true, text: `${label_}: done` });
      reload();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof ApiError ? e.message : `${label_} failed` });
    }
  }

  return (
    <Card title="Analyst actions">
      {!analyst ? <div className="provider-tag">Your role is viewer; actions are read-only.</div> : null}
      <div className="stack">
        <div>
          <div className="form-row">
            <select className="input" value={label} onChange={(e) => setLabel(e.target.value as Label)} disabled={!analyst} aria-label="Override label">
              {LABELS.map((l) => <option key={l} value={l}>{l}</option>)}
            </select>
            <input className="input" style={{ flex: 1 }} placeholder="Reason (5+ characters)" value={note}
              onChange={(e) => setNote(e.target.value)} disabled={!analyst} />
            <button className="btn accent" type="button" disabled={!analyst || note.trim().length < 5}
              onClick={() => run("Override", () => api(`/dash/submissions/${id}/override`, { method: "POST", body: { label, note } }))}>
              Override verdict
            </button>
          </div>
        </div>
        <div className="form-row">
          <button className="btn" type="button" disabled={!analyst}
            onClick={() => run("Re-analyze", () => api(`/dash/submissions/${id}/reanalyze`, { method: "POST", body: {} }))}>Re-analyze</button>
          <button className="btn danger" type="button" disabled={!analyst || !detail.verdict}
            onClick={() => run("Uninstall request", () => api(`/dash/submissions/${id}/remediation`, { method: "POST", body: { action: "uninstall", note } }))}>
            Request uninstall
          </button>
          <button className="btn" type="button" disabled={!analyst}
            onClick={() => run("Hold", () => api(`/dash/submissions/${id}/hold`, { method: "POST", body: { hold: !detail.submission.remediation_hold } }))}>
            {detail.submission.remediation_hold ? "Release remediation hold" : "Hold remediation"}
          </button>
          <button className="btn" type="button" disabled={!analyst || !detail.verdict}
            onClick={() => run("Generate rules", () => api(`/dash/submissions/${id}/generate-rules`, { method: "POST", body: {} }))}>
            Generate rules
          </button>
        </div>
        {msg ? <div className={msg.ok ? "provider-tag" : "error-box"} role="status">{msg.text}</div> : null}
      </div>
    </Card>
  );
}

function Timeline({ id }: { id: string }) {
  const { data } = useApi<{ events: PipelineEvent[] }>(`/dash/submissions/${id}/events`, { live: true });
  const { subscribe } = useRealtime();
  const [extra, setExtra] = useState<PipelineEvent[]>([]);
  useEffect(() => subscribe((ev) => { if (ev.submission_id === id) setExtra((c) => [...c, ev]); }), [subscribe, id]);
  const seen = new Set<number>();
  const rows = [...(data?.events ?? []), ...extra].filter((e) => (seen.has(e.event_id) ? false : (seen.add(e.event_id), true)));
  return (
    <Card title="Evidence chain">
      <div className="feed-list">
        {rows.length === 0 ? <div className="empty">No events recorded.</div> : null}
        {rows.slice().reverse().map((e) => (
          <div key={e.event_id} className={`feed-row lvl-${e.level}`}>
            <span className="feed-time">{clock(e.ts)}</span>
            <span className="feed-step">{e.stage}</span>
            <span className="feed-msg" title={e.message}>{e.message}</span>
          </div>
        ))}
      </div>
    </Card>
  );
}

export default function SubmissionDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data, error, reload } = useApi<SubmissionDetail>(`/dash/submissions/${id}`, { live: true });
  if (error) return <><Link className="back-link" href="/submissions">← Submissions</Link><ErrorBox message={error.message} /></>;
  if (!data) return <div className="empty">Loading…</div>;
  const s = data.submission;
  const v = data.verdict;
  const signals = data.evidence?.signals ?? [];
  const label = data.effective_label ?? v?.label ?? null;
  return (
    <>
      <div className="page-head">
        <div>
          <Link className="back-link" href="/submissions">← Submissions</Link>
          <h2 style={{ marginTop: 6 }}>{s.app_label || s.package_name}</h2>
          <div className="provider-tag mono">{s.package_name} · {s.version_name || "unknown version"}</div>
        </div>
        <div className="form-row">
          {s.in_progress ? <StatusPill kind="working">{s.status_label}</StatusPill> : <VerdictChip label={label} confidence={v?.confidence} />}
          {s.overridden ? <span className="chip neutral">analyst override</span> : null}
        </div>
      </div>

      <div className="detail-grid">
        <div className="stack">
          <Card title="Verdict">
            {!v ? <div className="empty">No verdict yet ({s.status_label}).</div> : (
              <div className="stack">
                <div className="path-banner">
                  <ProviderBadge p={{ provider: `${v.provider.name} v${v.provider.version}`, provider_detail: v.provider.detail,
                    provider_path: v.provider.path, tool_calls: v.agentic_trace.filter((t) => t.type === "tool_call").length }} />
                  {v.provider.fallback_from ? <span className="provider-tag">fell back from {v.provider.fallback_from}</span> : null}
                </div>
                <p style={{ margin: 0, fontSize: 13 }}>{v.explanation}</p>
                <dl className="kv">
                  <dt>Label</dt><dd>{v.label}{label !== v.label ? ` (analyst set ${label})` : ""}</dd>
                  <dt>Confidence</dt><dd>{pct(v.confidence)}%</dd>
                  <dt>Score</dt><dd>{v.score}</dd>
                  <dt>Recommended action</dt><dd>{v.recommended_action}</dd>
                  <dt>Generated</dt><dd>{v.generated_at ?? "n/a"}</dd>
                </dl>
                {v.techniques.length ? (
                  <div>
                    <div className="card-title" style={{ marginBottom: 6 }}>MITRE ATT&amp;CK</div>
                    {v.techniques.map((t) => (
                      <div className="tech" key={t.id}>
                        <span className="attck-tag">{t.id}</span>
                        <span>{t.name}</span>
                        {t.tactic ? <span className="provider-tag">{t.tactic}</span> : null}
                        <span className="provider-tag">{t.evidence_ids.length ? `evidence ${t.evidence_ids.join(", ")}` : "no cited evidence"}</span>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            )}
          </Card>

          {v?.provider.path === "agentic" || (v?.agentic_trace.length ?? 0) > 0 ? (
            <Card title="Agentic reasoning trace">
              <AgenticTrace trace={v?.agentic_trace ?? []} />
            </Card>
          ) : null}

          <Card title={`Signals (${signals.length})`}>
            {signals.length === 0 ? <div className="empty">No signals.</div> : (
              <div className="table-scroll">
                <table style={{ minWidth: 0 }}>
                  <thead><tr><th>ID</th><th>Signal</th><th>Severity</th><th>Detail</th></tr></thead>
                  <tbody>
                    {signals.map((sig) => (
                      <tr key={sig.id} style={{ cursor: "default" }}>
                        <td className="mono">{sig.id}</td>
                        <td>{sig.name}<div className="provider-tag">{sig.code}</div></td>
                        <td><span className={`sev ${sig.severity}`}>{sig.severity}</span></td>
                        <td>{sig.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
          <Timeline id={s.id} />
        </div>

        <div className="stack">
          <Actions detail={data} reload={reload} />
          <Card title="Sample">
            <dl className="kv">
              <dt>Device</dt><dd>{s.device.name}</dd>
              <dt>SHA-256</dt><dd className="mono">{s.sha256}</dd>
              <dt>Size</dt><dd>{bytes(s.size_bytes)}</dd>
              <dt>Installer</dt><dd>{s.installer_package ?? "unknown"}</dd>
              <dt>Submitted</dt><dd>{ago(s.created_at)}</dd>
              <dt>Permissions</dt><dd>{s.requested_permissions.length}</dd>
              {s.error_code ? <><dt>Error</dt><dd>{s.error_code}: {s.error_detail}</dd></> : null}
            </dl>
          </Card>
          <Card title="Verdict history">
            {data.verdict_history.map((h) => (
              <div className="tech" key={h.id}>
                <VerdictChip label={h.label} confidence={h.confidence} />
                <ProviderBadge p={{ provider: h.provider, provider_detail: h.provider_detail, provider_path: h.provider_path, tool_calls: h.tool_calls }} />
                <span className="provider-tag">{ago(h.created_at)}{h.is_current ? " · current" : ""}</span>
              </div>
            ))}
          </Card>
          {data.analyst_actions.length ? (
            <Card title="Analyst activity">
              {data.analyst_actions.map((a, i) => (
                <div className="tech" key={i}>
                  <span className="chip neutral">{a.kind}</span>
                  <span>{a.from && a.to ? `${a.from} → ${a.to}` : ""}</span>
                  <span className="provider-tag">{a.user} · {ago(a.created_at)}{a.note ? ` · ${a.note}` : ""}</span>
                </div>
              ))}
            </Card>
          ) : null}
        </div>
      </div>
    </>
  );
}
