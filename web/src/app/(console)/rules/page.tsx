"use client";

import { useState } from "react";
import { Card, ErrorBox, PageHead, Switch } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/auth";
import { useApi } from "@/lib/hooks";
import type { Page, RuleOut } from "@/lib/types";

interface RuleDetail {
  rule: RuleOut & { content: string; meta: Record<string, unknown>; approve_note: string };
  versions: RuleOut[];
  matches: { id: number; submission_id: string; package_name: string; ts: string; false_positive: boolean }[];
}

function RuleDetailPanel({ id }: { id: string }) {
  const { data, error, loading } = useApi<RuleDetail>(`/dash/rules/${id}`);
  if (error) return <ErrorBox message={error.message} />;
  if (loading || !data) return <div className="empty">Loading rule…</div>;
  const { rule, versions, matches } = data;
  const meta = Object.entries(rule.meta ?? {}).filter(([, v]) => typeof v !== "object" || v === null);
  return (
    <div className="rule-detail">
      <div className="rule-detail-head">
        <span className="rule-type">{rule.kind.toUpperCase()}</span>
        <span className="mono">{rule.name}</span>
        <span className="rule-status">v{rule.version} · {rule.status} · level {rule.level}</span>
        <button type="button" className="btn ghost" style={{ marginLeft: "auto" }}
          onClick={() => void navigator.clipboard?.writeText(rule.content)}>Copy rule</button>
      </div>
      <pre className="rule-code" tabIndex={0} aria-label={`${rule.name} rule source`}>{rule.content || "(empty rule)"}</pre>
      <div className="rule-detail-grid">
        <div>
          <h4>Details</h4>
          <div className="tech">FP test: {rule.fp_test?.status ?? "not run"}</div>
          <div className="tech">Source file: <span className="mono">{rule.source_sha256.slice(0, 24)}…</span></div>
          {rule.approve_note ? <div className="tech">Approval note: {rule.approve_note}</div> : null}
          {meta.map(([k, v]) => <div className="tech" key={k}>{k}: <span className="mono">{String(v)}</span></div>)}
          {rule.attck.length ? (
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 6 }}>
              {rule.attck.map((t) => <span key={t.id} className="attck-tag" title={t.name}>{t.id} {t.name}</span>)}
            </div>
          ) : null}
        </div>
        <div>
          <h4>Versions ({versions.length})</h4>
          {versions.map((v) => <div className="tech" key={v.id}>v{v.version} · {v.status} · {new Date(v.created_at).toLocaleString()}</div>)}
          <h4 style={{ marginTop: 10 }}>Matches ({matches.length})</h4>
          {matches.length === 0 ? <div className="tech">No matches yet.</div> : null}
          {matches.map((m) => (
            <div className="tech" key={m.id}>{m.package_name} · {new Date(m.ts).toLocaleString()}{m.false_positive ? " · false positive" : ""}</div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function RulesPage() {
  const session = useSession();
  const analyst = session?.user.role === "analyst";
  const { data, error, reload } = useApi<Page<RuleOut>>("/dash/rules?page_size=100", { live: true });
  const [pending, setPending] = useState<RuleOut | null>(null);
  const [note, setNote] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);

  async function toggle(rule: RuleOut, needNote = false) {
    setActionError(null);
    try {
      if (rule.status === "approved") {
        await api(`/dash/rules/${rule.id}/retire`, { method: "POST", body: { note: "Disabled from dashboard" } });
      } else if (rule.status === "draft") {
        const passed = rule.fp_test.status === "passed";
        if (!passed && !needNote) {
          setPending(rule);
          return;
        }
        await api(`/dash/rules/${rule.id}/approve`, { method: "POST", body: { note: needNote ? note : "Approved from dashboard" } });
      }
      setPending(null);
      setNote("");
      reload();
    } catch (e) {
      setActionError(e instanceof ApiError ? e.message : "Rule update failed.");
    }
  }

  return (
    <>
      <PageHead eyebrow="YARA + Sigma, generated from verdicts" title="Detection rules" />
      <Card>
        <p className="lede">
          YARA rules run over static features; Sigma rules run over manifest and runtime events. Rules are drafted from
          verdicts and only run once approved. Turning a rule off retires it; a retired rule is replaced by a new version.
        </p>
        {error ? <ErrorBox message={error.message} /> : null}
        {actionError ? <ErrorBox message={actionError} /> : null}
        {pending ? (
          <div className="path-banner" style={{ marginBottom: 12, flexWrap: "wrap" }}>
            <span>{pending.name}: the false-positive test did not pass. Add a note to approve anyway.</span>
            <input className="input" style={{ flex: 1, minWidth: 200 }} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Why is this safe to enable?" />
            <button className="btn accent" type="button" disabled={!note.trim()} onClick={() => toggle(pending, true)}>Approve</button>
            <button className="btn ghost" type="button" onClick={() => setPending(null)}>Cancel</button>
          </div>
        ) : null}
        <div className="rules-list">
          {data && data.results.length === 0 ? <div className="empty">No rules yet. Rules are generated from malicious verdicts.</div> : null}
          {(data?.results ?? []).map((r) => (
            <div key={r.id} className={`rule-item${openId === r.id ? " open" : ""}`}>
              <div className="rule-row clickable" role="button" tabIndex={0} aria-expanded={openId === r.id}
                onClick={() => setOpenId(openId === r.id ? null : r.id)}
                onKeyDown={(e) => {
                  if (e.target === e.currentTarget && (e.key === "Enter" || e.key === " ")) {
                    e.preventDefault();
                    setOpenId(openId === r.id ? null : r.id);
                  }
                }}>
                <span className="rule-id">{r.id.slice(0, 6)}</span>
                <span className="rule-name">
                  {r.name} <span className="rule-status">v{r.version} · {r.status}{r.needs_review ? " · needs review" : ""}</span>
                  <span className="target">{r.package_name ?? r.source_sha256.slice(0, 16)}</span>
                </span>
                <span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                  {r.attck.length === 0 ? <span className="provider-tag">no ATT&amp;CK tag</span> : null}
                  {r.attck.slice(0, 2).map((t) => <span key={t.id} className="attck-tag" title={t.name}>{t.id}</span>)}
                </span>
                <span className="rule-type">{r.kind}</span>
                <span className="rule-hits">{r.hits} hits</span>
                <span onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()}>
                  <Switch on={r.status === "approved"} label={`${r.name} enabled`} disabled={!analyst || r.status === "retired"}
                    title={r.status === "retired" ? "Retired rules cannot be re-enabled" : undefined}
                    onChange={() => void toggle(r)} />
                </span>
              </div>
              {openId === r.id ? <RuleDetailPanel id={r.id} /> : null}
            </div>
          ))}
        </div>
      </Card>
    </>
  );
}
