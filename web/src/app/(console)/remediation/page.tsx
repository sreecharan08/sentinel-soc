"use client";

import Link from "next/link";
import { useState } from "react";
import { Card, ErrorBox, Icon, PageHead, ProviderBadge, StatusPill, VerdictChip } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/auth";
import { ago, pct } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { QueueData } from "@/lib/types";

export default function RemediationPage() {
  const session = useSession();
  const analyst = session?.user.role === "analyst";
  const { data, error, reload } = useApi<QueueData>("/dash/remediation-queue", { live: true });
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  async function act(key: string, fn: () => Promise<unknown>) {
    setBusy(key);
    setActionError(null);
    try {
      await fn();
      reload();
    } catch (e) {
      setActionError(e instanceof ApiError ? e.message : "Action failed.");
    } finally {
      setBusy(null);
    }
  }

  const empty = data && data.open.length === 0 && data.candidates.length === 0;
  return (
    <>
      <PageHead eyebrow="Analyst & on-device approval required" title="Remediation queue" />
      <Card>
        <p className="lede">
          Nothing is removed automatically unless auto-remediation is switched on in Settings
          ({data?.auto_remediation_enabled ? "currently on" : "currently off"}). Every request still needs the device
          user&apos;s own confirmation on the phone.
        </p>
        {error ? <ErrorBox message={error.message} /> : null}
        {actionError ? <ErrorBox message={actionError} /> : null}
        {empty ? <div className="remed-empty">Queue is clear &mdash; no pending remediation actions.</div> : null}

        {data && data.open.length ? <div className="card-title" style={{ margin: "6px 0 10px" }}>Open requests</div> : null}
        <div className="remed-list">
          {(data?.open ?? []).map((r) => (
            <div className="remed-card" key={r.id}>
              <div className="remed-sev" style={{ background: "var(--suspicious-soft)", color: "var(--suspicious)" }}><Icon name="clock" size={16} /></div>
              <div className="remed-body">
                <div className="title">Uninstall requested &mdash; {r.app_label || r.package_name}</div>
                <div className="reason">
                  <StatusPill kind="working">{r.state}</StatusPill> &middot; origin {r.origin}
                  {r.created_by ? ` by ${r.created_by}` : ""} &middot; expires {ago(r.expires_at).replace(" ago", "")}
                </div>
                <div className="meta">{r.package_name} &middot; {r.device.name} &middot;{" "}
                  <Link href={`/submissions/${r.submission_id}`} style={{ color: "var(--accent)" }}>view submission</Link>
                </div>
              </div>
              <div className="remed-actions">
                <button className="btn ghost" type="button" disabled={!analyst || busy === r.id}
                  onClick={() => act(r.id, () => api(`/dash/remediations/${r.id}/cancel`, { method: "POST", body: {} }))}>
                  Cancel
                </button>
              </div>
            </div>
          ))}
        </div>

        {data && data.candidates.length ? <div className="card-title" style={{ margin: "18px 0 10px" }}>Awaiting analyst decision</div> : null}
        <div className="remed-list">
          {(data?.candidates ?? []).map((c) => {
            const mal = c.label === "malicious";
            return (
              <div className="remed-card" key={c.submission_id}>
                <div className="remed-sev" style={{ background: mal ? "var(--malicious-soft)" : "var(--suspicious-soft)", color: mal ? "var(--malicious)" : "var(--suspicious)" }}>
                  <Icon name="alert" size={16} />
                </div>
                <div className="remed-body">
                  <div className="title">{c.app_label || c.package_name}</div>
                  <div className="reason">{c.explanation}</div>
                  <div className="meta">
                    <VerdictChip label={c.label} confidence={c.confidence} /> {pct(c.confidence)}% &middot; {c.package_name} &middot; {c.device.name}
                  </div>
                  <div style={{ marginTop: 6 }}><ProviderBadge p={c} /></div>
                </div>
                <div className="remed-actions">
                  <Link className="btn ghost" href={`/submissions/${c.submission_id}`}>Review</Link>
                  <button className="btn primary" type="button" disabled={!analyst || busy === c.submission_id}
                    onClick={() => act(c.submission_id, () => api(`/dash/submissions/${c.submission_id}/remediation`,
                      { method: "POST", body: { action: "uninstall", note: "Requested from remediation queue" } }))}>
                    Request uninstall
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </Card>
    </>
  );
}
