"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Card, Donut, ErrorBox, LineChart, ProviderBadge, StatCard, StatusPill, VerdictChip } from "@/components/ui";
import { SimulateDock } from "@/components/SimulateDock";
import { ago, clock, initials } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { useRealtime } from "@/lib/realtime";
import type { Page, PipelineEvent, Stats, SubmissionRow } from "@/lib/types";

const STAGE_LABEL: Record<string, string> = {
  intake: "intake", static_analysis: "static", dynamic_analysis: "dynamic", reasoning: "reason", verdict: "verdict",
  remediation: "remed.", rules: "rules", device: "device", system: "system",
};

function Feed() {
  const initial = useApi<{ events: PipelineEvent[] }>("/dash/events?limit=12");
  const { subscribe } = useRealtime();
  const [live, setLive] = useState<PipelineEvent[]>([]);
  useEffect(() => subscribe((ev) => setLive((cur) => [ev, ...cur].slice(0, 12))), [subscribe]);
  const base = (initial.data?.events ?? []).slice().reverse();
  const seen = new Set<number>();
  const rows = [...live, ...base].filter((e) => (seen.has(e.event_id) ? false : (seen.add(e.event_id), true))).slice(0, 12);
  return (
    <Card title="Live pipeline feed" link={<span className="feed-live-tag"><span className="feed-live-dot" />streaming</span>}>
      <div className="feed-list">
        {rows.length === 0 ? <div className="empty">No pipeline events yet.</div> : null}
        {rows.map((e) => (
          <div key={e.event_id} className={`feed-row lvl-${e.level}`}>
            <span className="feed-time">{clock(e.ts)}</span>
            <span className="feed-step">{STAGE_LABEL[e.stage] ?? e.stage}</span>
            <span className="feed-msg" title={e.message}>{e.message}</span>
          </div>
        ))}
      </div>
    </Card>
  );
}

export default function OverviewPage() {
  const stats = useApi<Stats>("/dash/stats", { live: true });
  const recent = useApi<Page<SubmissionRow>>("/dash/submissions?page_size=5", { live: true });
  const s = stats.data;
  if (stats.error) return <ErrorBox message={stats.error.message} />;
  const dayDelta = s && s.submissions_yesterday > 0
    ? Math.round(((s.submissions_today - s.submissions_yesterday) / s.submissions_yesterday) * 100) : null;
  const scanned = s ? Object.values(s.by_label).reduce((a, b) => a + b, 0) : 0;
  return (
    <>
      <section className="stat-row" aria-label="Key metrics">
        <StatCard icon="phone" tone="accent" num={s?.devices_online ?? "–"} label="Devices online"
          delta={s ? `${s.devices_total} paired` : undefined} />
        <StatCard icon="list" tone="accent" num={s?.submissions_today ?? "–"} label="Scanned today"
          delta={dayDelta === null ? undefined : `${dayDelta >= 0 ? "↑" : "↓"} ${Math.abs(dayDelta)}%`}
          deltaTone={dayDelta === null ? undefined : dayDelta >= 0 ? "up" : "down"} />
        <StatCard icon="alert" tone="mal" num={s?.malicious_24h ?? "–"} label="Malicious verdicts" delta="24h" />
        <StatCard icon="clock" tone="sus" num={s?.in_progress ?? "–"} label="In progress"
          delta={s && s.in_progress > 0 ? <StatusPill kind="working">running</StatusPill> : undefined} />
        <StatCard icon="check" tone="ben" num={s?.pending_remediations ?? "–"} label="Pending remediation" delta="queue" />
      </section>

      <section className="charts-row">
        <Card title="Verdicts · last 24h" link={<Link className="card-link" href="/submissions">View all</Link>}>
          {s ? <Donut data={s.by_label} /> : <div className="empty">Loading…</div>}
          {s && scanned === 0 ? <div className="empty">No verdicts in the last 24 hours.</div> : null}
        </Card>
        <Card title={`Time to verdict · last ${s?.ttv_series.length ?? 0} runs`}>
          <LineChart data={(s?.ttv_series ?? []).map((p) => p.seconds)} label="Time to verdict in seconds" />
          <div className="spark-foot">
            <span className="spark-avg mono">{s?.avg_time_to_verdict_s ?? "–"}</span>
            <span className="spark-avg-unit">s avg{s?.ttv_p95_s != null ? ` · p95 ${s.ttv_p95_s}s` : ""}</span>
          </div>
        </Card>
      </section>

      <section className="split-row">
        <Feed />
        <Card title="Recent submissions">
          <div className="recent-list">
            {(recent.data?.results ?? []).length === 0 && !recent.loading ? <div className="empty">No submissions yet.</div> : null}
            {(recent.data?.results ?? []).map((r) => (
              <Link key={r.id} className="recent-row" href={`/submissions/${r.id}`}>
                <span className="app-glyph">{initials(r.app_label || r.package_name)}</span>
                <span className="recent-meta">
                  <div className="name">{r.app_label || r.package_name}</div>
                  <div className="pkg">{r.package_name}</div>
                </span>
                {r.in_progress ? <StatusPill kind="working">analyzing</StatusPill> : (
                  <span style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
                    <VerdictChip label={r.label} confidence={r.confidence} />
                    <ProviderBadge p={r} compact />
                  </span>
                )}
              </Link>
            ))}
          </div>
          <div className="provider-tag" style={{ marginTop: 10 }}>
            {recent.data?.results[0] ? `Latest ${ago(recent.data.results[0].created_at)}` : null}
          </div>
        </Card>
      </section>
      <SimulateDock />
    </>
  );
}
