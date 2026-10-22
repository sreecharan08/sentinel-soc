"use client";

import Link from "next/link";
import { useMemo } from "react";
import { Card, ErrorBox, Icon, LineChart, StatCard } from "@/components/ui";
import { Chamber } from "@/components/webgl/Chamber";
import { buildGlobe } from "@/components/webgl/globe";
import { clock } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { NetworkData } from "@/lib/types";

const LVL = { crit: "C", high: "H", med: "M", low: "L" } as const;

export default function NetworkPage() {
  const { data, error } = useApi<NetworkData>("/dash/network", { live: true });
  const key = useMemo(() => (data ? JSON.stringify(data.iocs.map((i) => [i.value, i.flagged])) : ""), [data]);
  const maxTactic = Math.max(1, ...(data?.attck ?? []).map((a) => a.count));

  return (
    <>
      <div className="ghead">
        <h2>Network Monitor</h2>
        <div className="gsub">IOC endpoints &middot; alerts &middot; agents &middot; last 24h</div>
      </div>
      {error ? <ErrorBox message={error.message} /> : null}

      {data ? (
        <Chamber size="sm" deps={[key]} unavailable="This browser could not start WebGL, so the live globe is unavailable."
          build={(canvas) => buildGlobe(canvas, data.iocs)}>
          <div className="ghud ghud-top">
            <span className="gbadge"><span className="dot" />IOC extraction active</span>
            <div className="gstats">
              <span className="gstat"><b>{data.kpis.ioc_endpoints}</b>endpoints</span>
              <span className="gstat alert"><b>{data.kpis.flagged_endpoints}</b>flagged</span>
            </div>
          </div>
          <div className="glegend ghud">
            <div className="glegend-row"><span className="glegend-dot" style={{ background: "#45e8ff", color: "#45e8ff" }} /><span className="lbl">Analysis hub</span></div>
            <div className="glegend-row"><span className="glegend-dot" style={{ background: "#ffb347", color: "#ffb347" }} /><span className="lbl">IOC endpoint</span></div>
            <div className="glegend-row"><span className="glegend-dot" style={{ background: "#ff4d6a", color: "#ff4d6a" }} /><span className="lbl">Flagged host</span></div>
          </div>
          <div className="ghint ghud">Drag to rotate &middot; positions are not geographic</div>
        </Chamber>
      ) : null}

      <div className="nm-stat-row">
        <StatCard icon="pulse" tone="accent" num={data?.kpis.events_last_minute ?? "–"} label="Pipeline events / min" />
        <StatCard icon="alert" tone="mal" num={data?.kpis.warn_error_24h ?? "–"} label="Warnings + errors (24h)" />
        <StatCard icon="plus" tone="ben" num={data?.kpis.ioc_endpoints ?? "–"} label="IOC endpoints" />
        <StatCard icon="clock" tone="sus" num={data?.kpis.rule_matches_24h ?? "–"} label="Rule matches (24h)" />
      </div>

      <div className="nm-grid">
        <Card title="Live alerts" link={<span className="feed-live-tag"><span className="feed-live-dot" />streaming</span>}>
          <div className="alert-table">
            {data && data.alerts.length === 0 ? <div className="empty">No alerts in the last 24 hours.</div> : null}
            {(data?.alerts ?? []).map((a, i) => (
              <div className="alert-row" key={`${a.ts}-${i}`}>
                <span className="alert-time">{clock(a.ts)}</span>
                <span className={`lvl-badge l-${a.level}`}>{LVL[a.level]}</span>
                <span className="alert-body">
                  <div className="desc">{a.message}</div>
                  <div className="agent">{a.rule ? `${a.rule} · ` : ""}{a.source}</div>
                </span>
                {a.submission_id ? <Link className="attck-tag" href={`/submissions/${a.submission_id}`}>open</Link> : null}
              </div>
            ))}
          </div>
        </Card>
        <Card title="Components & agents" link={<span className="card-link">{data?.agents.length ?? 0} tracked</span>}>
          <div className="agents-grid">
            {(data?.agents ?? []).map((a) => (
              <div className="agent-card" key={a.name}>
                <div className="agent-top"><span className="agent-name">{a.name}</span></div>
                <span className="agent-role">{a.role}</span>
                <span className={`agent-hb ${a.online ? "online" : "offline"}`}><span className="dot" />{a.online ? "Active" : "Down"} &middot; {a.detail}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <div className="nm-grid">
        <Card title="Pipeline throughput · events/min, last 60 min">
          <LineChart data={data?.events_per_minute ?? []} label="Pipeline events per minute" />
          <div className="card-head" style={{ margin: "16px 0 8px" }}><span className="card-title">Top IOC endpoints</span></div>
          {data && data.talkers.length === 0 ? <div className="empty">No URLs, IPs or hosts extracted from analysed samples yet.</div> : null}
          {(data?.talkers ?? []).map((t) => (
            <div className="talker-row" key={t.value}>
              <span className="talker-ip" style={{ width: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={t.value}>{t.value}</span>
              <span className="talker-bar"><span style={{ width: `${t.pct}%` }} /></span>
              <span className="talker-val">{t.samples}×</span>
            </div>
          ))}
        </Card>
        <Card title="MITRE ATT&CK coverage" link={<span className="card-link">by tactic · 24h</span>}>
          <p className="lede">Techniques cited by verdicts in the last 24 hours, grouped by tactic.</p>
          {data && data.attck.length === 0 ? <div className="empty">No techniques cited yet.</div> : null}
          <div className="attck-grid">
            {(data?.attck ?? []).map((a) => {
              const k = a.count / maxTactic;
              return (
                <div className="attck-cell" key={a.tactic}
                  style={{ background: `rgba(38,217,238,${(0.08 + k * 0.22).toFixed(2)})`, borderColor: `rgba(38,217,238,${(0.2 + k * 0.3).toFixed(2)})` }}>
                  <div className="t">{a.tactic}</div>
                  <div className="n">{a.count}</div>
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: 10 }}><Icon name="shield" size={12} /> <span className="provider-tag">Tactics come from the verdict&apos;s technique list.</span></div>
        </Card>
      </div>
    </>
  );
}
