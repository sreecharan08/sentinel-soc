"use client";

import type { ReactNode } from "react";
import { LABEL_TITLE, pct } from "@/lib/format";
import type { Label, ProviderFields, ProviderPath, TraceStep } from "@/lib/types";

/* ---------- icons ---------- */
const ICONS: Record<string, string> = {
  alert: "M12 9v4m0 4h.01M10.3 3.9 2.5 17.1A1.8 1.8 0 0 0 4.1 20h15.8a1.8 1.8 0 0 0 1.6-2.9L13.7 3.9a1.8 1.8 0 0 0-3.4 0Z",
  check: "M20 6 9 17l-5-5",
  help: "M12 17h.01M9.5 9a2.5 2.5 0 1 1 3.8 2.1c-.9.6-1.3 1.1-1.3 2",
  phone: "M7 2h10a2.2 2.2 0 0 1 2.2 2.2v15.6A2.2 2.2 0 0 1 17 22H7a2.2 2.2 0 0 1-2.2-2.2V4.2A2.2 2.2 0 0 1 7 2Zm4 16h2",
  grid: "M4.5 3h4a1.5 1.5 0 0 1 1.5 1.5v6A1.5 1.5 0 0 1 8.5 12h-4A1.5 1.5 0 0 1 3 10.5v-6A1.5 1.5 0 0 1 4.5 3Zm11 0h4A1.5 1.5 0 0 1 21 4.5v2A1.5 1.5 0 0 1 19.5 8h-4A1.5 1.5 0 0 1 14 6.5v-2A1.5 1.5 0 0 1 15.5 3ZM15.5 12h4a1.5 1.5 0 0 1 1.5 1.5v6a1.5 1.5 0 0 1-1.5 1.5h-4a1.5 1.5 0 0 1-1.5-1.5v-6a1.5 1.5 0 0 1 1.5-1.5ZM4.5 16h4A1.5 1.5 0 0 1 10 17.5v2A1.5 1.5 0 0 1 8.5 21h-4A1.5 1.5 0 0 1 3 19.5v-2A1.5 1.5 0 0 1 4.5 16Z",
  list: "M5.5 4h13A2 2 0 0 1 20.5 6v12a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2ZM7 9h10M7 13h7M7 17h4",
  radar: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6ZM12 2v4M12 18v4M4.9 4.9l2.8 2.8M16.3 16.3l2.8 2.8M2 12h4M18 12h4M4.9 19.1l2.8-2.8M16.3 7.7l2.8-2.8",
  graph: "M5 4a2 2 0 1 0 0 4 2 2 0 0 0 0-4Zm14 0a2 2 0 1 0 0 4 2 2 0 0 0 0-4ZM12 15.6a2.4 2.4 0 1 0 0 4.8 2.4 2.4 0 0 0 0-4.8ZM6.6 7.4 10.4 16M17.4 7.4 13.6 16M7 6h10",
  layers: "M5 3h14a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm0 7h14a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-2a1 1 0 0 1 1-1Zm0 7h14a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-2a1 1 0 0 1 1-1Z",
  cog: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6Zm7.4 6a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9c.14.36.4.67.75.86.17.1.36.16.55.18H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z",
  gear: "M9 4h6l1 3h3v3l-3 1v4l3 1v3h-3l-1 3H9l-1-3H5v-3l3-1v-4L5 10V7h3l1-3Zm3 5a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z",
  pulse: "M4 12h4l2 7 4-14 2 7h4",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm0 4v5l3 2",
  plus: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM8 12h8M12 8v8",
  shield: "M12 2 4 5v6c0 5.2 3.4 9.4 8 11 4.6-1.6 8-5.8 8-11V5l-8-3Z",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14Zm10 17-4.3-4.3",
};

export function Icon({ name, size = 15, stroke = 2.3 }: { name: keyof typeof ICONS | string; size?: number; stroke?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={stroke}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={ICONS[name] ?? ""} />
    </svg>
  );
}

/* ---------- verdict chip ---------- */
export function VerdictChip({ label, confidence }: { label: Label | null; confidence?: number | null }) {
  const kind: Label = label ?? "unknown";
  const icon = kind === "benign" ? "check" : kind === "unknown" ? "help" : "alert";
  const c = pct(confidence);
  return (
    <span className={`chip ${kind}`}>
      <Icon name={icon} size={11} stroke={2.4} />
      {LABEL_TITLE[kind]}
      {c !== null && c > 0 ? <span className="chip-conf">&nbsp;{c}%</span> : null}
    </span>
  );
}

/* ---------- provider: which path produced the verdict ---------- */
const PATH_META: Record<ProviderPath, { cls: string; text: string; hint: string }> = {
  rule_engine: { cls: "neutral", text: "Rule engine", hint: "Deterministic if/then rules. Not AI." },
  agentic: { cls: "agentic", text: "Agentic LLM", hint: "Rule engine, then an LLM tool-calling loop on a borderline case." },
  active_list: { cls: "active-list", text: "Active list", hint: "Matched a previously convicted hash, package or IOC." },
  fallback: { cls: "fallback", text: "Fallback", hint: "The configured reasoner failed; the rule engine produced this verdict." },
};

/** Always shows the path chip and the honest provider string; never a single generic "AI verdict" label. */
export function ProviderBadge({ p, compact = false }: { p: ProviderFields & { fallback_from?: string | null }; compact?: boolean }) {
  if (!p.provider_path) return <span className="provider-tag">&mdash;</span>;
  const meta = PATH_META[p.provider_path];
  return (
    <span className="provider-cell">
      <span className={`chip ${meta.cls}`} title={meta.hint}>
        {meta.text}
        {p.provider_path === "agentic" ? <span className="chip-conf">&nbsp;{p.tool_calls} tool call{p.tool_calls === 1 ? "" : "s"}</span> : null}
      </span>
      {compact ? null : <span className="provider-tag">{p.provider_detail ?? p.provider}</span>}
    </span>
  );
}

/* ---------- small blocks ---------- */
export function Card({ title, link, children, className = "" }: { title?: ReactNode; link?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      {title || link ? (
        <div className="card-head">
          <span className="card-title">{title}</span>
          {link}
        </div>
      ) : null}
      {children}
    </section>
  );
}

export function StatCard({ icon, tone, num, label, delta, deltaTone }: {
  icon: string; tone: "accent" | "mal" | "sus" | "ben"; num: ReactNode; label: string; delta?: ReactNode; deltaTone?: "up" | "down";
}) {
  return (
    <div className="stat-card">
      <div className="stat-top">
        <div className={`stat-icon c-${tone}`}><Icon name={icon} /></div>
        {delta ? <span className={`stat-delta ${deltaTone ?? ""}`}>{delta}</span> : null}
      </div>
      <div className="stat-num">{num}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export function StatusPill({ kind, children }: { kind: "working" | "done" | "err" | "warn" | ""; children: ReactNode }) {
  return <span className={`status-pill ${kind}`}><span className="dot" />{children}</span>;
}

export function Switch({ on, onChange, disabled, label, title }: { on: boolean; onChange?: (next: boolean) => void; disabled?: boolean; label: string; title?: string }) {
  return (
    <button type="button" role="switch" aria-checked={on} aria-label={label} title={title} disabled={disabled}
      className={`switch${on ? " on" : ""}`} onClick={() => onChange?.(!on)} />
  );
}

export function ErrorBox({ message }: { message: string }) {
  return <div className="error-box" role="alert">{message}</div>;
}

export function PageHead({ eyebrow, title }: { eyebrow: string; title: string }) {
  return (
    <div className="page-head">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h2>{title}</h2>
      </div>
    </div>
  );
}

/* ---------- charts ---------- */
const DONUT_COLORS: Record<Label, string> = {
  benign: "var(--benign)", suspicious: "var(--suspicious)", malicious: "var(--malicious)", unknown: "var(--unknown)",
};

export function Donut({ data }: { data: Record<Label, number> }) {
  const order: Label[] = ["benign", "suspicious", "malicious", "unknown"];
  const total = order.reduce((s, k) => s + (data[k] ?? 0), 0);
  const r = 48;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="donut-wrap">
      <svg width="128" height="128" viewBox="0 0 128 128" role="img" aria-label="Verdicts in the last 24 hours">
        <circle cx="64" cy="64" r={r} fill="none" stroke="var(--surface-3)" strokeWidth="16" />
        <g transform="rotate(-90 64 64)">
          {total > 0 && order.map((k) => {
            const len = ((data[k] ?? 0) / total) * c;
            const el = (
              <circle key={k} cx="64" cy="64" r={r} fill="none" stroke={DONUT_COLORS[k]} strokeWidth="16"
                strokeDasharray={`${len.toFixed(2)} ${(c - len).toFixed(2)}`} strokeDashoffset={(-offset).toFixed(2)} />
            );
            offset += len;
            return el;
          })}
        </g>
        <text x="64" y="60" textAnchor="middle" fill="var(--text)" fontFamily="Sora, sans-serif" fontWeight="800" fontSize="22">{total}</text>
        <text x="64" y="76" textAnchor="middle" fill="var(--text-faint)" fontSize="9.5" letterSpacing="1">VERDICTS</text>
      </svg>
      <div className="donut-legend">
        {order.map((k) => (
          <div className="legend-row" key={k}>
            <span className="legend-dot" style={{ background: DONUT_COLORS[k] }} />
            <span className="legend-label">{LABEL_TITLE[k]}</span>
            <span className="legend-val mono">{data[k] ?? 0}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function LineChart({ data, label }: { data: number[]; label: string }) {
  const w = 520, h = 118, padL = 6, padR = 6, padT = 14, padB = 20;
  if (data.length < 2) return <div className="empty">Not enough data yet.</div>;
  const min = Math.min(...data), max = Math.max(...data), range = max - min || 1, n = data.length;
  const stepX = (w - padL - padR) / (n - 1);
  const xAt = (i: number) => padL + i * stepX;
  const yAt = (v: number) => padT + (1 - (v - min) / range) * (h - padT - padB);
  const line = "M" + data.map((v, i) => `${xAt(i).toFixed(1)},${yAt(v).toFixed(1)}`).join(" L");
  const area = `${line} L${xAt(n - 1).toFixed(1)},${h - padB} L${xAt(0).toFixed(1)},${h - padB} Z`;
  const gid = `grad_${label.replace(/\W/g, "")}`;
  return (
    <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" role="img" aria-label={label}>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.32" />
          <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0, 1, 2].map((g) => {
        const y = padT + (g / 2) * (h - padT - padB);
        return <line key={g} x1={padL} y1={y} x2={w - padR} y2={y} stroke="var(--border-soft)" strokeWidth="1" />;
      })}
      <path d={area} fill={`url(#${gid})`} stroke="none" />
      <path d={line} fill="none" stroke="var(--accent)" strokeWidth="2.2" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={xAt(n - 1)} cy={yAt(data[n - 1])} r="4" fill="var(--bg)" stroke="var(--accent)" strokeWidth="2.4" />
    </svg>
  );
}

/* ---------- agentic trace ---------- */
function json(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

export function AgenticTrace({ trace }: { trace: TraceStep[] }) {
  if (!trace.length) return <div className="empty">No agentic steps: this verdict was produced without the LLM loop.</div>;
  return (
    <div className="trace">
      {trace.map((s, i) => {
        const cls = s.type === "conclude" ? "conclude" : s.type === "tool_call" ? "" : "bad";
        return (
          <div className={`trace-step ${cls}`} key={i}>
            <div className="head">
              <span className="n">#{i + 1}</span>
              {s.type === "tool_call" ? <><span className="tool">{s.tool}</span><span className="chip neutral">tool call</span></> : null}
              {s.type === "conclude" ? <span className="chip agentic">conclusion</span> : null}
              {s.type === "malformed_json" ? <span className="chip fallback">malformed reply</span> : null}
              {s.type === "invalid_tool_call" ? <span className="chip fallback">unknown tool: {s.requested}</span> : null}
              {s.type === "turn_limit_reached" ? <span className="chip fallback">turn limit reached</span> : null}
            </div>
            {s.reason ? <div>{s.reason}</div> : null}
            {s.type === "conclude" ? (
              <div>
                {s.verdict} · {s.confidence !== undefined ? `${Math.round(Number(s.confidence) * 100)}%` : "n/a"}
                {s.rationale ? <div className="provider-tag">{s.rationale}</div> : null}
              </div>
            ) : null}
            {s.detail ? <div className="provider-tag">{s.detail}</div> : null}
            {s.type === "tool_call" ? <pre>{json({ args: s.args, result: s.result })}</pre> : null}
          </div>
        );
      })}
    </div>
  );
}
