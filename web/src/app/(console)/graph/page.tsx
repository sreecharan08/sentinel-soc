"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { ErrorBox } from "@/components/ui";
import { Chamber } from "@/components/webgl/Chamber";
import type { SceneController } from "@/components/webgl/core";
import { buildThreatGraph, type GraphNodeInfo } from "@/components/webgl/threatGraph";
import { useApi } from "@/lib/hooks";
import type { GraphData } from "@/lib/types";

const KIND: Record<GraphNodeInfo["type"], string> = {
  core: "Correlation core", device: "Device", app: "Application", signal: "Signal", ioc: "IOC endpoint",
};
const VERDICT_COLOR = { malicious: "#ff4d6a", suspicious: "#ffb020", benign: "#39ff9a", unknown: "#9fb4c9" } as const;
const PARENT_ROW: Partial<Record<GraphNodeInfo["type"], string>> = { signal: "Application", app: "Device", device: "Core" };

export default function GraphPage() {
  const { data, error } = useApi<GraphData>("/dash/graph", { live: true });
  const [sel, setSel] = useState<GraphNodeInfo | null>(null);
  const ctl = useRef<SceneController | null>(null);
  // rebuild the scene only when the graph content really changes, not on every refetch
  const key = useMemo(
    () => (data ? JSON.stringify([data.devices, data.apps.map((a) => [a.id, a.label]), data.signals, data.iocs]) : ""),
    [data],
  );
  useEffect(() => setSel(null), [key]); // a rebuilt scene has no isolation, so drop the stale panel
  const nodes = data ? 1 + data.devices.length + data.apps.length + data.signals.length + data.iocs.length : 0;
  const links = data ? data.devices.length + data.apps.length + data.signals.length
    + data.iocs.reduce((n, i) => n + i.app_ids.length, 0) : 0;
  const close = () => { ctl.current?.clearSelection?.(); setSel(null); };

  return (
    <>
      <div className="ghead">
        <h2>Threat Graph</h2>
        <div className="gsub">Sentinel SOC &middot; correlation view &middot; devices &rarr; apps &rarr; signals</div>
      </div>
      {error ? <ErrorBox message={error.message} /> : null}
      {data ? (
        <Chamber
          deps={[key]}
          unavailable="This browser could not start WebGL, so the live 3D chamber is unavailable. Try a recent desktop browser."
          build={(canvas, chamber) => (ctl.current = buildThreatGraph(canvas, chamber, data, setSel))}
        >
          <div className="ghud ghud-top">
            <span className="gbadge"><span className="dot" />Correlating</span>
            <div className="gstats">
              <span className="gstat"><b>{nodes}</b>nodes</span>
              <span className="gstat"><b>{links}</b>links</span>
              <span className="gstat alert"><b>{data.shared_iocs}</b>shared IOCs</span>
            </div>
          </div>
          <div className="glegend ghud">
            {[["#45e8ff", "Core / device"], ["#ff4d6a", "Malicious"], ["#ffb020", "Suspicious"], ["#39ff9a", "Benign"], ["#ff4fd8", "Signal / IOC"]].map(([c, l]) => (
              <div className="glegend-row" key={l}><span className="glegend-dot" style={{ background: c, color: c }} /><span className="lbl">{l}</span></div>
            ))}
          </div>
          <div className="ghint ghud">Drag to rotate &middot; tap a node to isolate</div>
          <div className={`gpanel ghud interactive${sel ? " show" : ""}`}>
            <span className="close" onClick={close} role="button" aria-label="Close">&times;</span>
            <div className="kind">{sel ? KIND[sel.type] : "—"}</div>
            <div className="name">{sel?.label ?? "—"}</div>
            {sel?.verdict ? (
              <div className="row"><span>Verdict</span>
                <span className="gvchip" style={{ color: VERDICT_COLOR[sel.verdict], background: `${VERDICT_COLOR[sel.verdict]}22` }}>{sel.verdict}</span>
              </div>
            ) : null}
            {sel?.conf ? <div className="row"><span>Confidence</span><b>{Math.round(sel.conf * 100)}%</b></div> : null}
            {sel?.sev ? <div className="row"><span>Severity</span><b>{sel.sev}</b></div> : null}
            {sel?.parentLabel ? <div className="row"><span>{PARENT_ROW[sel.type] ?? "Parent"}</span><b>{sel.parentLabel}</b></div> : null}
            {(sel?.extra ?? []).map((r) => <div className="row" key={r.k}><span>{r.k}</span><b>{r.v}</b></div>)}
          </div>
        </Chamber>
      ) : null}
      {data && data.apps.length === 0 ? <div className="empty">No analysed apps yet. The graph fills in as submissions complete.</div> : null}
      <div className="styles-note">
        <span>Shells: x-ray / fresnel</span><span>Ambience: holographic point cloud</span>
        <span>Edges: neon circuitry pulses</span><span>Isolate-on-select: ego-network highlight</span>
      </div>
    </>
  );
}
