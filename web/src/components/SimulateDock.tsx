"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/auth";

interface SimResult {
  device_serial: string;
  tunnel: Record<string, string>;
  delivered: number;
  results: { file: string; package: string; label: string; ok: boolean; detail: string }[];
}

/**
 * Hidden demo control (analyst only). Nearly invisible until hovered or focused; Alt+Shift+S also opens it.
 * It asks the backend to push two harmless test APKs to the USB-connected phone, which works with no internet.
 */
export function SimulateDock() {
  const session = useSession();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SimResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (session?.user.role !== "analyst") return null;

  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api<SimResult>("/dash/demo/simulate", { method: "POST", body: {} }));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Simulation failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="sim-dock"
      onKeyDown={(e) => { if (e.altKey && e.shiftKey && e.key.toLowerCase() === "s") setOpen((o) => !o); }}>
      {open ? (
        <div className="sim-panel" role="dialog" aria-label="Simulate">
          <div className="card-title">Simulate</div>
          <p className="provider-tag" style={{ margin: "6px 0 10px" }}>
            Sends 2 test apps to the phone over the USB cable (no internet needed). The phone detects them, tells you,
            and scans them through the local tunnel.
          </p>
          <div className="form-row">
            <button className="btn accent" type="button" onClick={() => void run()} disabled={busy}>
              {busy ? "Sending…" : "Send to phone"}
            </button>
            <button className="btn" type="button" onClick={() => setOpen(false)}>Close</button>
          </div>
          {error ? <div className="error-box" role="status" style={{ marginTop: 8 }}>{error}</div> : null}
          {result ? (
            <div style={{ marginTop: 10 }}>
              {result.results.map((r) => (
                <div className="tech" key={r.package}>
                  <span className={`chip ${r.ok ? "neutral" : ""}`}>{r.ok ? "delivered" : "failed"}</span>
                  <span>{r.label}</span>
                  <span className="provider-tag mono">{r.ok ? r.package : r.detail}</span>
                </div>
              ))}
              <div className="provider-tag" style={{ marginTop: 6 }}>
                Device {result.device_serial} · tunnel {Object.values(result.tunnel).every((v) => v === "ok") ? "ready" : "check adb"}
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
      <button type="button" className="sim-trigger" aria-label="Simulate" onClick={() => setOpen((o) => !o)}>
        Simulate
      </button>
    </div>
  );
}
