"use client";

import { useEffect, useState, type ReactNode } from "react";
import { Card, ErrorBox, PageHead, Switch } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/auth";
import { useApi } from "@/lib/hooks";
import type { SettingsData } from "@/lib/types";

function Field({ label, hint, children }: { label: string; hint: string; children: ReactNode }) {
  return (
    <div className="field-row">
      <div>
        <div className="field-label">{label}</div>
        <div className="field-hint">{hint}</div>
      </div>
      <div className="field-control">{children}</div>
    </div>
  );
}

export default function SettingsPage() {
  const session = useSession();
  const analyst = session?.user.role === "analyst";
  const { data, error, reload } = useApi<SettingsData>("/dash/settings");
  const [saveError, setSaveError] = useState<string | null>(null);
  const [protectedText, setProtectedText] = useState("");
  const [conf, setConf] = useState(0.85);
  const s = data?.settings;

  useEffect(() => {
    if (s) {
      setProtectedText(s.protected_packages.join("\n"));
      setConf(s.auto_remediation_min_confidence);
    }
  }, [s]);

  async function save(key: string, value: unknown) {
    setSaveError(null);
    try {
      await api("/dash/settings", { method: "POST", body: { key, value } });
      reload();
    } catch (e) {
      setSaveError(e instanceof ApiError ? e.message : "Could not save the setting.");
    }
  }

  return (
    <>
      <PageHead eyebrow="Pipeline configuration" title="Settings" />
      {error ? <ErrorBox message={error.message} /> : null}
      {saveError ? <ErrorBox message={saveError} /> : null}
      {!analyst ? <div className="provider-tag">Your role is viewer; settings are read-only.</div> : null}
      {s && data ? (
        <div className="settings-grid">
          <Card title="Remediation guardrails">
            <Field label="Auto-remediation" hint="Propose uninstalls without analyst approval above the confidence threshold">
              <Switch on={s.auto_remediation_enabled} label="Auto-remediation" disabled={!analyst} onChange={(v) => save("auto_remediation_enabled", v)} />
            </Field>
            <Field label="Minimum confidence" hint="0.50 to 0.99">
              <span className="form-row">
                <input type="range" min={0.5} max={0.99} step={0.01} value={conf} disabled={!analyst}
                  onChange={(e) => setConf(Number(e.target.value))} onMouseUp={() => save("auto_remediation_min_confidence", conf)}
                  onKeyUp={() => save("auto_remediation_min_confidence", conf)} aria-label="Minimum confidence" />
                <span className="range-val">{conf.toFixed(2)}</span>
              </span>
            </Field>
            <Field label="Requests per device per hour" hint="1 to 100">
              <input className="input" type="number" min={1} max={100} defaultValue={s.remediation_rate_limit_per_device_hour}
                key={s.remediation_rate_limit_per_device_hour} disabled={!analyst} style={{ width: 80 }}
                onBlur={(e) => { const n = Number(e.target.value); if (n !== s.remediation_rate_limit_per_device_hour) void save("remediation_rate_limit_per_device_hour", n); }} />
            </Field>
            <div className="field-row" style={{ flexDirection: "column", alignItems: "stretch" }}>
              <div>
                <div className="field-label">Protected packages</div>
                <div className="field-hint">One per line. These can never be targeted for uninstall.</div>
              </div>
              <textarea className="input" value={protectedText} onChange={(e) => setProtectedText(e.target.value)} disabled={!analyst} />
              <div>
                <button className="btn accent" type="button" disabled={!analyst}
                  onClick={() => save("protected_packages", protectedText.split("\n").map((x) => x.trim()).filter(Boolean))}>
                  Save protected packages
                </button>
              </div>
            </div>
          </Card>

          <Card title="Analysis">
            <Field label="Reasoning backend" hint="rules = deterministic rule engine only. hybrid = rule engine + active lists + agentic LLM on borderline cases.">
              <select className="input" value={s.reasoner_backend} disabled={!analyst} aria-label="Reasoning backend"
                onChange={(e) => save("reasoner_backend", e.target.value)}>
                {data.env.reasoner_options.map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
            </Field>
            <Field label="Dynamic analysis" hint={data.env.dynamic_available ? "Emulator behaviour traces" : "Not installed on this server"}>
              <Switch on={s.dynamic_enabled} label="Dynamic analysis" disabled={!analyst || !data.env.dynamic_available}
                onChange={(v) => save("dynamic_enabled", v)} />
            </Field>
            <Field label="Analysis version" hint="Evidence schema generation used by the static analyzers">
              <span className="mono">{data.env.analysis_version}</span>
            </Field>
            <Field label="Reputation lists" hint="Bad hashes · good hashes · bad signers">
              <span className="mono">
                {data.reputation_counts.bad_hashes} · {data.reputation_counts.good_hashes} · {data.reputation_counts.bad_signers}
              </span>
            </Field>
          </Card>
        </div>
      ) : null}
    </>
  );
}
