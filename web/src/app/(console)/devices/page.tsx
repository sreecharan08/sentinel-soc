"use client";

import { useState } from "react";
import { Card, ErrorBox, Icon, PageHead, StatusPill } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useSession } from "@/lib/auth";
import { ago } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { DeviceRow } from "@/lib/types";

export default function DevicesPage() {
  const session = useSession();
  const { data, error } = useApi<{ devices: DeviceRow[] }>("/dash/devices", { live: true });
  const [open, setOpen] = useState<string | null>(null);
  const [code, setCode] = useState<{ code: string; expires_at: string } | null>(null);
  const [pairError, setPairError] = useState<string | null>(null);

  async function pair() {
    setPairError(null);
    try {
      setCode(await api<{ code: string; expires_at: string }>("/dash/pairing-code", { method: "POST", body: {} }));
    } catch (e) {
      setPairError(e instanceof ApiError ? e.message : "Could not create a pairing code.");
    }
  }

  return (
    <>
      <PageHead eyebrow="Paired watcher clients" title="Devices" />
      <Card
        title="Paired devices"
        link={
          <button className="btn accent" type="button" disabled={session?.user.role !== "analyst"} onClick={pair}>
            Pair device
          </button>
        }
      >
        <p className="lede">
          Every device runs the Sentinel watcher service, which reports new installs and lets analysts confirm uninstalls
          on-device &mdash; nothing is removed silently. Select a card for its details.
        </p>
        {code ? (
          <div className="path-banner" style={{ marginBottom: 14 }}>
            Pairing code <b className="mono" style={{ fontSize: 18, letterSpacing: ".12em" }}>{code.code}</b>
            <span className="provider-tag">expires {ago(code.expires_at).replace(" ago", "")} (UTC {code.expires_at})</span>
          </div>
        ) : null}
        {pairError ? <ErrorBox message={pairError} /> : null}
        {error ? <ErrorBox message={error.message} /> : null}
        {data && data.devices.length === 0 ? <div className="empty">No devices paired yet.</div> : null}
        <div className="device-grid">
          {(data?.devices ?? []).map((d) => (
            <div key={d.id} className={`device-card${open === d.id ? " open" : ""}`} onClick={() => setOpen(open === d.id ? null : d.id)}>
              <div className="device-card-head">
                <div className="device-icon"><Icon name="phone" size={16} /></div>
                <div>
                  <div className="device-name">{d.name}</div>
                  <div className="device-os">Android {d.android_version || "?"} &middot; app {d.app_version || "?"}</div>
                </div>
              </div>
              <div className="device-stats"><span>Scans <b>{d.scans}</b></span></div>
              {d.revoked ? <StatusPill kind="err">Revoked</StatusPill>
                : d.online ? <StatusPill kind="done">Online &middot; synced {ago(d.last_seen)}</StatusPill>
                : <StatusPill kind="">Offline &middot; {d.last_seen ? `last seen ${ago(d.last_seen)}` : "never seen"}</StatusPill>}
              <div className="device-spec">
                <span>Device ID&nbsp;<b>{d.id.slice(0, 8)}</b></span>
                <span>Paired&nbsp;<b>{ago(d.paired_at)}</b></span>
                <span>Protection&nbsp;<b>{d.protection_on ? "on" : "off"}</b></span>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </>
  );
}
