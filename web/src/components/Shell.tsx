"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { logout } from "@/lib/api";
import { useSession } from "@/lib/auth";
import { useApi } from "@/lib/hooks";
import { initials } from "@/lib/format";
import { RealtimeProvider, useRealtime } from "@/lib/realtime";
import type { Stats } from "@/lib/types";
import { Icon } from "./ui";

const NAV: { group: string; items: { href: string; label: string; icon: string; count?: (s: Stats) => number }[] }[] = [
  {
    group: "Monitor",
    items: [
      { href: "/", label: "Overview", icon: "grid" },
      { href: "/submissions", label: "Submissions", icon: "list", count: (s) => s.submissions_total },
      { href: "/devices", label: "Devices", icon: "phone", count: (s) => s.devices_total },
      { href: "/network", label: "Network Monitor", icon: "radar" },
      { href: "/graph", label: "Threat Graph", icon: "graph" },
      { href: "/pipeline", label: "Pipeline", icon: "layers" },
    ],
  },
  {
    group: "Act",
    items: [
      { href: "/remediation", label: "Remediation", icon: "alert", count: (s) => s.pending_remediations },
      { href: "/rules", label: "Rules", icon: "gear" },
    ],
  },
  { group: "Configure", items: [{ href: "/settings", label: "Settings", icon: "cog" }] },
];

const TITLES: Record<string, string> = {
  "/": "Overview", "/submissions": "Submissions", "/devices": "Devices", "/network": "Network Monitor",
  "/graph": "Threat Graph", "/pipeline": "Pipeline", "/remediation": "Remediation", "/rules": "Detection Rules",
  "/settings": "Settings",
};

function Topbar({ title }: { title: string }) {
  const session = useSession();
  const { state, lastEventAt } = useRealtime();
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const name = session?.user.username ?? "";
  const since = lastEventAt ? Math.max(0, Math.round((now - lastEventAt) / 1000)) : null;
  const badge = state === "live" ? { cls: "", text: "Live" } : state === "connecting" ? { cls: "wait", text: "Connecting" } : { cls: "off", text: "Offline" };
  return (
    <header className="topbar">
      <div>
        <h1>{title}</h1>
        <div className="sub">
          {new Date(now).toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" })} &middot;{" "}
          {since === null ? "waiting for events" : <>last event <span className="mono">{since}s</span> ago</>}
        </div>
      </div>
      <div style={{ flex: 1 }} />
      <div className={`conn-badge ${badge.cls}`}>
        <span className={`conn-dot ${state === "live" ? "live" : "static"}`} />
        {badge.text}
      </div>
      <div className="avatar-sm" title={name}>{initials(name || "?")}</div>
    </header>
  );
}

function ConsoleFrame({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const session = useSession();
  const stats = useApi<Stats>("/dash/stats", { live: true });
  const active = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));
  const title = TITLES[pathname] ?? (pathname.startsWith("/submissions/") ? "Submission" : "Sentinel SOC");
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Icon name="shield" size={16} stroke={2.4} /></div>
          <div className="brand-text">Sentinel SOC<small>Mobile threat response</small></div>
        </div>
        {NAV.map((g) => (
          <div key={g.group} style={{ display: "contents" }}>
            <div className="nav-label">{g.group}</div>
            {g.items.map((it) => (
              <Link key={it.href} href={it.href} className={`nav-item${active(it.href) ? " active" : ""}`}>
                <Icon name={it.icon} size={17} stroke={2} />
                <span className="label">{it.label}</span>
                {it.count && stats.data ? <span className="count">{it.count(stats.data)}</span> : null}
              </Link>
            ))}
          </div>
        ))}
        <div className="sidebar-foot">
          <div className="user-chip">
            <div className="user-avatar">{initials(session?.user.username ?? "?")}</div>
            <div className="user-meta">
              <div className="name">{session?.user.username}</div>
              <div className="role" style={{ textTransform: "capitalize" }}>{session?.user.role}</div>
            </div>
          </div>
          <button className="nav-item" type="button" onClick={() => logout()}>
            <span className="label">Sign out</span>
          </button>
        </div>
      </aside>
      <div className="main">
        <Topbar title={title} />
        <main className="content">{children}</main>
      </div>
    </div>
  );
}

/** Auth guard + realtime connection for every console route. */
export function Shell({ children }: { children: ReactNode }) {
  const session = useSession();
  const router = useRouter();
  useEffect(() => {
    if (session === null) router.replace("/login");
  }, [session, router]);
  if (!session) return null;
  return (
    <RealtimeProvider>
      <ConsoleFrame>{children}</ConsoleFrame>
    </RealtimeProvider>
  );
}
