"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Card, ErrorBox, Icon, PageHead, ProviderBadge, StatusPill, VerdictChip } from "@/components/ui";
import { ago } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { Page, SubmissionRow } from "@/lib/types";

const FILTERS: { key: string; title: string; query: string }[] = [
  { key: "all", title: "All", query: "" },
  { key: "malicious", title: "Malicious", query: "&label=malicious" },
  { key: "suspicious", title: "Suspicious", query: "&label=suspicious" },
  { key: "benign", title: "Benign", query: "&label=benign" },
  { key: "progress", title: "In progress", query: "&status=in_progress" },
];

function StatusCell({ r }: { r: SubmissionRow }) {
  if (r.status === "error") return <StatusPill kind="err">Error</StatusPill>;
  if (r.in_progress) return <StatusPill kind="working">{r.status_label}</StatusPill>;
  return <StatusPill kind="done">{r.status_label}</StatusPill>;
}

export default function SubmissionsPage() {
  const router = useRouter();
  const [filter, setFilter] = useState("all");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const f = FILTERS.find((x) => x.key === filter) ?? FILTERS[0];
  const path = `/dash/submissions?page=${page}&page_size=25${f.query}${q.trim() ? `&q=${encodeURIComponent(q.trim())}` : ""}`;
  const { data, error, loading } = useApi<Page<SubmissionRow>>(path, { live: true });
  const pages = data ? Math.max(1, Math.ceil(data.count / 25)) : 1;

  return (
    <>
      <PageHead eyebrow="Static analysis + reasoning" title="Submissions" />
      <Card title="All submissions" link={<span className="card-link">{data?.count ?? 0} total</span>}>
        <div className="toolbar">
          {FILTERS.map((x) => (
            <button key={x.key} type="button" className={`filter-chip${filter === x.key ? " active" : ""}`}
              onClick={() => { setFilter(x.key); setPage(1); }}>{x.title}</button>
          ))}
          <div className="search" style={{ marginLeft: "auto" }}>
            <Icon name="search" size={13} stroke={2.2} />
            <input type="text" placeholder="Filter by package…" aria-label="Filter submissions" value={q}
              onChange={(e) => { setQ(e.target.value); setPage(1); }} />
          </div>
        </div>
        {error ? <ErrorBox message={error.message} /> : null}
        <div className="table-scroll">
          <table>
            <thead>
              <tr><th>Application</th><th>Verdict</th><th>Status</th><th>Device</th><th>Provider</th><th>When</th></tr>
            </thead>
            <tbody>
              {(data?.results ?? []).map((r) => (
                <tr key={r.id} onClick={() => router.push(`/submissions/${r.id}`)}>
                  <td className="row-app">
                    <div className="name"><Link href={`/submissions/${r.id}`} onClick={(e) => e.stopPropagation()}>{r.app_label || r.package_name}</Link></div>
                    <div className="pkg">{r.package_name}</div>
                  </td>
                  <td>{r.in_progress ? <StatusPill kind="working">Analyzing</StatusPill> : <VerdictChip label={r.label} confidence={r.confidence} />}</td>
                  <td><StatusCell r={r} /></td>
                  <td><span className="device-cell"><Icon name="phone" size={13} />{r.device.name}</span></td>
                  <td><ProviderBadge p={r} /></td>
                  <td className="when-cell">{ago(r.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!loading && (data?.results.length ?? 0) === 0 ? <div className="empty">No submissions match.</div> : null}
        </div>
        <div className="pager">
          <button className="btn" type="button" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
          <span>Page {page} of {pages}</span>
          <button className="btn" type="button" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>Next</button>
        </div>
      </Card>
    </>
  );
}
