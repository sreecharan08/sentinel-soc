/* soc.js - Sentinel SOC dashboard behaviour (Stage 5). No framework. DOM is built with createElement and
   textContent only: package names and labels come from phones and are untrusted. */
(function () {
  "use strict";

  // ---------- Util ----------
  const U = {
    el(tag, attrs, children) {
      const node = document.createElement(tag);
      for (const [k, v] of Object.entries(attrs || {})) {
        if (v === undefined || v === null || v === false) continue;
        if (k === "class") node.className = v;
        else if (k === "text") node.textContent = v;
        else if (k === "on") for (const [ev, fn] of Object.entries(v)) node.addEventListener(ev, fn);
        else if (k === "value") node.value = v;
        else if (k === "checked") node.checked = !!v;
        else if (k === "disabled") node.disabled = !!v;
        else node.setAttribute(k, v === true ? "" : String(v));
      }
      for (const c of children || []) {
        if (c === null || c === undefined || c === false) continue;
        node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
      }
      return node;
    },
    clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); return node; },
    rel(iso) {
      if (!iso) return "-";
      const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
      if (s < 5) return "just now";
      if (s < 60) return s + " s ago";
      if (s < 3600) return Math.round(s / 60) + " min ago";
      if (s < 86400) return Math.round(s / 3600) + " h ago";
      return Math.round(s / 86400) + " d ago";
    },
    time(iso) { return iso ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "-"; },
    dt(iso) { return iso ? new Date(iso).toLocaleString() : "-"; },
    pct(x) { return x === null || x === undefined ? "-" : Math.round(x * 100) + "%"; },
    defang(s) { return String(s).replace(/^https?:\/\//i, (m) => m.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://").replace(/\./g, "[.]"); },
    cookie(name) {
      const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
      return m ? decodeURIComponent(m[1]) : "";
    },
    qs(params) {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(params || {})) if (v !== "" && v !== null && v !== undefined) p.set(k, v);
      const s = p.toString();
      return s ? "?" + s : "";
    },
    debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; },
  };

  // ---------- Api ----------
  const ERR = {
    invalid_token: "This device is no longer paired. Pair it again.",
    pairing_failed: "That code is wrong or expired. Generate a new one.",
    validation_error: "Something in the request was invalid.",
    apk_too_large: "The app file is larger than the allowed limit.",
    hash_mismatch: "The uploaded file did not match its fingerprint. Try again.",
    not_an_apk: "That file isn't an Android app package.",
    rate_limited: "Too many requests. Wait a moment.",
    state_conflict: "That can't be done in the current state.",
    forbidden: "You don't have permission to do that.",
    internal_error: "The server had a problem. Try again.",
    not_found: "That item no longer exists.",
  };
  const Api = {
    async req(method, path, body) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 10000);
      const headers = { Accept: "application/json", "X-CSRFToken": U.cookie("csrftoken") };
      if (body !== undefined) headers["Content-Type"] = "application/json";
      try {
        const resp = await fetch("/api/v1/dash" + path, {
          method, headers, credentials: "same-origin", signal: ctrl.signal,
          body: body !== undefined ? JSON.stringify(body) : undefined,
        });
        const text = await resp.text();
        const data = text ? JSON.parse(text) : {};
        if (!resp.ok) {
          const e = (data && data.error) || { code: "internal_error", message: "" };
          const err = new Error(ERR[e.code] || e.message || "Something went wrong. Try again.");
          err.code = e.code; err.details = e.details || {};
          throw err;
        }
        return data;
      } catch (e) {
        if (e.name === "AbortError") throw new Error("The server did not answer in time.");
        throw e;
      } finally { clearTimeout(timer); }
    },
    get(p) { return this.req("GET", p); },
    post(p, b) { return this.req("POST", p, b || {}); },
    put(p, b) { return this.req("PUT", p, b || {}); },
  };

  // ---------- Components ----------
  const LABEL_TEXT = { malicious: "Malicious", suspicious: "Suspicious", benign: "Safe", unknown: "Unknown" };
  const LABEL_ICON = { malicious: "⚠", suspicious: "▲", benign: "✓", unknown: "?" };
  const C = {
    verdictChip(label, confidence, overridden) {
      if (!label) return U.el("span", { class: "chip chip--unknown", text: "No verdict" });
      const kids = [U.el("span", { "aria-hidden": "true", text: LABEL_ICON[label] || "?" }),
        U.el("span", { text: LABEL_TEXT[label] || label })];
      if (confidence !== null && confidence !== undefined) kids.push(U.el("span", { text: " " + U.pct(confidence) }));
      const wrap = U.el("span", { class: "row", style: "gap:6px" }, [
        U.el("span", { class: "chip chip--" + label, "aria-label": "Verdict: " + (LABEL_TEXT[label] || label) }, kids)]);
      if (overridden) wrap.appendChild(U.el("span", { class: "chip chip--override", text: "Analyst override" }));
      return wrap;
    },
    statusChip(status, label) {
      const cls = status === "error" ? "chip--error" : (["verdict_ready"].includes(status) ? "chip--status" :
        "chip--progress");
      const pulse = !["verdict_ready", "error"].includes(status);
      return U.el("span", { class: "chip " + cls }, [
        pulse ? U.el("span", { class: "dot dot--pulse", "aria-hidden": "true" }) : null, label || status]);
    },
    toast(text, opts) {
      const o = opts || {};
      const region = document.getElementById("toast-region");
      const kids = [U.el("div", { text })];
      if (o.href) kids.push(U.el("a", { href: o.href, text: o.actionText || "Open" }));
      const close = U.el("button", { class: "btn btn--ghost", type: "button", text: "Dismiss" });
      const node = U.el("div", { class: "toast" + (o.kind ? " toast--" + o.kind : ""), role: "status" },
        [...kids, close]);
      close.addEventListener("click", () => node.remove());
      region.appendChild(node);
      if (!o.persistent) setTimeout(() => node.remove(), 5000);
      return node;
    },
    modal(opts) {
      const backdrop = U.el("div", { class: "modal-backdrop" });
      const prev = document.activeElement;
      const close = () => { backdrop.remove(); if (prev && prev.focus) prev.focus(); };
      const actions = U.el("div", { class: "row", style: "justify-content:flex-end" }, []);
      for (const a of opts.actions || []) {
        actions.appendChild(U.el("button", {
          class: "btn " + (a.kind ? "btn--" + a.kind : ""), type: "button", text: a.label,
          on: { click: async () => { try { await a.run(close); } catch (e) { alert(e.message); } } },
        }));
      }
      const dialog = U.el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-labelledby": "m-title" }, [
        U.el("h2", { id: "m-title", text: opts.title }),
        ...(opts.body || []), actions]);
      backdrop.appendChild(dialog);
      backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close(); });
      document.addEventListener("keydown", function esc(e) {
        if (e.key === "Escape" && backdrop.isConnected) { close(); document.removeEventListener("keydown", esc); }
      });
      document.body.appendChild(backdrop);
      const first = dialog.querySelector("input, textarea, select") || actions.querySelector("button:not(.btn--danger)");
      if (first) first.focus();
      return { close };
    },
    banner(text, kind) { return U.el("div", { class: "banner banner--" + (kind || "info"), role: "status" }, [U.el("span", { text })]); },
    empty(title, text, action) {
      return U.el("div", { class: "empty" }, [U.el("div", { class: "empty__title", text: title }),
        U.el("div", { text }), action || null]);
    },
    rail(status, errorStatus) {
      const steps = [["received", "Received"], ["queued", "Queued"], ["static_analysis", "Inspecting"],
        ["reasoning", "Verdict"], ["verdict_ready", "Done"]];
      const order = steps.map((s) => s[0]);
      const idx = order.indexOf(status);
      return U.el("div", { class: "rail", "aria-label": "Progress" }, steps.map(([key, text], i) => {
        let cls = "rail__step";
        if (status === "error" && i === Math.max(idx, 0)) cls += " error";
        else if (idx > i || status === "verdict_ready") cls += " done";
        else if (idx === i) cls += " current";
        return U.el("span", { class: cls }, [U.el("span", { class: "dot", "aria-hidden": "true" }), text]);
      }));
    },
    donut(counts) {
      const total = Object.values(counts).reduce((a, b) => a + b, 0);
      const colors = { malicious: "#F0524F", suspicious: "#F5A524", benign: "#2FBF71", unknown: "#8B98A8" };
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("viewBox", "0 0 42 42"); svg.setAttribute("width", "160"); svg.setAttribute("height", "160");
      svg.setAttribute("role", "img");
      const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
      title.textContent = "Verdicts in the last 24 hours: " + Object.entries(counts).map(([k, v]) => k + " " + v).join(", ");
      svg.appendChild(title);
      let offset = 25;
      const r = 15.915;
      if (total === 0) {
        svg.appendChild(circle(21, 21, r, "#263040", 0, 0));
      } else {
        for (const [k, v] of Object.entries(counts)) {
          if (!v) continue;
          const frac = (v / total) * 100;
          svg.appendChild(circle(21, 21, r, colors[k] || "#8B98A8", frac, offset));
          offset -= frac;
        }
      }
      const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
      text.setAttribute("x", "21"); text.setAttribute("y", "23"); text.setAttribute("text-anchor", "middle");
      text.setAttribute("font-size", "7"); text.setAttribute("fill", "#E6EDF3"); text.textContent = String(total);
      svg.appendChild(text);
      return svg;
      function circle(cx, cy, rr, stroke, dash, off) {
        const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        c.setAttribute("cx", cx); c.setAttribute("cy", cy); c.setAttribute("r", rr);
        c.setAttribute("fill", "none"); c.setAttribute("stroke", stroke); c.setAttribute("stroke-width", "4");
        c.setAttribute("stroke-dasharray", dash + " " + (100 - dash)); c.setAttribute("stroke-dashoffset", off);
        c.setAttribute("transform", "rotate(-90 21 21)");
        return c;
      }
    },
    sparkline(series) {
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("viewBox", "0 0 240 48"); svg.setAttribute("width", "100%"); svg.setAttribute("height", "64");
      svg.setAttribute("role", "img");
      const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
      title.textContent = "Time to verdict (last " + series.length + ")";
      svg.appendChild(title);
      if (series.length < 2) return svg;
      const max = Math.max(...series.map((p) => p.seconds), 1);
      const pts = series.map((p, i) => [(i / (series.length - 1)) * 236 + 2, 44 - (p.seconds / max) * 40]);
      const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
      line.setAttribute("fill", "none"); line.setAttribute("stroke", "#22D3EE"); line.setAttribute("stroke-width", "2");
      line.setAttribute("points", pts.map((p) => p.join(",")).join(" "));
      svg.appendChild(line);
      const last = pts[pts.length - 1];
      const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      dot.setAttribute("cx", last[0]); dot.setAttribute("cy", last[1]); dot.setAttribute("r", "3"); dot.setAttribute("fill", "#22D3EE");
      svg.appendChild(dot);
      return svg;
    },
    table(headers, rows, opts) {
      const thead = U.el("thead", {}, [U.el("tr", {}, headers.map((h) => U.el("th", { scope: "col", text: h })))]);
      const tbody = U.el("tbody", {}, rows);
      return U.el("div", { class: "table-wrap" }, [U.el("table", { "aria-label": (opts && opts.caption) || "" }, [thead, tbody])]);
    },
  };

  // Table helper is used by several pages; expose it on the shared utilities as well.
  U.table = C.table;

  // ---------- Live connection ----------
  const Live = {
    handlers: [],
    client: null,
    lastEventId: 0,
    start() {
      if (this.client || typeof Ws === "undefined") return;
      const badge = document.getElementById("conn-badge");
      const label = { live: ["Live", "conn--live"], reconnecting: ["Reconnecting...", "conn--reconnecting"],
        offline: ["Offline - polling", "conn--offline"] };
      const apply = (state) => {
        if (!badge) return;
        const [text, cls] = label[state] || label.reconnecting;
        badge.textContent = text;
        badge.className = "conn " + cls;
        if (state === "offline") Poll.start(); else Poll.stop();
      };
      this.client = Ws.connect("/ws/dashboard/", {
        onState: apply,
        onEvent: (ev) => {
          this.lastEventId = Math.max(this.lastEventId, ev.event_id);
          for (const h of this.handlers) { try { h(ev); } catch (e) { console.error(e); } }
        },
        onResync: () => { for (const h of this.handlers) { try { h({ type: "resync" }); } catch (e) { console.error(e); } } },
        onAuthFailure: () => { window.location.href = "/login/?next=" + encodeURIComponent(location.pathname); },
      });
    },
    on(fn) { this.handlers.push(fn); },
  };
  const Poll = {
    timer: null,
    start() { if (!this.timer) this.timer = setInterval(() => { for (const h of Live.handlers) h({ type: "poll" }); }, 5000); },
    stop() { clearInterval(this.timer); this.timer = null; },
  };

  // ---------- Pages ----------
  const data = () => {
    const node = document.getElementById("page-data");
    try { return node ? JSON.parse(node.textContent) : {}; } catch (e) { return {}; }
  };
  const isAnalyst = () => document.getElementById("app") && document.getElementById("app").dataset.role === "analyst";
  const viewerNote = () => U.el("div", { class: "banner banner--info" }, [U.el("span", { text: "Read-only access. Ask an analyst to make changes." })]);
  const app = () => U.clear(document.getElementById("app"));
  const stat = (label, value, href) => {
    const body = [U.el("div", { class: "stat", text: String(value) }), U.el("div", { class: "stat-label", text: label })];
    return href ? U.el("a", { class: "card stat-card", href }, body) : U.el("div", { class: "card" }, body);
  };

  const Pages = {};

  Pages.overview = {
    init(d) {
      const root = app();
      const counters = U.el("div", { class: "grid" });
      const feed = U.el("ul", { class: "feed", "aria-live": "polite", "aria-atomic": "false", "aria-label": "Live pipeline feed" });
      const recent = U.el("div", { class: "stack" });
      const donutBox = U.el("div", { class: "card" });
      const sparkBox = U.el("div", { class: "card" });
      root.append(
        counters,
        U.el("div", { class: "grid" }, [
          U.el("div", { class: "span-6" }, [donutBox]),
          U.el("div", { class: "span-6" }, [sparkBox]),
        ]),
        U.el("div", { class: "grid" }, [
          U.el("div", { class: "span-8 card" }, [U.el("div", { class: "card__title", text: "Live pipeline feed" }), feed]),
          U.el("div", { class: "span-4 card" }, [U.el("div", { class: "card__title", text: "Recent submissions" }), recent]),
        ]));
      counters.className = "grid";

      const render = (s) => {
        U.clear(counters);
        counters.append(
          stat("Devices online", s.devices_online, "/devices/"),
          stat("Scanned today", s.submissions_today, "/submissions/"),
          stat("Malicious 24h", s.by_label.malicious || 0, "/submissions/?label=malicious"),
          stat("In progress", s.in_progress, "/submissions/?status=in_progress"),
          stat("Pending remediation", s.pending_remediations, "/remediation/"));
        U.clear(donutBox).append(U.el("div", { class: "card__title", text: "Verdicts, last 24 h" }),
          U.el("div", { class: "row" }, [C.donut(s.by_label),
            U.el("div", { class: "donut-legend" }, Object.entries(s.by_label).map(([k, v]) => U.el("div", {}, [
              U.el("span", { class: "swatch", style: "background:" + ({ malicious: "#F0524F", suspicious: "#F5A524", benign: "#2FBF71", unknown: "#8B98A8" }[k]), "aria-hidden": "true" }),
              k + ": " + v])))]));
        U.clear(sparkBox).append(U.el("div", { class: "card__title", text: "Time to verdict (last 30)" }),
          C.sparkline(s.ttv_series || []),
          U.el("div", { class: "muted", text: s.avg_time_to_verdict_s ? "Average " + s.avg_time_to_verdict_s + " s" : "No verdicts yet" }));
      };
      const renderRecent = (rows) => {
        U.clear(recent);
        if (!rows.length) { recent.append(C.empty("No scans yet", "Install an app on a paired phone.")); return; }
        for (const r of rows) recent.append(submissionLink(r));
      };
      const renderFeed = (events) => {
        U.clear(feed);
        for (const e of events.slice().reverse()) feed.prepend(feedRow(e));
        while (feed.children.length > 50) feed.lastChild.remove();
      };
      render(d.stats);
      renderRecent(d.recent_submissions || []);
      renderFeed(d.recent_events || []);
      const refresh = U.debounce(async () => {
        try {
          const [s, list] = await Promise.all([Api.get("/stats"), Api.get("/submissions" + U.qs({ page_size: 10 }))]);
          render(s); renderRecent(list.results);
        } catch (e) { /* keep last good view */ }
      }, 400);
      Live.on((ev) => {
        if (ev.type === "pipeline.event") { feed.prepend(feedRow(ev)); while (feed.children.length > 50) feed.lastChild.remove(); }
        if (["submission.created", "submission.status_changed", "verdict.ready", "remediation.updated",
          "device.heartbeat", "rule.generated", "resync", "poll"].includes(ev.type)) refresh();
        if (ev.type === "verdict.ready" && ev.data && ev.data.label === "malicious") {
          C.toast("A malicious verdict was reached: " + (ev.message || ""), { kind: "malicious", persistent: true,
            href: "/submissions/" + ev.submission_id + "/", actionText: "Open" });
        }
      });
    },
  };

  function submissionLink(r) {
    return U.el("a", { class: "row row--between", href: "/submissions/" + r.id + "/", style: "padding:6px 0" }, [
      U.el("span", { class: "truncate", text: r.app_label || r.package_name }),
      r.label ? C.verdictChip(r.label, null) : C.statusChip(r.status, r.status_label),
    ]);
  }

  function feedRow(e) {
    const who = e.submission_id ? e.submission_id.slice(0, 8) : "system";
    return U.el("li", { class: "lvl-" + e.level }, [
      U.el("span", { text: U.time(e.ts) }),
      U.el("span", { class: "truncate", text: who + " " + e.stage }),
      U.el("span", { class: "truncate", text: e.step + ": " + e.message, title: e.message }),
    ]);
  }

  Pages.submissions = {
    init(d) {
      const root = app();
      const params = new URLSearchParams(location.search);
      const filters = { label: params.get("label") || "", status: params.get("status") || "", q: params.get("q") || "" };
      const form = U.el("form", { class: "row", role: "search" }, [
        U.el("input", { class: "input", style: "max-width:260px", type: "search", name: "q", placeholder: "Search package or app", "aria-label": "Search", value: filters.q }),
        U.el("select", { class: "select", style: "max-width:180px", name: "label", "aria-label": "Verdict" }, [
          U.el("option", { value: "", text: "Any verdict" }),
          ...["malicious", "suspicious", "benign", "unknown"].map((l) => U.el("option", { value: l, text: LABEL_TEXT[l], selected: filters.label === l })),
        ]),
        U.el("select", { class: "select", style: "max-width:200px", name: "status", "aria-label": "Status" }, [
          U.el("option", { value: "", text: "Any status" }),
          U.el("option", { value: "in_progress", text: "In progress", selected: filters.status === "in_progress" }),
          U.el("option", { value: "verdict_ready", text: "Done", selected: filters.status === "verdict_ready" }),
          U.el("option", { value: "error", text: "Error", selected: filters.status === "error" }),
        ]),
        U.el("button", { class: "btn", type: "submit", text: "Filter" }),
      ]);
      const body = U.el("div", { class: "card" });
      const pager = U.el("div", { class: "row row--between" });
      root.append(form, body, pager);
      if (!isAnalyst()) root.insertBefore(viewerNote(), form);

      let page = Number(params.get("page") || 1);
      const load = async () => {
        const q = { page, label: filters.label, status: filters.status, q: filters.q };
        history.replaceState(null, "", "/submissions/" + U.qs(q));
        try {
          const res = await Api.get("/submissions" + U.qs(q));
          render(res);
        } catch (e) { U.clear(body).append(C.empty("Could not load submissions", e.message, retryBtn(load))); }
      };
      const render = (res) => {
        U.clear(body);
        if (!res.results.length) {
          body.append(C.empty(filters.q || filters.label || filters.status ? "No submissions match these filters." : "No submissions yet",
            filters.q || filters.label || filters.status ? "Try clearing a filter." : "Install an app on a paired phone.",
            filters.q || filters.label || filters.status ? U.el("button", { class: "btn", type: "button", text: "Clear filters", on: { click: () => { form.reset(); filters.label = filters.status = filters.q = ""; page = 1; load(); } } }) : null));
        } else {
          body.append(U.table(["App", "Verdict", "Status", "Device", "Provider", "When"],
            res.results.map((r) => U.el("tr", {
              class: "is-link", tabindex: "0",
              on: { click: () => { location.href = "/submissions/" + r.id + "/"; },
                keydown: (e) => { if (e.key === "Enter") location.href = "/submissions/" + r.id + "/"; } },
            }, [
              U.el("td", {}, [U.el("div", { class: "truncate", text: r.app_label || r.package_name }), U.el("div", { class: "mono muted truncate", text: r.package_name })]),
              U.el("td", {}, [C.verdictChip(r.label, r.confidence, r.overridden)]),
              U.el("td", {}, [C.statusChip(r.status, r.status_label)]),
              U.el("td", {}, [r.device.name]),
              U.el("td", { class: "muted" }, [r.provider || "-"]),
              U.el("td", { title: U.dt(r.created_at) }, [U.rel(r.created_at)]),
            ])), { caption: "Submissions" }));
        }
        U.clear(pager).append(
          U.el("span", { class: "muted", text: res.count + " total" }),
          U.el("span", { class: "row" }, [
            U.el("button", { class: "btn", type: "button", text: "Previous", disabled: page <= 1, on: { click: () => { page -= 1; load(); } } }),
            U.el("button", { class: "btn", type: "button", text: "Next", disabled: !res.next, on: { click: () => { page += 1; load(); } } })]));
      };
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        const f = new FormData(form);
        filters.q = f.get("q").trim(); filters.label = f.get("label"); filters.status = f.get("status");
        page = 1; load();
      });
      render(d.page || { results: [], count: 0 });
      Live.on((ev) => {
        if (page === 1 && ["submission.created", "submission.status_changed", "verdict.ready"].includes(ev.type)) {
          U.debounce(load, 300)();
        }
      });
    },
  };

  function retryBtn(fn) { return U.el("button", { class: "btn", type: "button", text: "Retry", on: { click: fn } }); }

  Pages.submission = {
    init(d) {
      const detail = d.detail;
      const sub = detail.submission;
      const root = app();
      let current = detail;
      const header = U.el("div", { class: "card" });
      const tabsBar = U.el("div", { class: "tabs", role: "tablist", "aria-label": "Submission sections" });
      const panel = U.el("div", { class: "card", role: "tabpanel" });
      root.append(header, tabsBar, panel);
      if (!isAnalyst()) root.insertBefore(viewerNote(), header);
      const events = [];
      let lastEvent = 0;
      const TABS = ["summary", "timeline", "analysis", "verdict", "remediation", "rules", "raw"];
      let tab = (location.hash || "#summary").slice(1);
      if (!TABS.includes(tab)) tab = "summary";

      const renderHeader = (s) => {
        const v = current.verdict;
        U.clear(header).append(
          U.el("div", { class: "row row--between" }, [
            U.el("div", {}, [
              U.el("h2", { text: s.app_label || s.package_name }),
              U.el("div", { class: "mono muted", text: s.package_name + (s.version_name ? "  v" + s.version_name : "") }),
              U.el("div", { class: "muted", text: "Device " + s.device.name + " · received " + U.dt(s.created_at) }),
            ]),
            U.el("div", { class: "row" }, [C.verdictChip(s.label, s.confidence, s.overridden)]),
          ]),
          U.el("div", { class: "row", style: "margin-top:12px" }, [C.statusChip(s.status, s.status_label), C.rail(s.status)]),
          U.el("div", { class: "row", style: "margin-top:12px" }, actionButtons(s, v)));
      };
      const actionButtons = (s, v) => {
        if (!isAnalyst()) return [];
        const btns = [];
        if (s.label && s.label !== "benign") btns.push(U.el("button", { class: "btn btn--danger", type: "button", text: "Propose uninstall", on: { click: proposeUninstall } }));
        btns.push(U.el("button", { class: "btn", type: "button", text: "Override verdict", on: { click: overrideDialog }, disabled: !v }));
        btns.push(U.el("button", { class: "btn", type: "button", text: "Re-analyze", on: { click: reanalyze },
          disabled: !["verdict_ready", "error"].includes(s.status) }));
        btns.push(U.el("button", { class: "btn", type: "button", text: s.remediation_hold ? "Clear hold" : "Hold auto-remediation",
          on: { click: toggleHold } }));
        return btns;
      };

      const renderTabs = () => {
        U.clear(tabsBar);
        for (const t of TABS) {
          tabsBar.appendChild(U.el("button", {
            class: "tab", role: "tab", type: "button", "aria-selected": t === tab ? "true" : "false",
            id: "tab-" + t, text: t[0].toUpperCase() + t.slice(1), on: { click: () => { tab = t; history.replaceState(null, "", "#" + t); renderTabs(); renderPanel(); } },
          }));
        }
      };
      const renderPanel = () => {
        U.clear(panel);
        const fn = { summary: summaryTab, timeline: timelineTab, analysis: analysisTab, verdict: verdictTab,
          remediation: remediationTab, rules: rulesTab, raw: rawTab }[tab];
        fn(panel, current);
      };
      function summaryTab(el, d2) {
        const v = d2.verdict;
        const s = d2.submission;
        el.append(U.el("div", { class: "grid" }, [
          U.el("div", { class: "span-6 stack" }, [
            U.el("div", { class: "card__title", text: "Verdict" }),
            v ? U.el("div", { class: "stack" }, [
              C.verdictChip(s.label, v.confidence, s.overridden),
              U.el("div", { class: "bar", "aria-hidden": "true" }, [U.el("span", { style: "width:" + Math.round(v.confidence * 100) + "%" })]),
              U.el("div", { class: "muted", text: "Score " + v.score.toFixed(2) + " · provider " + v.provider.name + " v" + v.provider.version + (v.provider.fallback_from ? " (fallback from " + v.provider.fallback_from + ")" : "") }),
              U.el("div", { class: "muted", text: "Recommended action: " + v.recommended_action }),
            ]) : C.empty("No verdict yet", "The pipeline is still running."),
          ]),
          U.el("div", { class: "span-6 stack" }, [
            U.el("div", { class: "card__title", text: "Why" }),
            U.el("p", { text: v ? v.explanation : "" }),
            U.el("div", { class: "row" }, (v && v.techniques || []).map((t) => U.el("span", { class: "pill", text: t.id + " " + t.name }))),
          ]),
          U.el("div", { class: "span-6 stack" }, [
            U.el("div", { class: "card__title", text: "Remediation" }),
            d2.remediation ? U.el("div", { text: "State: " + d2.remediation.state + " (" + d2.remediation.origin + ")" }) : U.el("div", { class: "muted", text: "No uninstall request." }),
          ]),
          U.el("div", { class: "span-6 stack" }, [
            U.el("div", { class: "card__title", text: "Device and file" }),
            U.el("dl", { class: "kv" }, [
              U.el("dt", { text: "SHA-256" }), U.el("dd", { class: "mono", text: s.sha256 }),
              U.el("dt", { text: "Size" }), U.el("dd", { text: (d2.sample.size_bytes / 1048576).toFixed(2) + " MB" }),
              U.el("dt", { text: "Installer" }), U.el("dd", { text: s.installer_package || "unknown" }),
              U.el("dt", { text: "Permissions" }), U.el("dd", { text: String((s.requested_permissions || []).length) }),
            ]),
          ]),
        ]));
        const signals = (d2.evidence && d2.evidence.signals) || [];
        if (signals.length) {
          el.append(U.el("div", { class: "card__title", style: "margin-top:16px", text: "Top signals" }),
            U.el("ul", { class: "stack", style: "padding-left:0;list-style:none" }, signals.slice(0, 5).map((g) =>
              U.el("li", { class: "row" }, [U.el("span", { class: "pill", text: g.severity }), U.el("span", { text: g.name }), U.el("span", { class: "mono muted", text: g.detail })]))));
        }
      }
      function timelineTab(el) {
        const showDebug = U.el("input", { type: "checkbox", id: "show-debug", checked: false });
        const list = U.el("ol", { class: "timeline", "aria-live": "polite", "aria-label": "Evidence chain" });
        const copy = U.el("button", { class: "btn", type: "button", text: "Copy as text", on: { click: async () => {
          const lines = events.filter((e) => showDebug.checked || e.level !== "debug").map((e) => "+" + offsetOf(e) + "s " + e.stage + "/" + e.step + " " + e.message);
          try { await navigator.clipboard.writeText(lines.join("\n")); C.toast("Timeline copied", { kind: "ok" }); }
          catch (err) { C.toast("Copy failed: " + err.message, { kind: "malicious" }); }
        } } });
        el.append(U.el("div", { class: "row row--between" }, [
          U.el("label", { class: "row" }, [showDebug, U.el("span", { text: "Show debug" })]), copy]), list);
        const start = events.length ? events[0].ts : null;
        function offsetOf(e) { return start ? ((Date.parse(e.ts) - Date.parse(start)) / 1000).toFixed(2) : "0.00"; }
        const draw = () => {
          U.clear(list);
          for (const e of events) {
            if (!showDebug.checked && e.level === "debug") continue;
            list.appendChild(U.el("li", { class: "lvl-" + e.level }, [
              U.el("div", { class: "meta", text: "+" + offsetOf(e) + "s  " + e.stage + " / " + e.step + "  " + U.time(e.ts) }),
              U.el("div", { class: "msg", text: e.message }),
            ]));
          }
          if (!list.children.length) list.appendChild(U.el("li", { text: "No events yet." }));
        };
        showDebug.addEventListener("change", draw);
        draw();
        panelDraw = draw;
      }
      let panelDraw = null;
      function analysisTab(el, d2) {
        const ev = d2.evidence;
        if (!ev) { el.append(C.empty("No analysis yet", "Static analysis has not stored evidence for this file.")); return; }
        if (ev.partial) el.append(U.el("div", { class: "banner banner--warn" }, [U.el("span", { text: "Partial analysis: " + ev.partial_reasons.join("; ") })]));
        el.append(U.el("h3", { text: "Signals (" + ev.signals.length + ")" }));
        el.append(U.table(["ID", "Severity", "Signal", "Detail", "ATT&CK"], ev.signals.map((g) => U.el("tr", {}, [
          U.el("td", { class: "mono", text: g.id }), U.el("td", {}, [U.el("span", { class: "pill", text: g.severity })]),
          U.el("td", { text: g.name + " (" + g.code + ")" }), U.el("td", { class: "mono", text: g.detail }),
          U.el("td", { text: (g.attck || []).join(", ") })])), { caption: "Signals" }));
        const st = ev.static || {};
        const hosts = (st.strings && st.strings.domains) || [];
        el.append(U.el("h3", { style: "margin-top:16px", text: "Network indicators (defanged)" }),
          U.el("ul", { class: "mono" }, (st.strings && st.strings.urls || []).slice(0, 20).map((u) => U.el("li", { text: U.defang(u) }))),
          U.el("div", { class: "muted", text: "Hosts: " + (hosts.length ? hosts.map(U.defang).join(", ") : "none") }));
        el.append(U.el("h3", { style: "margin-top:16px", text: "Manifest" }), U.el("pre", { class: "code", text: JSON.stringify(st.manifest || {}, null, 2) }));
      }
      function verdictTab(el, d2) {
        const v = d2.verdict;
        if (!v) { el.append(C.empty("No verdict yet", "Wait for the pipeline to finish.")); return; }
        el.append(U.el("div", { class: "row" }, [C.verdictChip(d2.submission.label, v.confidence, d2.submission.overridden)]),
          U.el("p", { text: v.explanation }));
        el.append(U.el("h3", { text: "Techniques" }), U.table(["ID", "Name", "Tactic", "Confidence", "Evidence"],
          (v.techniques || []).map((t) => U.el("tr", {}, [U.el("td", { text: t.id }), U.el("td", { text: t.name }),
            U.el("td", { text: t.tactic || "" }), U.el("td", { text: U.pct(t.confidence) }), U.el("td", { class: "mono", text: (t.evidence_ids || []).join(", ") })]))));
        el.append(U.el("h3", { style: "margin-top:16px", text: "History" }), U.table(["When", "Label", "Confidence", "Provider", "Current"],
          d2.verdict_history.map((h) => U.el("tr", {}, [U.el("td", { text: U.dt(h.created_at) }), U.el("td", { text: LABEL_TEXT[h.label] || h.label }),
            U.el("td", { text: U.pct(h.confidence) }), U.el("td", { text: h.provider }), U.el("td", { text: h.is_current ? "yes" : "" })]))));
        el.append(U.el("h3", { style: "margin-top:16px", text: "Analyst actions" }), U.table(["When", "Action", "From", "To", "Note", "By"],
          d2.analyst_actions.map((a) => U.el("tr", {}, [U.el("td", { text: U.dt(a.created_at) }), U.el("td", { text: a.kind }),
            U.el("td", { text: a.from || "" }), U.el("td", { text: a.to || "" }), U.el("td", { text: a.note || "" }), U.el("td", { text: a.user || "" })]))));
      }
      function remediationTab(el, d2) {
        if (!d2.remediations.length) { el.append(C.empty("No uninstall requests", "Propose an uninstall once a verdict says so.")); return; }
        el.append(U.table(["When", "Origin", "State", "Detail", "Checks"], d2.remediations.map((r) => U.el("tr", {}, [
          U.el("td", { text: U.dt(r.created_at) }), U.el("td", { text: r.origin }), U.el("td", { text: r.state }),
          U.el("td", { text: r.outcome_detail || "" }), U.el("td", { text: (r.checks || []).map((c) => (c.passed ? "pass " : "fail ") + c.id).join(", ") })]))));
      }
      function rulesTab(el, d2) {
        const actions = isAnalyst() ? U.el("button", { class: "btn", type: "button", text: "Generate rules", on: { click: async () => {
          try { await Api.post("/submissions/" + sub.id + "/generate-rules"); C.toast("Rule generation started", { kind: "ok" }); }
          catch (e) { C.toast(e.message, { kind: "malicious" }); } } } }) : null;
        el.append(U.el("div", { class: "row row--between" }, [U.el("span", { class: "muted", text: d2.rules.length + " generated rule(s)" }), actions]));
        if (!d2.rules.length) { el.append(C.empty("No rules yet", "Rules are drafted for malicious verdicts.")); return; }
        el.append(U.table(["Name", "Kind", "Status", "FP test"], d2.rules.map((r) => U.el("tr", { class: "is-link", tabindex: "0",
          on: { click: () => { location.href = "/rules/" + r.id + "/"; } } }, [
          U.el("td", { class: "mono", text: r.name }), U.el("td", { text: r.kind }), U.el("td", { text: r.status }),
          U.el("td", { text: (r.fp_test && r.fp_test.status) || "not_run" })]))));
      }
      function rawTab(el, d2) {
        el.append(U.el("div", { class: "row" }, [
          U.el("a", { class: "btn", href: "/api/v1/dash/submissions/" + sub.id, text: "Open JSON" }),
          U.el("a", { class: "btn", href: "/api/v1/dash/submissions/" + sub.id + "/events?since_event_id=0", text: "Events JSON" })]));
        el.append(U.el("pre", { class: "code", text: JSON.stringify({ submission: d2.submission, verdict: d2.verdict }, null, 2) }));
      }

      async function refresh() {
        try { current = { ...(await Api.get("/submissions/" + sub.id)), ...{} }; } catch (e) { return; }
        renderHeader(current.submission);
        renderPanel();
      }
      async function proposeUninstall() {
        const note = U.el("textarea", { class: "textarea", "aria-label": "Note", placeholder: "Why? (optional)" });
        C.modal({ title: "Ask the user to uninstall " + (sub.app_label || sub.package_name) + "?", body: [
          U.el("p", { text: sub.package_name + " will be flagged on the user's phone. They must confirm in Android before anything is removed." }),
          note], actions: [
          { label: "Cancel", run: (close) => close() },
          { label: "Propose uninstall", kind: "danger", run: async (close) => {
            await Api.post("/submissions/" + sub.id + "/remediation", { action: "uninstall", note: note.value });
            close(); C.toast("Uninstall proposed to the phone", { kind: "ok" }); refresh(); } }]});
      }
      function overrideDialog() {
        const group = U.el("fieldset", { class: "stack", style: "border:0;padding:0" }, [
          U.el("legend", { text: "New verdict" }),
          ...["malicious", "suspicious", "benign"].map((l) => U.el("label", { class: "row" }, [
            U.el("input", { type: "radio", name: "ov", value: l, checked: l === "benign" }), U.el("span", { text: LABEL_TEXT[l] })])),
        ]);
        const note = U.el("textarea", { class: "textarea", name: "note", "aria-label": "Reason", placeholder: "Reason (at least 5 characters)" });
        const notify = U.el("input", { type: "checkbox", checked: true });
        const err = U.el("div", { class: "form-error", role: "alert" });
        C.modal({ title: "Override verdict", body: [group, note, U.el("label", { class: "row" }, [notify, U.el("span", { text: "Notify the device" })]), err],
          actions: [
            { label: "Cancel", run: (close) => close() },
            { label: "Save override", run: async (close) => {
              const chosen = group.querySelector("input:checked").value;
              if (note.value.trim().length < 5) { err.textContent = "Please give a reason (at least 5 characters)."; return; }
              await Api.post("/submissions/" + sub.id + "/override", { label: chosen, note: note.value.trim(), notify: notify.checked });
              close(); C.toast("Verdict updated to " + LABEL_TEXT[chosen], { kind: "ok" }); refresh(); } }]});
      }
      async function reanalyze() {
        try { await Api.post("/submissions/" + sub.id + "/reanalyze"); C.toast("Re-analysis queued", { kind: "ok" }); refresh(); }
        catch (e) { C.toast(e.message, { kind: "malicious" }); }
      }
      async function toggleHold() {
        try { await Api.post("/submissions/" + sub.id + "/hold", { hold: !current.submission.remediation_hold }); refresh(); }
        catch (e) { C.toast(e.message, { kind: "malicious" }); }
      }

      renderHeader(sub);
      renderTabs();
      renderPanel();
      Live.on(async (ev) => {
        if (ev.submission_id === sub.id || ev.type === "resync" || ev.type === "poll") {
          if (ev.type === "pipeline.event" && ev.submission_id === sub.id) {
            events.push(ev); lastEvent = Math.max(lastEvent, ev.event_id);
            if (tab === "timeline" && panelDraw) { U.clear(panel); timelineTab(panel); }
          }
          if (["submission.status_changed", "verdict.ready", "remediation.updated", "resync", "poll"].includes(ev.type)) refresh();
        }
      });
      // Load the evidence chain once, then keep it live through the socket.
      Api.get("/submissions/" + sub.id + "/events?since_event_id=0").then((res) => {
        events.length = 0; events.push(...res.events);
        lastEvent = res.events.length ? res.events[res.events.length - 1].event_id : 0;
        if (tab === "timeline") { U.clear(panel); timelineTab(panel); }
      }).catch(() => {});
    },
  };

  Pages.devices = {
    init(d) {
      const root = app();
      const table = U.el("div", { class: "card" });
      const head = U.el("div", { class: "row row--between" }, [U.el("h2", { text: "Paired phones" }),
        isAnalyst() ? U.el("button", { class: "btn btn--primary", type: "button", text: "Pair device", on: { click: pairDialog } }) : null]);
      root.append(head, table);
      if (!isAnalyst()) root.insertBefore(viewerNote(), head);
      const render = (devices) => {
        U.clear(table);
        if (!devices.length) { table.append(C.empty("No devices paired yet", "Use Pair device to connect a phone.")); return; }
        table.append(U.table(["Name", "Android", "App", "Status", "Last seen", "Protection", "Scans"], devices.map((x) => U.el("tr", {}, [
          U.el("td", { text: x.name }), U.el("td", { text: x.android_version || "-" }), U.el("td", { text: x.app_version || "-" }),
          U.el("td", {}, [U.el("span", { class: "chip " + (x.online ? "chip--benign" : "chip--unknown"), text: x.online ? "Online" : "Offline" })]),
          U.el("td", { text: U.rel(x.last_seen) }), U.el("td", { text: x.protection_on ? "On" : "Off" }), U.el("td", { class: "num", text: String(x.scans) })]))));
      };
      render(d.devices || []);
      Live.on(U.debounce(async (ev) => {
        if (["device.heartbeat", "resync", "poll", "pipeline.event"].includes(ev.type)) {
          try { render((await Api.get("/devices")).devices); } catch (e) { /* keep view */ }
        }
      }, 1000));
      function pairDialog() {
        const codeBox = U.el("div", { class: "mono", style: "font-size:40px;letter-spacing:.2em", "aria-live": "polite", text: "------" });
        const countdown = U.el("div", { class: "muted", text: "" });
        let timer = null;
        const newCode = async () => {
          const res = await Api.post("/pairing-code");
          codeBox.textContent = res.code.slice(0, 3) + " " + res.code.slice(3);
          const end = Date.parse(res.expires_at);
          clearInterval(timer);
          timer = setInterval(() => {
            const left = Math.max(0, Math.round((end - Date.now()) / 1000));
            countdown.textContent = left ? "Expires in " + Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0") : "Expired. Generate a new code.";
            if (!left) clearInterval(timer);
          }, 500);
        };
        const m = C.modal({ title: "Pair a phone", body: [
          U.el("p", { text: "On the phone: open Sentinel, enter this code and the server address." }), codeBox, countdown,
          U.el("p", { class: "muted", text: "Emulator: http://10.0.2.2:8000. Phone with USB: adb reverse tcp:8000 tcp:8000, then http://127.0.0.1:8000." })],
          actions: [{ label: "Close", run: (close) => { clearInterval(timer); close(); } },
            { label: "New code", kind: "primary", run: async () => { await newCode(); } }] });
        newCode().catch((e) => C.toast(e.message, { kind: "malicious" }));
        return m;
      }
    },
  };

  Pages.remediation = {
    init(d) {
      const root = app();
      const box = U.el("div", { class: "card" });
      root.append(box);
      const rows = d.requests || [];
      if (!rows.length) { box.append(C.empty("No uninstall requests", "Requests appear here when a verdict or an analyst proposes one.")); return; }
      box.append(U.table(["When", "App", "Device", "Origin", "State", "Expires", ""], rows.map((r) => U.el("tr", {}, [
        U.el("td", { text: U.dt(r.created_at) }),
        U.el("td", {}, [U.el("a", { href: "/submissions/" + r.submission_id + "/", text: r.app_label || r.package_name })]),
        U.el("td", { text: r.device.name }), U.el("td", { text: r.origin }),
        U.el("td", { text: r.state }), U.el("td", { text: U.dt(r.expires_at) }),
        U.el("td", {}, [isAnalyst() && ["pending", "delivered"].includes(r.state) ? U.el("button", { class: "btn", type: "button", text: "Cancel", on: { click: () => {
          C.modal({ title: "Cancel this uninstall request?", body: [U.el("p", { text: r.package_name + " will stay installed. The phone is told to drop the request." })],
            actions: [{ label: "Keep request", run: (close) => close() },
              { label: "Cancel request", kind: "danger", run: async (close) => { await Api.post("/remediations/" + r.id + "/cancel", { note: "analyst" }); close(); location.reload(); } }] });
        } } }) : null]),
      ]))));
    },
  };

  Pages.rules = {
    init(d) {
      const root = app();
      const box = U.el("div", { class: "card" });
      const rows = d.rules || [];
      root.append(U.el("div", { class: "row row--between" }, [U.el("span", { class: "muted", text: rows.length + " rule(s)" }),
        U.el("a", { class: "btn", href: "/api/v1/dash/rules/export", text: "Export approved (zip)" })]), box);
      if (!rows.length) { box.append(C.empty("No rules yet", "Rules are drafted for malicious verdicts.")); return; }
      box.append(U.table(["Name", "Kind", "Status", "Level", "FP test", "Version", ""], rows.map((r) => U.el("tr", {}, [
        U.el("td", { class: "mono", text: r.name }), U.el("td", { text: r.kind }), U.el("td", { text: r.status }),
        U.el("td", { text: r.level }), U.el("td", { text: (r.fp_test && r.fp_test.status) || "not_run" }),
        U.el("td", { text: "v" + r.version }),
        U.el("td", {}, [U.el("a", { href: "/rules/" + r.id + "/", text: "Open" })])]))));
    },
  };

  Pages.rule = {
    init(d) {
      const root = app();
      const id = d.rule_id;
      const load = async () => {
        const res = await Api.get("/rules/" + id);
        render(res);
      };
      const render = (res) => {
        U.clear(root);
        const r = res.rule;
        const actions = isAnalyst() ? U.el("div", { class: "row" }, [
          U.el("button", { class: "btn btn--primary", type: "button", text: "Approve", disabled: r.status !== "draft", on: { click: () => approveDialog(r) } }),
          U.el("button", { class: "btn", type: "button", text: "Retire", disabled: r.status !== "approved", on: { click: () => retireDialog(r) } }),
          U.el("button", { class: "btn", type: "button", text: "Re-run FP test", on: { click: async () => { await Api.post("/rules/" + id + "/fp-test"); load(); } } }),
          U.el("button", { class: "btn", type: "button", text: "Edit as new version", disabled: r.status === "retired", on: { click: () => editDialog(r) } }),
        ]) : null;
        root.append(
          U.el("div", { class: "card stack" }, [
            U.el("div", { class: "row row--between" }, [U.el("h2", { class: "mono", text: r.name }), U.el("span", { class: "pill", text: r.status + " · v" + r.version })]),
            U.el("div", { class: "muted", text: "FP test: " + ((r.fp_test && r.fp_test.status) || "not_run") + (r.fp_test && r.fp_test.hits && r.fp_test.hits.length ? " (hits: " + r.fp_test.hits.join(", ") + ")" : "") }),
            r.needs_review ? U.el("div", { class: "banner banner--warn", text: "Needs review: an analyst marked a match as a false positive." }) : null,
            actions,
          ]),
          U.el("div", { class: "card stack", style: "margin-top:16px" }, [U.el("div", { class: "card__title", text: "Content" }),
            U.el("pre", { class: "code", text: r.content })]),
          U.el("div", { class: "card stack", style: "margin-top:16px" }, [U.el("div", { class: "card__title", text: "Matches (" + res.matches.length + ")" }),
            res.matches.length ? U.table(["When", "Package", "False positive", ""], res.matches.map((m) => U.el("tr", {}, [
              U.el("td", { text: U.dt(m.ts) }), U.el("td", { text: m.package_name }), U.el("td", { text: m.false_positive ? "yes" : "no" }),
              U.el("td", {}, [isAnalyst() && !m.false_positive ? U.el("button", { class: "btn", type: "button", text: "Mark false positive", on: { click: async () => {
                await Api.post("/matches/" + m.id + "/false-positive"); load(); } } }) : null])]))) : U.el("div", { class: "muted", text: "No matches yet." })]),
          U.el("div", { class: "card stack", style: "margin-top:16px" }, [U.el("div", { class: "card__title", text: "Versions" }),
            U.table(["Version", "Status", "FP test", "Created"], res.versions.map((v) => U.el("tr", {}, [
              U.el("td", { text: "v" + v.version }), U.el("td", { text: v.status }), U.el("td", { text: (v.fp_test && v.fp_test.status) || "not_run" }), U.el("td", { text: U.dt(v.created_at) })])))]),
        );
      };
      function approveDialog(r) {
        const note = U.el("textarea", { class: "textarea", placeholder: "Note (required if the FP test did not pass)" });
        const err = U.el("div", { class: "form-error", role: "alert" });
        C.modal({ title: "Approve " + r.name + "?", body: [U.el("p", { text: "Approved rules become active for new samples." }), note, err],
          actions: [{ label: "Cancel", run: (close) => close() },
            { label: "Approve", kind: "primary", run: async (close) => {
              try { await Api.post("/rules/" + id + "/approve", { note: note.value }); close(); C.toast("Rule approved", { kind: "ok" }); load(); }
              catch (e) { err.textContent = e.message; } } }] });
      }
      function retireDialog(r) {
        C.modal({ title: "Retire " + r.name + "?", body: [U.el("p", { text: "The active file is removed. The rule is kept for history." })],
          actions: [{ label: "Cancel", run: (close) => close() }, { label: "Retire", kind: "danger", run: async (close) => {
            await Api.post("/rules/" + id + "/retire", { note: "retired from dashboard" }); close(); load(); } }] });
      }
      function editDialog(r) {
        const ta = U.el("textarea", { class: "textarea", "aria-label": "Rule content" });
        ta.value = r.content;
        const err = U.el("div", { class: "form-error", role: "alert" });
        C.modal({ title: "Edit as a new draft", body: [ta, err], actions: [{ label: "Cancel", run: (close) => close() },
          { label: "Save draft", kind: "primary", run: async (close) => {
            try { await Api.put("/rules/" + id, { content: ta.value }); close(); load(); } catch (e) { err.textContent = e.message; } } }] });
      }
      load().catch((e) => root.append(C.banner(e.message, "error")));
    },
  };

  Pages.settings = {
    init(d) {
      const root = app();
      const s = d.settings;
      const writable = isAnalyst();
      if (!writable) root.append(viewerNote());
      const save = async (key, value) => {
        try { await Api.post("/settings", { key, value }); C.toast("Saved " + key, { kind: "ok" }); }
        catch (e) { C.toast(e.message, { kind: "malicious" }); }
      };
      const numberField = (label, key, value, min, max, step) => {
        const input = U.el("input", { class: "input", type: "number", value, min, max, step, "aria-label": label, disabled: !writable });
        input.addEventListener("change", () => save(key, key.includes("confidence") ? Number(input.value) : parseInt(input.value, 10)));
        return U.el("label", { class: "field" }, [U.el("span", { text: label }), input]);
      };
      const toggle = (label, key, value) => {
        const input = U.el("input", { type: "checkbox", checked: !!value, disabled: !writable });
        input.addEventListener("change", () => save(key, input.checked));
        return U.el("label", { class: "toggle" }, [input, U.el("span", { class: "toggle__track", "aria-hidden": "true" }),
          U.el("span", { text: label + ": " + (value ? "On" : "Off") })]);
      };
      const protectedBox = U.el("textarea", { class: "textarea", "aria-label": "Protected packages", disabled: !writable,
        value: (s.protected_packages || []).join("\n") });
      protectedBox.textContent = (s.protected_packages || []).join("\n");
      const reputationInput = U.el("input", { class: "input mono", placeholder: "64-character SHA-256", "aria-label": "Hash or signer", disabled: !writable });
      const kind = U.el("select", { class: "select", "aria-label": "List", disabled: !writable }, [
        U.el("option", { value: "bad_hash", text: "Known-bad hash" }), U.el("option", { value: "good_hash", text: "Known-good hash" }),
        U.el("option", { value: "bad_signer", text: "Known-bad signer" })]);
      root.append(
        U.el("div", { class: "card stack" }, [U.el("div", { class: "card__title", text: "Remediation guardrails" }),
          toggle("Auto-propose uninstall for confident malicious verdicts", "auto_remediation_enabled", s.auto_remediation_enabled),
          numberField("Minimum confidence (0.50 - 0.99)", "auto_remediation_min_confidence", s.auto_remediation_min_confidence, 0.5, 0.99, 0.01),
          numberField("Requests per device per hour", "remediation_rate_limit_per_device_hour", s.remediation_rate_limit_per_device_hour, 1, 100, 1),
          U.el("label", { class: "field" }, [U.el("span", { text: "Protected packages (one per line)" }), protectedBox,
            writable ? U.el("button", { class: "btn", type: "button", text: "Save protected packages", on: { click: () => save("protected_packages",
              protectedBox.value.split("\n").map((x) => x.trim()).filter(Boolean)) } }) : null])]),
        U.el("div", { class: "card stack", style: "margin-top:16px" }, [U.el("div", { class: "card__title", text: "Analysis" }),
          U.el("div", { text: "Reasoner: " + s.reasoner_backend + " (rules = rule engine only; hybrid = rule engine + active lists + agentic LLM on borderline cases)" }),
          toggle("Dynamic analysis (not installed in this build)", "dynamic_enabled", s.dynamic_enabled),
          U.el("div", { class: "muted", text: "Analysis version " + d.env.analysis_version })]),
        U.el("div", { class: "card stack", style: "margin-top:16px" }, [U.el("div", { class: "card__title", text: "Reputation lists" }),
          U.el("div", { class: "muted", text: "Bad hashes " + d.reputation_counts.bad_hashes + " · good hashes " + d.reputation_counts.good_hashes + " · bad signers " + d.reputation_counts.bad_signers }),
          writable ? U.el("form", { class: "row", on: { submit: async (e) => {
            e.preventDefault();
            try { await Api.post("/reputation", { kind: kind.value, value: reputationInput.value.trim() }); C.toast("Added to list", { kind: "ok" }); reputationInput.value = ""; }
            catch (err) { C.toast(err.message, { kind: "malicious" }); } } } }, [kind, reputationInput,
            U.el("button", { class: "btn", type: "submit", text: "Add entry" })]) : null]),
        U.el("div", { class: "card stack", style: "margin-top:16px" }, [U.el("div", { class: "card__title", text: "Interface" }),
          toggle("Show demo console", "show_demo_console", s.show_demo_console)]),
      );
    },
  };

  Pages.demo = {
    init(d) {
      const root = app();
      const pre = U.el("div", { class: "card", "aria-live": "polite" });
      const evidenceLink = U.el("a", { class: "btn", href: "/api/v1/dash/demo/evidence-pack", text: "Download evidence pack" });
      const marker = U.el("input", { class: "input", placeholder: "Timeline marker, e.g. Scenario A start", "aria-label": "Marker" });
      root.append(
        U.el("div", { class: "row" }, [
          U.el("button", { class: "btn btn--primary", type: "button", text: "Run pre-flight", on: { click: runPreflight } }),
          isAnalyst() ? U.el("button", { class: "btn btn--danger", type: "button", text: "Reset demo data", on: { click: resetDialog } }) : null,
          evidenceLink,
        ]),
        pre,
        isAnalyst() ? U.el("form", { class: "row", on: { submit: async (e) => {
          e.preventDefault();
          try { await Api.post("/demo/marker", { label: marker.value }); marker.value = ""; C.toast("Marker added", { kind: "ok" }); }
          catch (err) { C.toast(err.message, { kind: "malicious" }); } } } }, [marker, U.el("button", { class: "btn", type: "submit", text: "Add marker" })]) : null,
        U.el("div", { class: "card" }, [U.el("div", { class: "card__title", text: "Latest evaluation" }), U.el("div", { id: "eval-box", class: "muted", text: "Loading..." })]),
      );
      Api.get("/eval/latest").then((r) => {
        const box = document.getElementById("eval-box");
        U.clear(box).append(U.el("pre", { class: "code", text: JSON.stringify(r.summary || r, null, 2) }));
      }).catch(() => { document.getElementById("eval-box").textContent = "No evaluation has been run yet."; });
      async function runPreflight() {
        U.clear(pre).append(U.el("div", { class: "muted", text: "Checking..." }));
        try {
          const r = await Api.get("/demo/preflight");
          U.clear(pre).append(U.el("div", { class: "banner banner--" + (r.overall === "ready" ? "ok" : r.overall === "warn" ? "warn" : "error"),
            text: "Overall: " + r.overall.replace("_", " ") }), U.table(["Check", "Status", "Detail"], r.checks.map((c) => U.el("tr", {}, [
              U.el("td", { text: c.label }), U.el("td", { text: c.status }), U.el("td", { text: c.detail })]))));
        } catch (e) { U.clear(pre).append(C.banner(e.message, "error")); }
      }
      function resetDialog() {
        const input = U.el("input", { class: "input", placeholder: "Type reset to confirm", "aria-label": "Confirm reset" });
        C.modal({ title: "Reset demo data?", body: [U.el("p", { text: "Submissions, verdicts, commands, remediations, events and generated rules are deleted. Users, devices and settings are kept." }), input],
          actions: [{ label: "Cancel", run: (close) => close() },
            { label: "Reset", kind: "danger", run: async (close) => {
              if (input.value !== "reset") throw new Error("Type reset to confirm.");
              await Api.post("/demo/reset", { confirm: "reset" }); close(); C.toast("Reset started", { kind: "ok" }); } }] });
      }
    },
  };

  Pages.pipeline = {
    init(d) {
      const root = app();
      const filter = U.el("input", { class: "input", style: "max-width:320px", placeholder: "Filter by submission id prefix", "aria-label": "Filter" });
      const tbody = U.el("tbody");
      root.append(U.el("div", { class: "row" }, [filter]), U.el("div", { class: "card table-wrap" }, [
        U.el("table", { class: "mono" }, [U.el("thead", {}, [U.el("tr", {}, ["#", "Time", "Submission", "Stage", "Step", "Level", "Message"].map((h) => U.el("th", { text: h })))]), tbody])]));
      const addRow = (ev, atTop) => {
        if (filter.value && !(ev.submission_id || "").startsWith(filter.value)) return;
        const row = U.el("tr", { class: "lvl-" + ev.level }, [ev.event_id, U.time(ev.ts), (ev.submission_id || "-").slice(0, 8),
          ev.stage, ev.step, ev.level, ev.message].map((v) => U.el("td", { text: String(v) })));
        if (atTop) tbody.insertBefore(row, tbody.firstChild); else tbody.appendChild(row);
      };
      // Newest first: history is sent oldest-first by the server, so prepend in order.
      for (const ev of d.events || []) addRow(ev, true);
      Live.on((ev) => {
        if (ev.type !== "pipeline.event") return;
        addRow(ev, true);
        while (tbody.children.length > 200) tbody.lastChild.remove();
      });
    },
  };

  // ---------- Boot ----------
  document.addEventListener("DOMContentLoaded", () => {
    const page = document.body.dataset.page;
    const d = data();
    if (page === "login") return;
    Live.start();
    const fn = Pages[page];
    if (fn && fn.init && document.getElementById("app")) {
      try { fn.init(d); } catch (e) { app().appendChild(C.banner("Something went wrong: " + e.message, "error")); }
    }
  });
})();
