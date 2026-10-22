/* ws-client.js - reconnecting WebSocket client for the Sentinel event stream (contract v1).
   Usage:
     const ws = Ws.connect("/ws/dashboard/", {
       onEvent(ev) { ... },                 // called once per event, in event_id order, de-duplicated
       onState(state) { ... },              // "live" | "reconnecting" | "offline"
       onResync(lastEventId) { ... }        // called after every reconnect: fetch what you missed
     });
     ws.close();
*/
const Ws = (() => {
  const BACKOFF = [1000, 2000, 4000, 8000, 15000];
  const OFFLINE_AFTER_MS = 20000;

  function connect(path, handlers) {
    const url = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + path;
    let sock = null, attempt = 0, closedByUser = false, lastEventId = 0;
    let stableTimer = null, offlineTimer = null, state = "reconnecting";
    const seen = new Set();

    function setState(s) {
      if (s === state) return;
      state = s;
      if (handlers.onState) handlers.onState(s);
    }

    function open() {
      sock = new WebSocket(url);
      sock.onopen = () => {
        clearTimeout(offlineTimer);
        setState("live");
        if (attempt > 0 && handlers.onResync) handlers.onResync(lastEventId);   // repair gaps
        stableTimer = setTimeout(() => { attempt = 0; }, 10000);                // reset backoff once stable
      };
      sock.onmessage = (msg) => {
        let ev;
        try { ev = JSON.parse(msg.data); } catch (e) { return; }
        if (!ev || typeof ev.event_id !== "number" || ev.v !== 1) return;       // ignore unknown shapes
        if (seen.has(ev.event_id)) return;                                      // de-duplicate
        seen.add(ev.event_id);
        if (seen.size > 5000) { seen.clear(); seen.add(ev.event_id); }
        if (ev.event_id > lastEventId) lastEventId = ev.event_id;
        if (handlers.onEvent) handlers.onEvent(ev);
      };
      sock.onclose = (e) => {
        clearTimeout(stableTimer);
        if (closedByUser) return;
        if (e.code === 1006 && attempt === 0 && state !== "live") {
          // handshake rejected before ever opening: most likely not logged in
          if (handlers.onAuthFailure) handlers.onAuthFailure();
        }
        setState("reconnecting");
        clearTimeout(offlineTimer);
        offlineTimer = setTimeout(() => setState("offline"), OFFLINE_AFTER_MS);
        const delay = BACKOFF[Math.min(attempt, BACKOFF.length - 1)] + Math.floor(Math.random() * 500);
        attempt += 1;
        setTimeout(open, delay);
      };
      sock.onerror = () => { try { sock.close(); } catch (e) { /* already closing */ } };
    }

    open();
    return {
      close() { closedByUser = true; clearTimeout(offlineTimer); clearTimeout(stableTimer); if (sock) sock.close(); },
      get state() { return state; },
      get lastEventId() { return lastEventId; },
    };
  }

  return { connect };
})();
