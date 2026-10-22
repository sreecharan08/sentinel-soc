"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { freshAccessToken, getSession } from "./api";
import { WS_URL } from "./config";
import type { PipelineEvent } from "./types";

export type ConnState = "live" | "connecting" | "offline";

interface RealtimeValue {
  state: ConnState;
  /** Increments on every pipeline event and on every (re)connect; pages refetch when it changes. */
  tick: number;
  lastEventAt: number | null;
  subscribe: (fn: (ev: PipelineEvent) => void) => () => void;
}

const Ctx = createContext<RealtimeValue>({ state: "offline", tick: 0, lastEventAt: null, subscribe: () => () => {} });

/** One native WebSocket to /ws/dashboard/ for the whole console. Auth is `?token=<access JWT>`. */
export function RealtimeProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<ConnState>("connecting");
  const [tick, setTick] = useState(0);
  const [lastEventAt, setLastEventAt] = useState<number | null>(null);
  const subs = useRef(new Set<(ev: PipelineEvent) => void>());

  useEffect(() => {
    let socket: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let debounce: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    let stopped = false;

    const bump = () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => setTick((n) => n + 1), 400);
    };

    const connect = async () => {
      if (stopped || !getSession()) return;
      setState("connecting");
      const token = await freshAccessToken();
      if (stopped || !token) return;
      socket = new WebSocket(`${WS_URL}/ws/dashboard/?token=${encodeURIComponent(token)}`);
      socket.onopen = () => {
        attempt = 0;
        setState("live");
        setTick((n) => n + 1); // catch up on anything missed while disconnected
      };
      socket.onmessage = (msg) => {
        try {
          const ev = JSON.parse(msg.data as string) as PipelineEvent;
          setLastEventAt(Date.now());
          subs.current.forEach((fn) => fn(ev));
          bump();
        } catch {
          /* ignore malformed frame */
        }
      };
      socket.onclose = () => {
        if (stopped) return;
        setState("offline");
        attempt += 1;
        timer = setTimeout(connect, Math.min(1000 * 2 ** Math.min(attempt, 4), 15000));
      };
      socket.onerror = () => socket?.close();
    };

    void connect();
    return () => {
      stopped = true;
      clearTimeout(timer);
      clearTimeout(debounce);
      socket?.close();
    };
  }, []);

  const subscribe = useCallback((fn: (ev: PipelineEvent) => void) => {
    subs.current.add(fn);
    return () => {
      subs.current.delete(fn);
    };
  }, []);

  const value = useMemo(() => ({ state, tick, lastEventAt, subscribe }), [state, tick, lastEventAt, subscribe]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useRealtime(): RealtimeValue {
  return useContext(Ctx);
}
