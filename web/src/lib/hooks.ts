"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "./api";
import { useRealtime } from "./realtime";

export interface Query<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  reload: () => void;
}

/** GET `path`; refetches when `path` changes and, with `live`, whenever a realtime event arrives. */
export function useApi<T>(path: string | null, opts: { live?: boolean } = {}): Query<T> {
  const { tick } = useRealtime();
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(path !== null);
  const [manual, setManual] = useState(0);
  const seq = useRef(0);
  const liveTick = opts.live ? tick : 0;

  useEffect(() => {
    if (path === null) return;
    const mine = ++seq.current;
    api<T>(path)
      .then((d) => {
        if (mine !== seq.current) return;
        setData(d);
        setError(null);
      })
      .catch((e: unknown) => {
        if (mine !== seq.current) return;
        setError(e instanceof ApiError ? e : new ApiError(0, "network", "Cannot reach the server."));
      })
      .finally(() => {
        if (mine === seq.current) setLoading(false);
      });
  }, [path, liveTick, manual]);

  const reload = useCallback(() => setManual((n) => n + 1), []);
  return { data, error, loading, reload };
}
