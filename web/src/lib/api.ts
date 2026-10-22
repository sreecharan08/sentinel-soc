import { API_URL } from "./config";
import type { User } from "./types";

export interface Session {
  access: string;
  refresh: string;
  user: User;
}

const KEY = "sentinel.session";
let session: Session | null = null;
let loaded = false;
let refreshing: Promise<boolean> | null = null;
const listeners = new Set<() => void>();

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details: unknown = {},
  ) {
    super(message);
  }
}

function load(): Session | null {
  if (!loaded && typeof window !== "undefined") {
    loaded = true;
    try {
      const raw = window.localStorage.getItem(KEY);
      session = raw ? (JSON.parse(raw) as Session) : null;
    } catch {
      session = null;
    }
  }
  return session;
}

export function getSession(): Session | null {
  return load();
}

export function setSession(next: Session | null): void {
  session = next;
  loaded = true;
  try {
    if (next) window.localStorage.setItem(KEY, JSON.stringify(next));
    else window.localStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: the session lives for this tab only */
  }
  listeners.forEach((fn) => fn());
}

export function onSessionChange(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

function jwtExpiry(token: string): number {
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))) as { exp: number };
    return payload.exp * 1000;
  } catch {
    return 0;
  }
}

async function refreshAccess(): Promise<boolean> {
  const current = load();
  if (!current) return false;
  if (!refreshing) {
    refreshing = (async () => {
      try {
        const res = await fetch(`${API_URL}/api/v1/auth/refresh/`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh: current.refresh }),
        });
        if (!res.ok) return false;
        const body = (await res.json()) as { access: string; refresh?: string };
        setSession({ ...current, access: body.access, refresh: body.refresh ?? current.refresh });
        return true;
      } catch {
        return false;
      } finally {
        refreshing = null;
      }
    })();
  }
  return refreshing;
}

/** A valid access token, refreshing it first when it is about to expire. Null when signed out. */
export async function freshAccessToken(): Promise<string | null> {
  const current = load();
  if (!current) return null;
  if (jwtExpiry(current.access) - Date.now() < 30_000) {
    if (!(await refreshAccess())) {
      setSession(null);
      return null;
    }
  }
  return load()?.access ?? null;
}

async function parseError(res: Response): Promise<ApiError> {
  try {
    const body = (await res.json()) as { error?: { code: string; message: string; details?: unknown } };
    if (body.error) return new ApiError(res.status, body.error.code, body.error.message, body.error.details);
  } catch {
    /* non-JSON error body */
  }
  return new ApiError(res.status, "http_error", `Request failed (${res.status})`);
}

export async function login(username: string, password: string): Promise<Session> {
  const res = await fetch(`${API_URL}/api/v1/auth/token/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw await parseError(res);
  const next = (await res.json()) as Session;
  setSession(next);
  return next;
}

export function logout(): void {
  setSession(null);
}

export async function api<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const url = `${API_URL}/api/v1${path}`;
  const send = async () => {
    const token = await freshAccessToken();
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    if (init.body !== undefined) headers["Content-Type"] = "application/json";
    return fetch(url, {
      method: init.method ?? "GET",
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
  };
  let res = await send();
  if (res.status === 401) {
    if (await refreshAccess()) res = await send();
  }
  if (res.status === 401) {
    setSession(null);
    throw await parseError(res);
  }
  if (!res.ok) throw await parseError(res);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}
