"use client";

import { useSyncExternalStore } from "react";
import { getSession, onSessionChange, type Session } from "./api";

/** The signed-in session (null when signed out). `undefined` during server render, before storage is read. */
export function useSession(): Session | null | undefined {
  return useSyncExternalStore(
    onSessionChange,
    () => getSession(),
    () => undefined,
  );
}
