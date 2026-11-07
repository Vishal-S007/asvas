// UI-03: persona modes. "simple" (junior operator / sysadmin): prioritised fixes in plain language and a
// one-click verification. "advanced" (security architect): plan graph, raw job logs, policy source, hashes.
// The choice is a per-browser display preference only; it never changes what the server allows.
import { createContext, useContext } from "react";

export type Persona = "simple" | "advanced";
const KEY = (uid: string) => `asvas.persona.${uid}`;

export function loadPersona(uid: string): Persona {
  try { return localStorage.getItem(KEY(uid)) === "simple" ? "simple" : "advanced"; } catch { return "advanced"; }
}
export function savePersona(uid: string, p: Persona) {
  try { localStorage.setItem(KEY(uid), p); } catch { /* preference only */ }
}

export const PersonaCtx = createContext<{ persona: Persona; set: (p: Persona) => void }>({ persona: "advanced", set: () => {} });
export const usePersona = () => useContext(PersonaCtx);

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const bySeverity = <T extends { severity: string; verification_status: string }>(xs: T[]) =>
  [...xs].sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9)
    || Number(a.verification_status !== "confirmed") - Number(b.verification_status !== "confirmed"));
