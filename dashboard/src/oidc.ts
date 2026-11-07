// CP-07: OIDC authorization-code flow with PKCE (S256) for the public dashboard client.
// The verifier/state live in sessionStorage only for the round trip; the access token is kept in sessionStorage
// (cleared when the tab closes). Token validation is done by the API (JWKS, issuer, audience, MFA claim).
import { tokenStore } from "./api";

export interface OidcConfig { issuer: string; client_id: string; authorization_endpoint: string; token_endpoint: string;
  end_session_endpoint: string; scope: string }
export interface AuthConfig { oidc: OidcConfig | null; dev_login: boolean; mfa_required: boolean }

const PKCE_KEY = "asvas.oidc.pkce";
export const REAUTH_KEY = "asvas.oidc.reauth";
const b64url = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const rand = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));
const redirectUri = () => `${location.origin}/auth/callback`;

export async function getAuthConfig(): Promise<AuthConfig> {
  const r = await fetch("/api/v1/auth/config");
  if (!r.ok) throw new Error(`control plane unreachable (HTTP ${r.status})`);
  return r.json();
}

export async function beginLogin(c: OidcConfig) {
  const verifier = rand(48), state = rand(16), nonce = rand(16);
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  sessionStorage.setItem(PKCE_KEY, JSON.stringify({ verifier, state, nonce, token_endpoint: c.token_endpoint, client_id: c.client_id }));
  const q = new URLSearchParams({ client_id: c.client_id, response_type: "code", scope: c.scope, redirect_uri: redirectUri(),
    state, nonce, code_challenge: challenge, code_challenge_method: "S256" });
  // After an MFA refusal, force a fresh interactive login (the IdP session cookie would otherwise re-issue
  // a token without a second factor).
  if (sessionStorage.getItem(REAUTH_KEY)) { q.set("prompt", "login"); sessionStorage.removeItem(REAUTH_KEY); }
  location.assign(`${c.authorization_endpoint}?${q}`);
}

export async function completeLogin(): Promise<void> {
  const p = new URLSearchParams(location.search);
  const saved = JSON.parse(sessionStorage.getItem(PKCE_KEY) ?? "null");
  sessionStorage.removeItem(PKCE_KEY);
  if (p.get("error")) throw new Error(`sign-in failed: ${p.get("error_description") ?? p.get("error")}`);
  if (!saved || !p.get("code") || p.get("state") !== saved.state) throw new Error("sign-in response did not match this browser session (state mismatch)");
  const r = await fetch(saved.token_endpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: p.get("code")!, redirect_uri: redirectUri(),
      client_id: saved.client_id, code_verifier: saved.verifier }) });
  if (!r.ok) throw new Error(`token exchange failed (HTTP ${r.status})`);
  const t = await r.json();
  tokenStore.set(t.access_token);
  if (t.id_token) sessionStorage.setItem("asvas.oidc.id_token", t.id_token);
}

export function logoutUrl(c: OidcConfig): string {
  const q = new URLSearchParams({ client_id: c.client_id, post_logout_redirect_uri: `${location.origin}/` });
  const idt = sessionStorage.getItem("asvas.oidc.id_token");
  if (idt) q.set("id_token_hint", idt);
  return `${c.end_session_endpoint}?${q}`;
}
