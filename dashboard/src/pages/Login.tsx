import { useState } from "react";
import { api, ApiError, tokenStore } from "../api";
import { useEffect } from "react";
import { useResource } from "../hooks";
import { beginLogin, getAuthConfig, type AuthConfig } from "../oidc";

interface DevUser { email: string; display_name: string; role: string; tenant: string }

export function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [cfg, setCfg] = useState<AuthConfig>();
  useEffect(() => { getAuthConfig().then(setCfg).catch((e) => setErr(String(e))); }, []);
  const users = useResource<DevUser[]>(cfg?.dev_login ? "/auth/dev-users" : null);
  const [err, setErr] = useState<string>();
  const login = async (email: string) => {
    setErr(undefined);
    try {
      const r = await api<{ access_token: string }>("/auth/dev-login", { method: "POST", body: { email } });
      tokenStore.set(r.access_token);
      onLogin();
    } catch (e) { setErr(e instanceof ApiError ? e.title : String(e)); }
  };
  return (
    <div className="login">
      <h1>ASVAS Console</h1>
      <p className="muted">Autonomous Security Validation — development build (not production-ready).</p>
      {cfg?.oidc && <div className="card">
        <h2>Single sign-on</h2>
        <p className="small muted">Signs in with your organisation's identity provider ({cfg.oidc.issuer}).
          {cfg.mfa_required && " A second factor (authenticator app) is required."}</p>
        <button className="btn primary" onClick={() => void beginLogin(cfg.oidc!)}>Sign in with SSO</button>
      </div>}
      {cfg && !cfg.oidc && !cfg.dev_login && <div className="state error" role="alert">No sign-in method is configured on this server.</div>}
      {cfg?.dev_login && <div className="card">
        <h2>Development sign-in</h2>
        <p className="small muted">Development only: no password, no MFA. This sign-in exists only when the control plane runs with
          <code>ASVAS_ENV=development</code> and is refused in production.</p>
        {users.error ? (
          <div className="state error" role="alert">
            {users.error.status === 404 ? "Development sign-in is disabled on this server, and SSO is unavailable (CP-07)."
              : `Control plane unreachable: ${users.error.title}`}
          </div>
        ) : !users.data ? <div className="state loading"><span className="spinner" /> Loading…</div> : (
          <ul className="userlist">
            {users.data.map((u) => (
              <li key={u.email}><button onClick={() => login(u.email)}>
                <b>{u.display_name}</b> <span className="badge muted">{u.role}</span> <span className="muted small">{u.email} · tenant {u.tenant}</span>
              </button></li>
            ))}
          </ul>
        )}
      </div>}
      {err && <div className="state error" role="alert">{err}</div>}
    </div>
  );
}
