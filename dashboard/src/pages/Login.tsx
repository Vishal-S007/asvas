import { useState } from "react";
import { api, ApiError, tokenStore } from "../api";
import { useResource } from "../hooks";

interface DevUser { email: string; display_name: string; role: string; tenant: string }

export function LoginPage({ onLogin }: { onLogin: () => void }) {
  const users = useResource<DevUser[]>("/auth/dev-users");
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
      <p className="muted">Autonomous Security Validation — milestone 1 development build.</p>
      <div className="card">
        <h2>Development sign-in</h2>
        <p className="small muted">Enterprise SSO (OIDC + MFA) is not implemented yet (requirement CP-07). This sign-in exists only when the
          control plane runs with <code>ASVAS_ENV=development</code>.</p>
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
        {err && <div className="state error" role="alert">{err}</div>}
      </div>
    </div>
  );
}
