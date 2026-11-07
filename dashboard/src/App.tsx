import { createContext, useContext, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router";
import { completeLogin, getAuthConfig, logoutUrl, REAUTH_KEY } from "./oidc";
import { api, ApiError, rank, tokenStore, type Me, type Role } from "./api";
import { AssessmentsPage } from "./pages/Assessments";
import { NewAssessmentPage } from "./pages/NewAssessment";
import { AssessmentDetailPage } from "./pages/AssessmentDetail";
import { ApprovalsPage } from "./pages/Approvals";
import { SystemPage } from "./pages/System";
import { AuditPage } from "./pages/Audit";
import { LoginPage } from "./pages/Login";
import { EmergencyStopButton } from "./pages/System";
import { ControlsPage } from "./pages/Controls";
import { loadPersona, PersonaCtx, savePersona, type Persona } from "./persona";

const MeCtx = createContext<Me | null>(null);
export const useMe = () => useContext(MeCtx)!;
export const can = (me: Me, role: Role) => rank[me.role] >= rank[role];

export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [checked, setChecked] = useState(false);
  const [persona, setPersona] = useState<Persona>("advanced");
  useEffect(() => { if (me) setPersona(loadPersona(me.user_id)); }, [me]);
  const nav = useNavigate();
  const loc = useLocation();
  const [authErr, setAuthErr] = useState<string>();
  const refresh = async () => {
    if (!tokenStore.get()) { setMe(null); setChecked(true); return; }
    try { setMe(await api<Me>("/me")); } catch (e) { if (e instanceof ApiError && e.status === 401) setMe(null); }
    setChecked(true);
  };
  useEffect(() => {
    if (loc.pathname === "/auth/callback") {
      completeLogin()
        .then(async () => {
          try { setMe(await api<Me>("/me")); setChecked(true); nav("/assessments", { replace: true }); }
          catch (e) {
            tokenStore.clear();
            sessionStorage.setItem(REAUTH_KEY, "1");
            const t = e instanceof ApiError ? e.title : String(e);
            throw new Error(t.includes("multi-factor") ? "Authenticator registered. For security, sign in once more using a code from your authenticator app." : t);
          }
        })
        .catch((e) => { setAuthErr(String(e instanceof Error ? e.message : e)); setChecked(true); nav("/", { replace: true }); });
    } else void refresh();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const signOut = async () => {
    tokenStore.clear(); setMe(null);
    try { const c = await getAuthConfig(); if (c.oidc && sessionStorage.getItem("asvas.oidc.id_token")) {
      const u = logoutUrl(c.oidc); sessionStorage.removeItem("asvas.oidc.id_token"); location.assign(u); } } catch { /* local sign-out only */ }
  };
  if (!checked) return <div className="state loading"><span className="spinner" /> Loading…</div>;
  if (!me) return <>{authErr && <div className="state error" role="alert">{authErr}</div>}
    <LoginPage onLogin={async () => { await refresh(); nav("/assessments"); }} /></>;
  return (
    <MeCtx.Provider value={me}>
     <PersonaCtx.Provider value={{ persona, set: (p) => { setPersona(p); savePersona(me.user_id, p); } }}>
      <div className="shell">
        <aside className="sidebar">
          <div className="brand">ASVAS<small>M3 dev build · not production-ready</small></div>
          <nav>
            <NavLink to="/assessments">Assessments</NavLink>
            <NavLink to="/approvals">Approval queue</NavLink>
            <NavLink to="/system">Workers &amp; policy</NavLink>
            <NavLink to="/audit">Audit history</NavLink>
            {(me.role === "auditor" || me.role === "admin") && <NavLink to="/controls">Controls</NavLink>}
          </nav>
          <div className="persona" role="group" aria-label="View mode">
            <span className="small muted">View</span>
            {(["simple", "advanced"] as const).map((p) => <button key={p} className={`btn small ${persona === p ? "primary" : ""}`}
              aria-pressed={persona === p} onClick={() => { setPersona(p); savePersona(me.user_id, p); }}>{p === "simple" ? "Simplified" : "Advanced"}</button>)}
          </div>
          <div className="whoami">
            <div>{me.display_name}</div>
            <div className="muted small">{me.email} · <b>{me.role}</b></div>
            <button className="link" onClick={() => void signOut()}>Sign out</button>
          </div>
        </aside>
        <main>
          <header className="topbar">
            <span className="muted small">Authorized, non-destructive testing only. All results come from the control plane.</span>
            <EmergencyStopButton />
          </header>
          <Routes>
            <Route path="/" element={<Navigate to="/assessments" replace />} />
            <Route path="/assessments" element={<AssessmentsPage />} />
            <Route path="/assessments/new" element={<NewAssessmentPage />} />
            <Route path="/assessments/:id" element={<AssessmentDetailPage />} />
            <Route path="/approvals" element={<ApprovalsPage />} />
            <Route path="/system" element={<SystemPage />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/controls" element={<ControlsPage />} />
            <Route path="*" element={<div className="state">Page not found.</div>} />
          </Routes>
        </main>
      </div>
     </PersonaCtx.Provider>
    </MeCtx.Provider>
  );
}
