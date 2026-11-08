import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// SR-5 (security review 2026-11-08): the production build carries a strict Content-Security-Policy, so an
// injected script cannot run and read the bearer token from sessionStorage. The OIDC issuer origin is the only
// other origin the page may talk to (token exchange) or navigate a form to. Set ASVAS_OIDC_ORIGIN at build time,
// e.g. ASVAS_OIDC_ORIGIN=https://sso.example.com npm run build. The dev server is exempt (Vite needs inline scripts).
function csp(): Plugin {
  const idp = process.env.ASVAS_OIDC_ORIGIN ?? "https://localhost:8443";
  const policy = [
    "default-src 'self'", "script-src 'self'", "style-src 'self' 'unsafe-inline'", "img-src 'self' data:",
    `connect-src 'self' ${idp}`, `form-action 'self' ${idp}`, "object-src 'none'", "base-uri 'none'",
  ].join("; ");
  return {
    name: "asvas-csp", apply: "build",
    transformIndexHtml: (html) => html.replace("<head>", `<head>\n    <meta http-equiv="Content-Security-Policy" content="${policy}" />`),
  };
}

// The dev server proxies /api to the local control plane so tokens never cross origins.
// With TLS enabled (scripts/dev-up.sh), the API is https and Node must trust the dev CA:
// NODE_EXTRA_CA_CERTS=../var/certs/ca.crt ASVAS_API_URL=https://localhost:8000 npm run dev
export default defineConfig({
  plugins: [react(), csp()],
  server: { host: "127.0.0.1", port: 5173, proxy: { "/api": { target: process.env.ASVAS_API_URL ?? "http://127.0.0.1:8000", secure: true, changeOrigin: true } } },
  preview: { host: "127.0.0.1", port: 4173, proxy: { "/api": { target: process.env.ASVAS_API_URL ?? "http://127.0.0.1:8000", secure: true, changeOrigin: true } } },
});
