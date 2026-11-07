import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies /api to the local control plane so tokens never cross origins.
// With TLS enabled (scripts/dev-up.sh), the API is https and Node must trust the dev CA:
// NODE_EXTRA_CA_CERTS=../var/certs/ca.crt ASVAS_API_URL=https://localhost:8000 npm run dev
export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", port: 5173, proxy: { "/api": { target: process.env.ASVAS_API_URL ?? "http://127.0.0.1:8000", secure: true, changeOrigin: true } } },
});
