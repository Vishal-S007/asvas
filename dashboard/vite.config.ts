import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies /api to the local control plane so tokens never cross origins.
export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", port: 5173, proxy: { "/api": "http://127.0.0.1:8000" } },
});
