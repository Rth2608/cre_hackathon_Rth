import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiProxyTarget = process.env.VITE_API_PROXY_TARGET || "http://127.0.0.1:8787";
const extraAllowedHosts = (process.env.VITE_ALLOWED_HOSTS || "")
  .split(",")
  .map((item) => item.trim())
  .filter(Boolean);
const allowedHosts = ["localhost", "127.0.0.1", ".trycloudflare.com", ...extraAllowedHosts];

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    allowedHosts,
    proxy: {
      "/api": {
        target: apiProxyTarget,
        changeOrigin: true
      },
      "/healthz": {
        target: apiProxyTarget,
        changeOrigin: true
      }
    }
  }
});
