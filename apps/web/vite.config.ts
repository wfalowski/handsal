import { tanstackRouter } from "@tanstack/router-plugin/vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { defineConfig } from "vite";

const apiTarget = process.env.VITE_API_TARGET ?? "http://localhost:3000";

export default defineConfig({
  plugins: [tanstackRouter({ target: "react", autoCodeSplitting: true }), react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": apiTarget,
      // Regex key: a bare "/t" prefix would also swallow the SPA routes /tenants and /t/:id/*.
      "^/t/[^/]+/(oauth|\\.well-known)": apiTarget,
      "/health": apiTarget,
      "/ready": apiTarget,
      "/instance": apiTarget,
    },
  },
});
