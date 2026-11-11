import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// En dev, /api/* est relayé vers le backend FastAPI : pas besoin de CORS.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: process.env.SECPULSE_API ?? "http://127.0.0.1:8000",
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
