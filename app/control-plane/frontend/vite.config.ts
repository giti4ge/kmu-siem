import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Ausgabe direkt in das vom Proxy ausgelieferte Verzeichnis (app/proxy/html)
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: "../../proxy/html", emptyOutDir: true, sourcemap: false },
  server: { proxy: { "/api": "http://127.0.0.1:8000" } },
});
