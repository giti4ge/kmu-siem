import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { readFileSync } from "node:fs";
import { defineConfig } from "vite";

// Version und Release-Datum (erster datierter Abschnitt im CHANGELOG) für die Fußzeile
const root = new URL("../../../", import.meta.url);
const version = readFileSync(new URL("VERSION", root), "utf-8").trim();
const date = /^## \[[^\]]+\] – (\d{4}-\d{2}-\d{2})/m.exec(readFileSync(new URL("CHANGELOG.md", root), "utf-8"))?.[1] ?? "";

// Ausgabe direkt in das vom Proxy ausgelieferte Verzeichnis (app/proxy/html)
export default defineConfig({
  define: { __APP_VERSION__: JSON.stringify(version), __APP_DATE__: JSON.stringify(date) },
  plugins: [react(), tailwindcss()],
  build: { outDir: "../../proxy/html", emptyOutDir: true, sourcemap: false },
  server: { proxy: { "/api": "http://127.0.0.1:8000" } },
});
