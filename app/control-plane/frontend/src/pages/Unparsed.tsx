import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

async function exportSample(ip: string, program: string) {
  const r = await api<{ lines: string[] }>("GET", `/api/logs/unparsed/sample?ip=${encodeURIComponent(ip)}&program=${encodeURIComponent(program)}&limit=50`);
  const url = URL.createObjectURL(new Blob([r.lines.join("
") + "
"], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `probe-${program || "unbekannt"}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

type Source = {
  ip: string; program: string; count: number; last_seen: string | null; hostname: string | null; samples: string[];
};

export default function UnparsedPage() {
  const { t } = useTranslation();
  const [hours, setHours] = useState(24);
  const q = useQuery({
    queryKey: ["unparsed", hours],
    queryFn: () => api<{ sources: Source[] }>("GET", `/api/logs/unparsed?hours=${hours}`),
  });
  return (
    <div className="max-w-5xl">
      <h1 className="mb-1 text-xl font-semibold">{t("unparsed.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("unparsed.intro")}</p>
      <div className="mb-3 flex items-end gap-2">
        <div>
          <label className="label" htmlFor="up-h">{t("unparsed.period")}</label>
          <select id="up-h" className="input" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            {[1, 24, 168, 720].map((h) => <option key={h} value={h}>{t("unparsed.hours", { count: h })}</option>)}
          </select>
        </div>
        <button className="btn-secondary" onClick={() => q.refetch()}>{t("syslog.refresh")}</button>
      </div>
      <ErrorBox error={q.error} />
      {q.data && q.data.sources.length === 0 && <p className="card text-sm text-slate-600">{t("unparsed.empty")}</p>}
      {q.data?.sources.map((s) => (
        <div key={`${s.ip}|${s.program}`} className="card mb-3">
          <div className="mb-1 flex flex-wrap items-baseline gap-x-4 text-sm">
            <span className="font-mono font-medium">{s.ip}</span>
            {s.hostname && <span>{s.hostname}</span>}
            {s.program && <span className="text-slate-500">{t("unparsed.program")}: {s.program}</span>}
            <span className="text-slate-500">{t("unparsed.count", { count: s.count })}</span>
            {s.last_seen && <span className="text-slate-500">{t("unparsed.last")}: {s.last_seen}</span>}
          </div>
          <button className="btn-secondary mb-2" onClick={() => exportSample(s.ip, s.program)}>{t("unparsed.export")}</button>
          <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-slate-700">
            {s.samples.join("\n")}
          </pre>
        </div>
      ))}
    </div>
  );
}
