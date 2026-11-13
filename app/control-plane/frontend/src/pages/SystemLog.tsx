import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

const SOURCES = [
  "install", "hostd-audit", "siem-hostd", "docker", "nftables", "ssh", "chrony", "unattended-upgrades",
  "opensearch", "vector", "proxy", "api", "dashboards",
] as const;

type Logs = { source: string; lines: string[]; truncated: boolean };

export default function SystemLogPage() {
  const { t } = useTranslation();
  const [source, setSource] = useState<(typeof SOURCES)[number]>("install");
  const [lines, setLines] = useState(500);
  const [query, setQuery] = useState("");
  const [applied, setApplied] = useState("");
  const q = useQuery({
    queryKey: ["syslog", source, lines, applied],
    queryFn: () =>
      api<Logs>("GET", `/api/system/logs?${new URLSearchParams({ source, lines: String(lines), query: applied })}`),
  });
  const download = () => {
    if (!q.data) return;
    const url = URL.createObjectURL(new Blob([q.data.lines.join("\n") + "\n"], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `siem-${source}-${new Date().toISOString().slice(0, 19).replace(/:/g, "")}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">{t("nav.syslog")}</h1>
      <div className="mb-3 flex flex-wrap items-end gap-2">
        <div>
          <label className="label" htmlFor="sl-s">{t("syslog.source")}</label>
          <select id="sl-s" className="input" value={source} onChange={(e) => setSource(e.target.value as typeof source)}>
            {SOURCES.map((s) => <option key={s} value={s}>{t(`syslog.sources.${s}`)}</option>)}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="sl-n">{t("syslog.lines")}</label>
          <select id="sl-n" className="input" value={lines} onChange={(e) => setLines(Number(e.target.value))}>
            {[100, 500, 1000, 2000].map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
        </div>
        <form className="flex items-end gap-2" onSubmit={(e) => { e.preventDefault(); setApplied(query); }}>
          <div>
            <label className="label" htmlFor="sl-q">{t("syslog.filter")}</label>
            <input id="sl-q" className="input" maxLength={100} value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <button className="btn">{t("syslog.apply")}</button>
        </form>
        <button className="btn-secondary" onClick={() => q.refetch()}>{t("syslog.refresh")}</button>
        <button className="btn-secondary" disabled={!q.data?.lines.length} onClick={download}>{t("syslog.export")}</button>
      </div>
      <ErrorBox error={q.error} />
      {q.data?.truncated && <p className="mb-2 text-xs text-slate-500">{t("syslog.truncated", { count: lines })}</p>}
      <pre className="card max-h-[70vh] overflow-auto whitespace-pre-wrap break-all font-mono text-xs">
        {q.data && (q.data.lines.length ? q.data.lines.join("\n") : t("syslog.empty"))}
      </pre>
    </div>
  );
}
