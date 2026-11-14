import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Kv = { key: string; count: number };
type Data = {
  generated: string; days: number; alerts_by_severity: Kv[]; alerts_by_status: Kv[]; top_rules: Kv[];
  alerts_per_day: Kv[]; events_by_category: Kv[]; top_blocked: Kv[]; changes: number;
};

function Table({ title, rows }: { title: string; rows: Kv[] }) {
  const { t } = useTranslation();
  return (
    <section className="card mb-3 break-inside-avoid">
      <h2 className="mb-1 font-medium">{title}</h2>
      {rows.length === 0 ? <p className="text-sm text-slate-500">{t("dashboard.none")}</p> : (
        <ul className="text-sm">{rows.map((r) => <li key={r.key} className="flex justify-between border-b border-slate-100 py-0.5"><span>{r.key}</span><span className="text-slate-500">{r.count}</span></li>)}</ul>
      )}
    </section>
  );
}

async function downloadCsv(days: number) {
  const r = await fetch(`/api/reports/alerts.csv?days=${days}`, { credentials: "same-origin" });
  if (!r.ok) return;
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = "alarme.csv";
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportsPage() {
  const { t } = useTranslation();
  const [days, setDays] = useState(30);
  const q = useQuery({ queryKey: ["report", days], queryFn: () => api<Data>("GET", `/api/reports/summary?days=${days}`) });
  const d = q.data;
  return (
    <div className="max-w-4xl">
      <div className="mb-3 flex items-end justify-between print:hidden">
        <h1 className="text-xl font-semibold">{t("reports.title")}</h1>
        <div className="flex items-end gap-2">
          <div><label className="label" htmlFor="rp-d">{t("reports.period")}</label>
            <select id="rp-d" className="input" value={days} onChange={(e) => setDays(Number(e.target.value))}>
              {[7, 30, 90, 365].map((x) => <option key={x} value={x}>{t("reports.days", { count: x })}</option>)}
            </select></div>
          <button className="btn-secondary" onClick={() => window.print()}>{t("reports.print")}</button>
          <button className="btn-secondary" onClick={() => downloadCsv(days)}>{t("reports.csv")}</button>
        </div>
      </div>
      <ErrorBox error={q.error} />
      {d && (
        <>
          <h1 className="mb-1 hidden text-xl font-semibold print:block">{t("reports.title")} – {t("reports.days", { count: d.days })}</h1>
          <p className="mb-3 text-sm text-slate-500">{t("reports.generated", { at: d.generated })}</p>
          <div className="grid gap-3 md:grid-cols-2">
            <Table title={t("reports.by_severity")} rows={d.alerts_by_severity} />
            <Table title={t("reports.by_status")} rows={d.alerts_by_status} />
            <Table title={t("reports.top_rules")} rows={d.top_rules} />
            <Table title={t("reports.top_blocked")} rows={d.top_blocked} />
            <Table title={t("reports.events")} rows={d.events_by_category} />
            <Table title={t("reports.per_day")} rows={d.alerts_per_day} />
          </div>
          <p className="mt-2 text-sm">{t("reports.changes", { count: d.changes })}</p>
        </>
      )}
    </div>
  );
}
