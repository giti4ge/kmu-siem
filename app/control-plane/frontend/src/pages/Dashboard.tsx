import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, type Me } from "../api";

type Kv = { key: string; count: number };
type Data = {
  alerts: { open: Record<string, number> };
  areas: Record<string, "ok" | "warn" | "critical">;
  top_blocked: Kv[]; failed_logons: Kv[]; failed_sources: Kv[];
  volume: Record<string, number>; unparsed_sources: number;
  disk: { percent: number; level: string } | null; errors: string[];
};

const AREAS = ["perimeter", "windows", "servers", "network", "endpoints"];
const WIDGETS = ["areas", "alerts", "blocked", "logons", "volume", "health"] as const;
const LIGHT: Record<string, string> = { ok: "bg-green-500", warn: "bg-yellow-400", critical: "bg-red-600" };
const SEV = ["critical", "high", "medium", "low"];

function List({ rows }: { rows: Kv[] }) {
  const { t } = useTranslation();
  if (!rows.length) return <p className="text-sm text-slate-500">{t("dashboard.none")}</p>;
  return (
    <ul className="text-sm">
      {rows.map((r) => (
        <li key={r.key} className="flex justify-between border-b border-slate-100 py-0.5">
          <span className="font-mono">{r.key}</span><span className="text-slate-500">{r.count}</span>
        </li>
      ))}
    </ul>
  );
}

export default function Dashboard({ me }: { me: Me }) {
  const { t } = useTranslation();
  const storeKey = `siem.dashboard.${me.user.username}`;
  const [hidden, setHidden] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(storeKey) ?? "[]"); } catch { return []; }
  });
  const [edit, setEdit] = useState(false);
  const toggle = (w: string) => {
    const next = hidden.includes(w) ? hidden.filter((x) => x !== w) : [...hidden, w];
    setHidden(next);
    localStorage.setItem(storeKey, JSON.stringify(next));
  };
  const show = (w: string) => !hidden.includes(w);
  const q = useQuery({ queryKey: ["dashboard"], queryFn: () => api<Data>("GET", "/api/dashboard"), refetchInterval: 60000 });
  const d = q.data;
  const info = useQuery({
    queryKey: ["system-info"],
    queryFn: () => api<{ version: string }>("GET", "/api/system/info"),
    enabled: me.permissions.includes("system:read"),
  });
  return (
    <div className="max-w-6xl">
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold">{t("nav.dashboard")}</h1>
        <button className="btn-secondary" onClick={() => setEdit(!edit)}>{t("dashboard.customize")}</button>
      </div>
      {edit && (
        <div className="card mb-4 flex flex-wrap gap-4 text-sm">
          {WIDGETS.map((w) => (
            <label key={w} className="flex items-center gap-1">
              <input type="checkbox" checked={show(w)} onChange={() => toggle(w)} />{t(`dashboard.w.${w}`)}
            </label>
          ))}
        </div>
      )}
      {d?.errors.length ? <p className="card mb-4 text-sm text-red-700">{t("dashboard.unavailable")}</p> : null}
      <div className="grid gap-4 md:grid-cols-2">
        {show("areas") && (
          <section className="card md:col-span-2">
            <h2 className="mb-2 font-medium">{t("dashboard.w.areas")}</h2>
            <div className="flex flex-wrap gap-6">
              {AREAS.map((a) => (
                <div key={a} className="flex items-center gap-2 text-sm">
                  <span className={`inline-block h-4 w-4 rounded-full ${LIGHT[d?.areas[a] ?? "ok"]}`} aria-hidden />
                  <span>{t(`dashboard.area.${a}`)}</span>
                  <span className="text-slate-500">{t(`dashboard.state.${d?.areas[a] ?? "ok"}`)}</span>
                </div>
              ))}
            </div>
          </section>
        )}
        {show("alerts") && (
          <section className="card">
            <h2 className="mb-2 font-medium">{t("dashboard.w.alerts")}</h2>
            <div className="flex gap-4">
              {SEV.map((s) => (
                <div key={s} className="text-center">
                  <div className="text-2xl font-semibold">{d?.alerts.open[s] ?? 0}</div>
                  <div className="text-xs text-slate-500">{t(`alerts.sev.${s}`)}</div>
                </div>
              ))}
            </div>
          </section>
        )}
        {show("health") && (
          <section className="card">
            <h2 className="mb-2 font-medium">{t("dashboard.w.health")}</h2>
            <p className="text-sm">{t("dashboard.disk")}: {d?.disk ? `${d.disk.percent} %` : "–"}</p>
            <p className="text-sm">{t("dashboard.new_sources")}: {d?.unparsed_sources ?? 0}</p>
            {info.data && <p className="mt-2 text-xs text-slate-500">{t("dashboard.version", { version: info.data.version })}</p>}
          </section>
        )}
        {show("blocked") && (
          <section className="card"><h2 className="mb-2 font-medium">{t("dashboard.w.blocked")}</h2><List rows={d?.top_blocked ?? []} /></section>
        )}
        {show("logons") && (
          <section className="card">
            <h2 className="mb-2 font-medium">{t("dashboard.w.logons")}</h2>
            <List rows={d?.failed_logons ?? []} />
            <div className="mt-2"><List rows={d?.failed_sources ?? []} /></div>
          </section>
        )}
        {show("volume") && (
          <section className="card md:col-span-2">
            <h2 className="mb-2 font-medium">{t("dashboard.w.volume")}</h2>
            <List rows={Object.entries(d?.volume ?? {}).map(([key, count]) => ({ key, count }))} />
          </section>
        )}
      </div>
    </div>
  );
}
