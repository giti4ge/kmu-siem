import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Alert = {
  id: string; index: string; time: string; rule: string; severity: string; status: string; group: string;
  group_by: string; count: number; last_seen: string; summary: string; sample: string; mitre: string[];
  description: string; ack_by?: string;
};
type Rule = {
  id: string; name: string; severity: string; description: string; threshold: number; window_minutes: number;
  enabled: boolean; mitre: string[]; category: string;
};

const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-100 text-red-800", high: "bg-orange-100 text-orange-800",
  medium: "bg-yellow-100 text-yellow-800", low: "bg-slate-100 text-slate-700",
};

export default function AlertsPage({ canWrite, canRules }: { canWrite: boolean; canRules: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [status, setStatus] = useState("open");
  const [tab, setTab] = useState<"alerts" | "rules">("alerts");
  const q = useQuery({
    queryKey: ["alerts", status],
    queryFn: () => api<{ alerts: Alert[] }>("GET", `/api/alerts?hours=720${status ? `&status=${status}` : ""}`),
    refetchInterval: 30000,
  });
  const rules = useQuery({ queryKey: ["rules"], queryFn: () => api<{ rules: Rule[] }>("GET", "/api/alerts/rules"), enabled: tab === "rules" });
  const set = useMutation({
    mutationFn: (v: { a: Alert; status: string }) => api("POST", `/api/alerts/${v.a.id}/status`, { status: v.status, index: v.a.index }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["alerts"] }),
  });
  const upd = useMutation({
    mutationFn: (v: { id: string; body: Record<string, unknown> }) => api<{ rules: Rule[] }>("PUT", `/api/alerts/rules/${v.id}`, v.body),
    onSuccess: (d) => qc.setQueryData(["rules"], d),
  });

  return (
    <div className="max-w-5xl">
      <h1 className="mb-1 text-xl font-semibold">{t("alerts.title")}</h1>
      <div className="mb-3 flex gap-2" role="tablist">
        <button className={tab === "alerts" ? "btn" : "btn-secondary"} onClick={() => setTab("alerts")}>{t("alerts.tab_alerts")}</button>
        {canRules && <button className={tab === "rules" ? "btn" : "btn-secondary"} onClick={() => setTab("rules")}>{t("alerts.tab_rules")}</button>}
      </div>
      <ErrorBox error={q.error ?? set.error ?? upd.error ?? rules.error} />
      {tab === "alerts" && (
        <>
          <div className="mb-3 flex items-end gap-2">
            <div>
              <label className="label" htmlFor="al-st">{t("alerts.status")}</label>
              <select id="al-st" className="input" value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="">{t("alerts.all")}</option>
                {["open", "acknowledged", "closed"].map((s) => <option key={s} value={s}>{t(`alerts.st.${s}`)}</option>)}
              </select>
            </div>
          </div>
          {q.data && q.data.alerts.length === 0 && <p className="card text-sm text-slate-600">{t("alerts.empty")}</p>}
          {q.data?.alerts.map((a) => (
            <div key={a.id} className="card mb-3">
              <div className="flex flex-wrap items-baseline gap-x-3 text-sm">
                <span className={`rounded px-2 py-0.5 text-xs font-medium ${SEV_CLASS[a.severity] ?? ""}`}>{t(`alerts.sev.${a.severity}`)}</span>
                <span className="font-medium">{a.rule}</span>
                {a.group && <span className="font-mono text-slate-600">{a.group}</span>}
                <span className="text-slate-500">{t("alerts.count", { count: a.count })}</span>
                <span className="text-slate-500">{a.last_seen}</span>
                <span className="text-slate-500">{t(`alerts.st.${a.status}`)}{a.ack_by ? ` (${a.ack_by})` : ""}</span>
              </div>
              <p className="mt-1 text-sm text-slate-700">{a.description}</p>
              {a.mitre?.length > 0 && <p className="text-xs text-slate-500">MITRE ATT&amp;CK: {a.mitre.join(", ")}</p>}
              {a.sample && <pre className="mt-1 max-h-24 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-slate-600">{a.sample}</pre>}
              {canWrite && (
                <div className="mt-2 flex gap-2">
                  {a.status === "open" && <button className="btn-secondary" onClick={() => set.mutate({ a, status: "acknowledged" })}>{t("alerts.ack")}</button>}
                  {a.status !== "closed" && <button className="btn-secondary" onClick={() => set.mutate({ a, status: "closed" })}>{t("alerts.close")}</button>}
                  {a.status === "closed" && <button className="btn-secondary" onClick={() => set.mutate({ a, status: "open" })}>{t("alerts.reopen")}</button>}
                </div>
              )}
            </div>
          ))}
        </>
      )}
      {tab === "rules" && (
        <section className="card">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b text-slate-500">
                <th className="py-1">{t("alerts.rule")}</th><th>{t("alerts.severity")}</th><th>{t("alerts.threshold")}</th><th>{t("alerts.enabled")}</th>
              </tr>
            </thead>
            <tbody>
              {rules.data?.rules.map((r) => (
                <tr key={r.id} className="border-b border-slate-100 align-top">
                  <td className="py-1"><div className="font-medium">{r.name}</div><div className="text-xs text-slate-500">{r.description}</div></td>
                  <td>
                    <select className="input" value={r.severity} disabled={!canWrite} aria-label={t("alerts.severity")}
                      onChange={(e) => upd.mutate({ id: r.id, body: { severity: e.target.value } })}>
                      {["low", "medium", "high", "critical"].map((s) => <option key={s} value={s}>{t(`alerts.sev.${s}`)}</option>)}
                    </select>
                  </td>
                  <td>
                    <input className="input w-20" type="number" min={1} defaultValue={r.threshold} disabled={!canWrite} aria-label={t("alerts.threshold")}
                      onBlur={(e) => { const v = Number(e.target.value); if (v >= 1 && v !== r.threshold) upd.mutate({ id: r.id, body: { threshold: v } }); }} />
                    <span className="ml-1 text-xs text-slate-500">/ {r.window_minutes} min</span>
                  </td>
                  <td><input type="checkbox" checked={r.enabled} disabled={!canWrite} aria-label={t("alerts.enabled")}
                    onChange={(e) => upd.mutate({ id: r.id, body: { enabled: e.target.checked } })} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
