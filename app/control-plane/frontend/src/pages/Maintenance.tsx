import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Job = { at: string; ok: boolean; detail: unknown } | null;
type Data = {
  jobs: Record<string, Job>;
  window: { start: number; end: number };
  thresholds: { warn: number; emergency: number; target: number };
  keep: { db_backups: number; snapshots: number };
};

async function downloadDiagnostics() {
  const pkg = await api<unknown>("GET", "/api/system/diagnostics");
  const url = URL.createObjectURL(new Blob([JSON.stringify(pkg, null, 2)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `diagnose-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

type Upd = { current: string; config: { repo: string; channel: string; has_token: boolean; last_check: string | null; latest: { version: string; name: string; notes: string; url: string } | null } };

function Updates({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["updates"], queryFn: () => api<Upd>("GET", "/api/updates") });
  const check = useMutation({ mutationFn: () => api("POST", "/api/updates/check"), onSettled: () => qc.invalidateQueries({ queryKey: ["updates"] }) });
  const d = q.data;
  return (
    <section className="card mt-4">
      <h2 className="mb-1 font-medium">{t("maintenance.upd_title")}</h2>
      <ErrorBox error={q.error ?? check.error} />
      <p className="text-sm">{t("maintenance.upd_current", { version: d?.current ?? "" })} ({d?.config.channel}, {d?.config.repo})</p>
      {d?.config.latest ? (
        <div className="mt-1 rounded bg-green-50 p-2 text-sm">
          <strong>{t("maintenance.upd_available", { version: d.config.latest.version })}</strong>
          <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap text-xs">{d.config.latest.notes}</pre>
          <p className="mt-1 text-xs text-slate-600">{t("maintenance.upd_howto")}</p>
        </div>
      ) : d?.config.last_check ? <p className="text-sm text-slate-600">{t("maintenance.upd_uptodate")}</p> : null}
      {canWrite && <button className="btn-secondary mt-2" disabled={check.isPending} onClick={() => check.mutate()}>{t("maintenance.upd_check")}</button>}
    </section>
  );
}

type Sup = { active: boolean; until: number | null; from: string | null; by: string | null; max_hours: number };

function Support({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["support"], queryFn: () => api<Sup>("GET", "/api/support"), refetchInterval: 30000 });
  const [key, setKey] = useState("");
  const [hours, setHours] = useState(4);
  const [source, setSource] = useState("");
  const done = (d: Sup) => qc.setQueryData(["support"], d);
  const enable = useMutation({ mutationFn: () => api<Sup>("POST", "/api/support/enable", { key, hours, source }), onSuccess: (d) => { done(d); setKey(""); } });
  const disable = useMutation({ mutationFn: () => api<Sup>("POST", "/api/support/disable"), onSuccess: done });
  const d = q.data;
  return (
    <section className="card mt-4">
      <h2 className="mb-1 font-medium">{t("support.title")}</h2>
      <p className="mb-2 text-sm text-slate-600">{t("support.intro")}</p>
      <ErrorBox error={q.error ?? enable.error ?? disable.error} />
      {d?.active ? (
        <div className="rounded bg-yellow-50 p-2 text-sm">
          {t("support.active", { until: new Date((d.until ?? 0) * 1000).toLocaleString(), from: d.from })}
          {canWrite && <button className="btn-secondary ml-3" disabled={disable.isPending} onClick={() => disable.mutate()}>{t("support.disable")}</button>}
        </div>
      ) : canWrite && (
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2"><label className="label" htmlFor="sp-k">{t("support.key")}</label><textarea id="sp-k" className="input font-mono text-xs" rows={2} value={key} onChange={(e) => setKey(e.target.value)} /></div>
          <div><label className="label" htmlFor="sp-s">{t("support.source")}</label><input id="sp-s" className="input" value={source} onChange={(e) => setSource(e.target.value)} /></div>
          <div><label className="label" htmlFor="sp-h">{t("support.hours")}</label><input id="sp-h" className="input w-24" type="number" min={1} max={d?.max_hours ?? 72} value={hours} onChange={(e) => setHours(Number(e.target.value))} /></div>
          <div><button className="btn" disabled={!key || !source || enable.isPending} onClick={() => enable.mutate()}>{t("support.enable")}</button></div>
        </div>
      )}
      {!d?.active && !canWrite && <p className="text-sm text-slate-500">{t("support.inactive")}</p>}
    </section>
  );
}

const JOBS = ["guard", "db_backup", "db_integrity", "snapshot"];

function summary(job: string, d: unknown): string {
  if (!d || typeof d !== "object") return String(d ?? "");
  const o = d as Record<string, unknown>;
  if (job === "guard") return `${o.percent} %`;
  if (job === "db_backup") return String(o.file ?? "");
  if (job === "snapshot") return String(o.snapshot ?? "");
  return String(o.result ?? "");
}

export default function MaintenancePage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["maintenance"], queryFn: () => api<Data>("GET", "/api/maintenance"), refetchInterval: 30000 });
  const run = useMutation({
    mutationFn: (job: string) => api("POST", `/api/maintenance/run/${job}`),
    onSettled: () => qc.invalidateQueries({ queryKey: ["maintenance"] }),
  });
  const d = q.data;
  return (
    <div className="max-w-3xl">
      <h1 className="mb-1 text-xl font-semibold">{t("maintenance.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">
        {d && t("maintenance.intro", { start: d.window.start, end: d.window.end, warn: d.thresholds.warn, emergency: d.thresholds.emergency })}
      </p>
      <ErrorBox error={q.error ?? run.error} />
      <section className="card">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b text-slate-500">
              <th className="py-1">{t("maintenance.job")}</th>
              <th>{t("maintenance.last")}</th>
              <th>{t("maintenance.result")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {JOBS.map((j) => {
              const s = d?.jobs[j] ?? null;
              return (
                <tr key={j} className="border-b border-slate-100">
                  <td className="py-1">{t(`maintenance.jobs.${j}`)}</td>
                  <td>{s ? new Date(s.at).toLocaleString() : t("maintenance.never")}</td>
                  <td className={s && !s.ok ? "text-red-700" : ""}>{s ? `${s.ok ? t("maintenance.ok") : t("maintenance.failed")} – ${summary(j, s.detail)}` : "–"}</td>
                  <td>
                    {canWrite && (
                      <button className="btn" disabled={run.isPending} onClick={() => run.mutate(j)}>{t("maintenance.run")}</button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
      <section className="card mt-4">
        <h2 className="mb-1 font-medium">{t("maintenance.diag_title")}</h2>
        <p className="mb-2 text-sm text-slate-600">{t("maintenance.diag_intro")}</p>
        <button className="btn" onClick={() => downloadDiagnostics()}>{t("maintenance.diag_button")}</button>
      </section>
      <Updates canWrite={canWrite} />
      <Support canWrite={canWrite} />
    </div>
  );
}
