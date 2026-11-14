import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
    </div>
  );
}
