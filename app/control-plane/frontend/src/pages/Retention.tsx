import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Data = {
  min_days: number;
  max_days: number;
  categories: { category: string; days: number | null; daily_bytes: number }[];
  storage: { needed_bytes: number; total_bytes: number; ok: boolean };
};

const gb = (b: number) => (b / 1024 ** 3).toFixed(1);

function PrivacyMode({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["privacy"], queryFn: () => api<{ enabled: boolean }>("GET", "/api/retention/privacy") });
  const set = useMutation({
    mutationFn: (enabled: boolean) => api<{ enabled: boolean }>("PUT", "/api/retention/privacy", { enabled }),
    onSuccess: (d) => qc.setQueryData(["privacy"], d),
  });
  return (
    <section className="card mb-4">
      <h2 className="mb-1 font-medium">{t("privacy.title")}</h2>
      <p className="mb-2 text-sm text-slate-600">{t("privacy.intro")}</p>
      <ErrorBox error={q.error ?? set.error} />
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={q.data?.enabled ?? false} disabled={!canWrite || set.isPending} onChange={(e) => set.mutate(e.target.checked)} />
        {t("privacy.enable")}
      </label>
    </section>
  );
}

export default function RetentionPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["retention"], queryFn: () => api<Data>("GET", "/api/retention") });
  const [days, setDays] = useState<Record<string, string>>({});
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (q.data) setDays(Object.fromEntries(q.data.categories.map((c) => [c.category, c.days ? String(c.days) : ""])));
  }, [q.data]);

  const save = useMutation({
    mutationFn: () =>
      api<Data>("PUT", "/api/retention", {
        days: Object.fromEntries(Object.entries(days).filter(([, v]) => v !== "").map(([k, v]) => [k, Number(v)])),
      }),
    onSuccess: (d) => { setSaved(true); qc.setQueryData(["retention"], d); },
    onError: () => setSaved(false),
  });

  const d = q.data;
  return (
    <div className="max-w-3xl">
      <h1 className="mb-1 text-xl font-semibold">{t("retention.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("retention.intro", { min: d?.min_days ?? 7, max: d?.max_days ?? 730 })}</p>
      <ErrorBox error={q.error ?? save.error} />
      <PrivacyMode canWrite={canWrite} />
      <section className="card mb-4">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b text-slate-500">
              <th className="py-1">{t("retention.category")}</th>
              <th>{t("retention.days")}</th>
              <th>{t("retention.daily")}</th>
            </tr>
          </thead>
          <tbody>
            {d?.categories.map((c) => (
              <tr key={c.category} className="border-b border-slate-100">
                <td className="py-1">{t(`retention.cat.${c.category}`)}</td>
                <td>
                  <input className="input w-24" type="number" min={d.min_days} max={d.max_days} value={days[c.category] ?? ""}
                    aria-label={t("retention.days")} disabled={!canWrite || c.days === null}
                    onChange={(e) => { setSaved(false); setDays({ ...days, [c.category]: e.target.value }); }} />
                </td>
                <td>{(c.daily_bytes / 1024 ** 2).toFixed(1)} {t("retention.mb_day")}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {d && (
          <p className={`mt-3 text-sm ${d.storage.ok ? "text-slate-600" : "text-red-700"}`}>
            {t("retention.estimate", { needed: gb(d.storage.needed_bytes), total: gb(d.storage.total_bytes) })}
          </p>
        )}
        {canWrite && (
          <div className="mt-3 flex items-center gap-3">
            <button className="btn" disabled={save.isPending} onClick={() => save.mutate()}>{t("common.save")}</button>
            {saved && <span className="text-sm text-green-700">{t("retention.saved")}</span>}
          </div>
        )}
      </section>
    </div>
  );
}
