import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Status = {
  config: { enabled: boolean; client_id: string; mode: "auto" | "datalake" | "siem"; has_secret: boolean };
  last_run: { at: string; error: string | null; sent: number; mode: string | null } | null;
  last_mode: string | null;
  interval_minutes: number;
};

export default function SophosPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["sophos"], queryFn: () => api<Status>("GET", "/api/sophos"), refetchInterval: 15000 });
  const [enabled, setEnabled] = useState(false);
  const [clientId, setClientId] = useState("");
  const [secret, setSecret] = useState("");
  const [mode, setMode] = useState<"auto" | "datalake" | "siem">("auto");
  const [saved, setSaved] = useState(false);
  const [probe, setProbe] = useState<{ tenant: string; datalake: boolean } | null>(null);

  useEffect(() => {
    if (!q.data) return;
    setEnabled(q.data.config.enabled);
    setClientId(q.data.config.client_id);
    setMode(q.data.config.mode);
  }, [q.data]);

  const save = useMutation({
    mutationFn: () =>
      api<Status>("PUT", "/api/sophos/settings", {
        enabled, client_id: clientId.trim(), mode, client_secret: secret || null,
      }),
    onSuccess: (d) => { setSaved(true); setSecret(""); qc.setQueryData(["sophos"], d); },
    onError: () => setSaved(false),
  });
  const test = useMutation({
    mutationFn: () => api<{ tenant: string; datalake: boolean }>("POST", "/api/sophos/test"),
    onSuccess: (d) => setProbe(d),
    onError: () => setProbe(null),
  });

  const d = q.data;
  return (
    <div className="max-w-3xl">
      <h1 className="mb-1 text-xl font-semibold">{t("sophos.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("sophos.intro")}</p>
      <ErrorBox error={q.error ?? save.error ?? test.error} />
      <section className="card mb-4">
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <label className="label" htmlFor="s-id">{t("sophos.client_id")}</label>
            <input id="s-id" className="input" value={clientId} disabled={!canWrite} onChange={(e) => setClientId(e.target.value)} />
          </div>
          <div>
            <label className="label" htmlFor="s-sec">{t("sophos.client_secret")}</label>
            <input id="s-sec" className="input" type="password" autoComplete="off" value={secret} disabled={!canWrite}
              placeholder={d?.config.has_secret ? t("sophos.secret_set") : ""} onChange={(e) => setSecret(e.target.value)} />
          </div>
          <div>
            <label className="label" htmlFor="s-mode">{t("sophos.mode")}</label>
            <select id="s-mode" className="input" value={mode} disabled={!canWrite}
              onChange={(e) => setMode(e.target.value as typeof mode)}>
              <option value="auto">{t("sophos.modes.auto")}</option>
              <option value="datalake">{t("sophos.modes.datalake")}</option>
              <option value="siem">{t("sophos.modes.siem")}</option>
            </select>
          </div>
          <label className="flex items-center gap-2 self-end text-sm">
            <input type="checkbox" checked={enabled} disabled={!canWrite} onChange={(e) => setEnabled(e.target.checked)} />
            {t("sophos.enabled")}
          </label>
        </div>
        {canWrite && (
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <button className="btn" disabled={save.isPending} onClick={() => save.mutate()}>{t("common.save")}</button>
            <button className="btn" disabled={test.isPending || !d?.config.has_secret} onClick={() => test.mutate()}>{t("sophos.test")}</button>
            {saved && <span className="text-sm text-green-700">{t("sophos.saved")}</span>}
            {probe && (
              <span className="text-sm text-green-700">
                {t(probe.datalake ? "sophos.probe_datalake" : "sophos.probe_siem")}
              </span>
            )}
          </div>
        )}
      </section>
      <section className="card">
        <h2 className="mb-2 font-medium">{t("sophos.status")}</h2>
        <dl className="grid grid-cols-[12rem_1fr] gap-y-1 text-sm">
          <dt className="text-slate-500">{t("sophos.last_run")}</dt>
          <dd>{d?.last_run ? new Date(d.last_run.at).toLocaleString() : t("sophos.never")}</dd>
          <dt className="text-slate-500">{t("sophos.active_mode")}</dt>
          <dd>{d?.last_mode ? t(`sophos.modes.${d.last_mode}`) : "–"}</dd>
          <dt className="text-slate-500">{t("sophos.sent")}</dt>
          <dd>{d?.last_run?.sent ?? 0}</dd>
          <dt className="text-slate-500">{t("sophos.result")}</dt>
          <dd className={d?.last_run?.error ? "text-red-700" : ""}>
            {d?.last_run ? (d.last_run.error ? t(`errors.${d.last_run.error}`) : t("sophos.ok")) : "–"}
          </dd>
        </dl>
      </section>
    </div>
  );
}
