import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Cfg = {
  email_enabled: boolean; smtp_host: string; smtp_port: number; smtp_security: string; smtp_user: string;
  has_smtp_password: boolean; mail_from: string; mail_to: string[]; teams_enabled: boolean; has_teams_url: boolean;
  min_severity: string;
};
type Data = { config: Cfg; state: Record<string, { at: string; ok: boolean; error: string }> };

export default function NotificationsPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["notify"], queryFn: () => api<Data>("GET", "/api/notifications") });
  const [f, setF] = useState<Cfg | null>(null);
  const [pw, setPw] = useState("");
  const [url, setUrl] = useState("");
  const [to, setTo] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    if (q.data) { setF(q.data.config); setTo(q.data.config.mail_to.join(", ")); }
  }, [q.data]);

  const save = useMutation({
    mutationFn: () => api<Data>("PUT", "/api/notifications", {
      ...f, mail_to: to.split(/[,;\s]+/).filter(Boolean), smtp_password: pw || null, teams_url: url || null,
    }),
    onSuccess: (d) => { qc.setQueryData(["notify"], d); setPw(""); setUrl(""); setMsg(t("notify.saved")); },
    onError: () => setMsg(""),
  });
  const test = useMutation({
    mutationFn: (channel: string) => api("POST", "/api/notifications/test", { channel }),
    onSuccess: () => { setMsg(t("notify.test_ok")); qc.invalidateQueries({ queryKey: ["notify"] }); },
    onError: () => { setMsg(""); qc.invalidateQueries({ queryKey: ["notify"] }); },
  });
  if (!f) return <ErrorBox error={q.error} />;
  const set = <K extends keyof Cfg>(k: K, v: Cfg[K]) => { setMsg(""); setF({ ...f, [k]: v }); };
  const st = q.data?.state ?? {};
  return (
    <div className="max-w-3xl">
      <h1 className="mb-1 text-xl font-semibold">{t("notify.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("notify.intro")}</p>
      <ErrorBox error={q.error ?? save.error ?? test.error} />
      <section className="card mb-4">
        <label className="mb-3 flex items-center gap-2 text-sm">
          <span>{t("notify.min_severity")}</span>
          <select className="input" value={f.min_severity} disabled={!canWrite} onChange={(e) => set("min_severity", e.target.value)}>
            {["low", "medium", "high", "critical"].map((s) => <option key={s} value={s}>{t(`alerts.sev.${s}`)}</option>)}
          </select>
        </label>
        <h2 className="mb-2 font-medium">{t("notify.email")}</h2>
        <label className="mb-2 flex items-center gap-2 text-sm"><input type="checkbox" checked={f.email_enabled} disabled={!canWrite} onChange={(e) => set("email_enabled", e.target.checked)} />{t("notify.enabled")}</label>
        <div className="grid grid-cols-2 gap-3">
          <div><label className="label" htmlFor="n-host">{t("notify.smtp_host")}</label><input id="n-host" className="input" value={f.smtp_host} disabled={!canWrite} onChange={(e) => set("smtp_host", e.target.value)} /></div>
          <div><label className="label" htmlFor="n-port">{t("notify.smtp_port")}</label><input id="n-port" className="input" type="number" value={f.smtp_port} disabled={!canWrite} onChange={(e) => set("smtp_port", Number(e.target.value))} /></div>
          <div><label className="label" htmlFor="n-sec">{t("notify.smtp_security")}</label>
            <select id="n-sec" className="input" value={f.smtp_security} disabled={!canWrite} onChange={(e) => set("smtp_security", e.target.value)}>
              <option value="starttls">{t("notify.starttls")}</option><option value="ssl">{t("notify.ssl")}</option><option value="none">{t("notify.none")}</option>
            </select></div>
          <div><label className="label" htmlFor="n-user">{t("notify.smtp_user")}</label><input id="n-user" className="input" value={f.smtp_user} disabled={!canWrite} onChange={(e) => set("smtp_user", e.target.value)} autoComplete="off" /></div>
          <div><label className="label" htmlFor="n-pw">{t("notify.smtp_password")}</label><input id="n-pw" className="input" type="password" value={pw} disabled={!canWrite} placeholder={f.has_smtp_password ? "••••••••" : ""} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" /></div>
          <div><label className="label" htmlFor="n-from">{t("notify.mail_from")}</label><input id="n-from" className="input" value={f.mail_from} disabled={!canWrite} onChange={(e) => set("mail_from", e.target.value)} /></div>
          <div className="col-span-2"><label className="label" htmlFor="n-to">{t("notify.mail_to")}</label><input id="n-to" className="input" value={to} disabled={!canWrite} onChange={(e) => { setMsg(""); setTo(e.target.value); }} /></div>
        </div>
        {st.email && <p className={`mt-2 text-xs ${st.email.ok ? "text-green-700" : "text-red-700"}`}>{t("notify.last")}: {st.email.at} – {st.email.ok ? t("maintenance.ok") : st.email.error}</p>}
        {canWrite && <button className="btn-secondary mt-2" disabled={test.isPending} onClick={() => test.mutate("email")}>{t("notify.test")}</button>}
      </section>
      <section className="card mb-4">
        <h2 className="mb-2 font-medium">{t("notify.teams")}</h2>
        <label className="mb-2 flex items-center gap-2 text-sm"><input type="checkbox" checked={f.teams_enabled} disabled={!canWrite} onChange={(e) => set("teams_enabled", e.target.checked)} />{t("notify.enabled")}</label>
        <label className="label" htmlFor="n-url">{t("notify.teams_url")}</label>
        <input id="n-url" className="input" type="password" value={url} disabled={!canWrite} placeholder={f.has_teams_url ? "••••••••" : "https://…logic.azure.com/…"} onChange={(e) => setUrl(e.target.value)} autoComplete="off" />
        {st.teams && <p className={`mt-2 text-xs ${st.teams.ok ? "text-green-700" : "text-red-700"}`}>{t("notify.last")}: {st.teams.at} – {st.teams.ok ? t("maintenance.ok") : st.teams.error}</p>}
        {canWrite && <button className="btn-secondary mt-2" disabled={test.isPending} onClick={() => test.mutate("teams")}>{t("notify.test")}</button>}
      </section>
      {canWrite && (
        <div className="flex items-center gap-3">
          <button className="btn" disabled={save.isPending} onClick={() => save.mutate()}>{t("common.save")}</button>
          {msg && <span className="text-sm text-green-700">{msg}</span>}
        </div>
      )}
    </div>
  );
}
