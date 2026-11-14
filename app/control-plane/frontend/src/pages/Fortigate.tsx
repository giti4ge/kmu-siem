import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Status = {
  config: { enabled: boolean; host: string; port: number; vdom: string; tls_pin: string; has_token: boolean };
  last_run: { at: string; error: string | null; sent: number; arp: number; dhcp: number } | null;
  interval_minutes: number;
};

export default function FortigatePage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["fortigate"], queryFn: () => api<Status>("GET", "/api/fortigate"), refetchInterval: 15000 });
  const [enabled, setEnabled] = useState(false);
  const [host, setHost] = useState("");
  const [port, setPort] = useState(443);
  const [vdom, setVdom] = useState("root");
  const [pin, setPin] = useState("");
  const [token, setToken] = useState("");
  const [saved, setSaved] = useState(false);
  const [probe, setProbe] = useState<string | null>(null);
  const [counts, setCounts] = useState<{ arp: number; dhcp: number } | null>(null);

  useEffect(() => {
    if (!q.data) return;
    const c = q.data.config;
    setEnabled(c.enabled); setHost(c.host); setPort(c.port); setVdom(c.vdom); setPin(c.tls_pin);
  }, [q.data]);

  const save = useMutation({
    mutationFn: () => api<Status>("PUT", "/api/fortigate/settings", { enabled, host: host.trim(), port, vdom, tls_pin: pin, token: token || null }),
    onSuccess: (d) => { setSaved(true); setToken(""); qc.setQueryData(["fortigate"], d); },
    onError: () => setSaved(false),
  });
  const fingerprint = useMutation({
    mutationFn: () => api<{ fingerprint: string }>("POST", "/api/fortigate/fingerprint", { host: host.trim(), port }),
    onSuccess: (d) => setProbe(d.fingerprint),
  });
  const test = useMutation({
    mutationFn: () => api<{ arp: number; dhcp: number }>("POST", "/api/fortigate/test"),
    onSuccess: (d) => setCounts(d),
    onError: () => setCounts(null),
  });
  const d = q.data;
  const fmtPin = (p: string) => p.match(/.{2}/g)?.join(":") ?? p;

  return (
    <div className="max-w-3xl">
      <h1 className="mb-1 text-xl font-semibold">{t("fortigate.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("fortigate.intro")}</p>
      <ErrorBox error={q.error ?? save.error ?? fingerprint.error ?? test.error} />
      <section className="card mb-4">
        <div className="grid gap-3 md:grid-cols-4">
          <div className="md:col-span-2">
            <label className="label" htmlFor="f-h">{t("fortigate.host")}</label>
            <input id="f-h" className="input" value={host} disabled={!canWrite} onChange={(e) => setHost(e.target.value)} />
          </div>
          <div>
            <label className="label" htmlFor="f-p">{t("fortigate.port")}</label>
            <input id="f-p" className="input" type="number" value={port} disabled={!canWrite} onChange={(e) => setPort(Number(e.target.value))} />
          </div>
          <div>
            <label className="label" htmlFor="f-v">{t("fortigate.vdom")}</label>
            <input id="f-v" className="input" value={vdom} disabled={!canWrite} onChange={(e) => setVdom(e.target.value)} />
          </div>
          <div className="md:col-span-4">
            <label className="label" htmlFor="f-t">{t("fortigate.token")}</label>
            <input id="f-t" className="input" type="password" autoComplete="off" value={token} disabled={!canWrite}
              placeholder={d?.config.has_token ? t("fortigate.token_set") : ""} onChange={(e) => setToken(e.target.value)} />
            <p className="mt-1 text-xs text-slate-500">{t("fortigate.token_hint")}</p>
          </div>
          <div className="md:col-span-4">
            <label className="label" htmlFor="f-pin">{t("fortigate.pin")}</label>
            <input id="f-pin" className="input font-mono text-xs" value={fmtPin(pin)} disabled={!canWrite}
              onChange={(e) => setPin(e.target.value.replace(/[^0-9a-fA-F]/g, "").toLowerCase())} />
            <div className="mt-1 flex flex-wrap items-center gap-2">
              {canWrite && <button className="btn" disabled={!host.trim() || fingerprint.isPending} onClick={() => fingerprint.mutate()}>{t("fortigate.fetch_pin")}</button>}
              {probe && (
                <>
                  <span className="break-all font-mono text-xs">{fmtPin(probe)}</span>
                  {canWrite && <button className="btn" onClick={() => { setPin(probe); setProbe(null); }}>{t("fortigate.accept_pin")}</button>}
                </>
              )}
            </div>
            <p className="mt-1 text-xs text-slate-500">{t("fortigate.pin_hint")}</p>
          </div>
          <label className="flex items-center gap-2 text-sm md:col-span-4">
            <input type="checkbox" checked={enabled} disabled={!canWrite} onChange={(e) => setEnabled(e.target.checked)} />
            {t("fortigate.enabled")}
          </label>
        </div>
        {canWrite && (
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <button className="btn" disabled={save.isPending} onClick={() => save.mutate()}>{t("common.save")}</button>
            <button className="btn" disabled={test.isPending || !d?.config.has_token} onClick={() => test.mutate()}>{t("fortigate.test")}</button>
            {saved && <span className="text-sm text-green-700">{t("fortigate.saved")}</span>}
            {counts && <span className="text-sm text-green-700">{t("fortigate.test_ok", counts)}</span>}
          </div>
        )}
      </section>
      <section className="card">
        <h2 className="mb-2 font-medium">{t("fortigate.status")}</h2>
        <dl className="grid grid-cols-[12rem_1fr] gap-y-1 text-sm">
          <dt className="text-slate-500">{t("fortigate.last_run")}</dt>
          <dd>{d?.last_run ? new Date(d.last_run.at).toLocaleString() : t("fortigate.never")}</dd>
          <dt className="text-slate-500">{t("fortigate.entries")}</dt>
          <dd>{d?.last_run ? t("fortigate.entries_value", d.last_run) : "–"}</dd>
          <dt className="text-slate-500">{t("fortigate.result")}</dt>
          <dd className={d?.last_run?.error ? "text-red-700" : ""}>
            {d?.last_run ? (d.last_run.error ? t(`errors.${d.last_run.error}`) : t("fortigate.ok")) : "–"}
          </dd>
        </dl>
      </section>
    </div>
  );
}
