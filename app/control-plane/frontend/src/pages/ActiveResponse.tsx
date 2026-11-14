import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Cfg = { enabled: boolean; auto: boolean; group: string; hours: number; protected: string[]; has_token: boolean };
type Block = { ip: string; reason: string; by: string; auto: boolean; created: string; until: string };
type Data = { config: Cfg; blocks: Block[]; max: number };

export default function ActiveResponsePage({ canSettings, canBlock }: { canSettings: boolean; canBlock: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["ar"], queryFn: () => api<Data>("GET", "/api/ar"), refetchInterval: 30000 });
  const [f, setF] = useState<Cfg | null>(null);
  const [prot, setProt] = useState("");
  const [token, setToken] = useState("");
  const [ip, setIp] = useState("");
  const [hours, setHours] = useState("");
  const [saved, setSaved] = useState(false);
  useEffect(() => { if (q.data) { setF(q.data.config); setProt(q.data.config.protected.join(", ")); } }, [q.data]);
  const done = (d: Data) => qc.setQueryData(["ar"], d);
  const save = useMutation({
    mutationFn: () => api<Data>("PUT", "/api/ar/settings", { ...f, protected: prot.split(/[,;\s]+/).filter(Boolean), token: token || null }),
    onSuccess: (d) => { done(d); setSaved(true); setToken(""); },
  });
  const block = useMutation({
    mutationFn: () => api<Data>("POST", "/api/ar/block", { ip, hours: hours ? Number(hours) : null, reason: "manuell" }),
    onSuccess: (d) => { done(d); setIp(""); },
  });
  const unblock = useMutation({ mutationFn: (x: string) => api<Data>("DELETE", `/api/ar/block/${x}`), onSuccess: done });
  if (!f) return <ErrorBox error={q.error} />;
  const set = <K extends keyof Cfg>(k: K, v: Cfg[K]) => { setSaved(false); setF({ ...f, [k]: v }); };
  return (
    <div className="max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold">{t("ar.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("ar.intro")}</p>
      <ErrorBox error={q.error ?? save.error ?? block.error ?? unblock.error} />
      {canSettings && (
        <section className="card mb-4">
          <h2 className="mb-2 font-medium">{t("ar.settings")}</h2>
          <label className="mb-1 flex items-center gap-2 text-sm"><input type="checkbox" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />{t("ar.enabled")}</label>
          <label className="mb-2 flex items-center gap-2 text-sm"><input type="checkbox" checked={f.auto} disabled={!f.enabled} onChange={(e) => set("auto", e.target.checked)} />{t("ar.auto")}</label>
          <div className="grid grid-cols-2 gap-3">
            <div><label className="label" htmlFor="ar-g">{t("ar.group")}</label><input id="ar-g" className="input" value={f.group} onChange={(e) => set("group", e.target.value)} /></div>
            <div><label className="label" htmlFor="ar-h">{t("ar.hours")}</label><input id="ar-h" className="input" type="number" min={1} max={720} value={f.hours} onChange={(e) => set("hours", Number(e.target.value))} /></div>
            <div><label className="label" htmlFor="ar-t">{t("ar.token")}</label><input id="ar-t" className="input" type="password" autoComplete="new-password" value={token} placeholder={f.has_token ? "••••••••" : ""} onChange={(e) => { setSaved(false); setToken(e.target.value); }} /></div>
            <div><label className="label" htmlFor="ar-p">{t("ar.protected")}</label><input id="ar-p" className="input" value={prot} onChange={(e) => { setSaved(false); setProt(e.target.value); }} /></div>
          </div>
          <p className="mt-2 text-xs text-slate-500">{t("ar.hint", { group: f.group })}</p>
          <div className="mt-2 flex items-center gap-3"><button className="btn" disabled={save.isPending} onClick={() => save.mutate()}>{t("common.save")}</button>{saved && <span className="text-sm text-green-700">{t("notify.saved")}</span>}</div>
        </section>
      )}
      {canBlock && f.enabled && (
        <section className="card mb-4">
          <h2 className="mb-2 font-medium">{t("ar.block_title")}</h2>
          <div className="flex flex-wrap items-end gap-3">
            <div><label className="label" htmlFor="ar-ip">{t("ar.ip")}</label><input id="ar-ip" className="input" value={ip} onChange={(e) => setIp(e.target.value)} /></div>
            <div><label className="label" htmlFor="ar-hh">{t("ar.hours")}</label><input id="ar-hh" className="input w-24" type="number" min={1} max={720} value={hours} placeholder={String(f.hours)} onChange={(e) => setHours(e.target.value)} /></div>
            <button className="btn" disabled={!ip || block.isPending} onClick={() => block.mutate()}>{t("ar.block")}</button>
          </div>
        </section>
      )}
      <section className="card">
        <h2 className="mb-2 font-medium">{t("ar.active", { count: q.data?.blocks.length ?? 0, max: q.data?.max ?? 0 })}</h2>
        {q.data?.blocks.length === 0 && <p className="text-sm text-slate-500">{t("ar.none")}</p>}
        <ul className="text-sm">
          {q.data?.blocks.map((b) => (
            <li key={b.ip} className="flex flex-wrap items-center gap-3 border-b border-slate-100 py-1">
              <span className="font-mono">{b.ip}</span><span>{b.reason}</span>
              <span className="text-slate-500">{b.auto ? t("ar.auto_label") : b.by}</span>
              <span className="text-slate-500">{t("ar.until")}: {b.until}</span>
              {canBlock && <button className="btn-secondary ml-auto" onClick={() => unblock.mutate(b.ip)}>{t("ar.unblock")}</button>}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
