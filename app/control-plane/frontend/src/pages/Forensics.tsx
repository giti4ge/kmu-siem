import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Cfg = { enabled: boolean; provider: string; model: string; base_url: string; has_key: boolean; anonymize: boolean; daily_token_limit: number };
type Item = { time?: string; statement: string; evidence: string[] };
type Result = {
  events: number; timeline: Item[]; scope: Item[]; initial_access: Item | null; gaps: string[]; contradictions: string[];
  disclaimer: string; rejected?: number; request?: { system: string; user: string };
};

export function AiSettings({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["ai"], queryFn: () => api<{ config: Cfg; used_today: number }>("GET", "/api/ai") });
  const [f, setF] = useState<Cfg | null>(null);
  const [key, setKey] = useState("");
  const [saved, setSaved] = useState(false);
  useEffect(() => { if (q.data) setF(q.data.config); }, [q.data]);
  const save = useMutation({
    mutationFn: () => api("PUT", "/api/ai", { ...f, api_key: key || null }),
    onSuccess: () => { setSaved(true); setKey(""); qc.invalidateQueries({ queryKey: ["ai"] }); },
  });
  if (!f) return <ErrorBox error={q.error} />;
  const set = <K extends keyof Cfg>(k: K, v: Cfg[K]) => { setSaved(false); setF({ ...f, [k]: v }); };
  return (
    <section className="card mb-4">
      <h2 className="mb-1 font-medium">{t("ai.settings")}</h2>
      <p className="mb-2 text-sm text-slate-600">{t("ai.intro")}</p>
      <ErrorBox error={save.error} />
      <label className="mb-2 flex items-center gap-2 text-sm"><input type="checkbox" checked={f.enabled} disabled={!canWrite} onChange={(e) => set("enabled", e.target.checked)} />{t("notify.enabled")}</label>
      <div className="grid grid-cols-2 gap-3">
        <div><label className="label" htmlFor="ai-p">{t("ai.provider")}</label>
          <select id="ai-p" className="input" value={f.provider} disabled={!canWrite} onChange={(e) => set("provider", e.target.value)}>
            {["anthropic", "gemini", "openai", "azure", "custom"].map((p) => <option key={p} value={p}>{t(`ai.prov.${p}`)}</option>)}
          </select></div>
        <div><label className="label" htmlFor="ai-m">{t("ai.model")}</label><input id="ai-m" className="input" value={f.model} disabled={!canWrite} onChange={(e) => set("model", e.target.value)} /></div>
        {["azure", "custom", "openai"].includes(f.provider) && (
          <div className="col-span-2"><label className="label" htmlFor="ai-u">{t("ai.base_url")}</label><input id="ai-u" className="input" value={f.base_url} disabled={!canWrite} onChange={(e) => set("base_url", e.target.value)} /></div>
        )}
        <div><label className="label" htmlFor="ai-k">{t("ai.api_key")}</label><input id="ai-k" className="input" type="password" autoComplete="new-password" value={key} placeholder={f.has_key ? "••••••••" : ""} disabled={!canWrite} onChange={(e) => { setSaved(false); setKey(e.target.value); }} /></div>
        <div><label className="label" htmlFor="ai-l">{t("ai.limit")}</label><input id="ai-l" className="input" type="number" value={f.daily_token_limit} disabled={!canWrite} onChange={(e) => set("daily_token_limit", Number(e.target.value))} /></div>
      </div>
      {f.provider === "custom" && (
        <label className="mt-2 flex items-center gap-2 text-sm"><input type="checkbox" checked={f.anonymize} disabled={!canWrite} onChange={(e) => set("anonymize", e.target.checked)} />{t("ai.anonymize")}</label>
      )}
      <p className="mt-2 text-xs text-slate-500">{t("ai.used", { count: q.data?.used_today ?? 0 })}</p>
      {canWrite && <div className="mt-2 flex items-center gap-3"><button className="btn" disabled={save.isPending} onClick={() => save.mutate()}>{t("common.save")}</button>{saved && <span className="text-sm text-green-700">{t("notify.saved")}</span>}</div>}
    </section>
  );
}

function Section({ title, items }: { title: string; items: Item[] }) {
  const { t } = useTranslation();
  if (!items.length) return null;
  return (
    <section className="card mb-3">
      <h3 className="mb-1 font-medium">{title}</h3>
      <ul className="text-sm">
        {items.map((i, n) => (
          <li key={n} className="border-b border-slate-100 py-1">
            {i.time && <span className="mr-2 font-mono text-xs text-slate-500">{i.time}</span>}{i.statement}
            <span className="ml-2 text-xs text-slate-500">{t("ai.evidence")}: {i.evidence.join(", ")}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export default function ForensicsPage({ canSettings }: { canSettings: boolean }) {
  const { t } = useTranslation();
  const [field, setField] = useState("user.name");
  const [value, setValue] = useState("");
  const [hours, setHours] = useState(24);
  const [testMode, setTestMode] = useState(false);
  const run = useMutation({
    mutationFn: () => api<Result>("POST", "/api/ai/forensics", { field, value, hours, test: testMode }),
  });
  const r = run.data;
  return (
    <div className="max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold">{t("ai.forensics")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("ai.forensics_intro")}</p>
      {canSettings && <AiSettings canWrite />}
      <section className="card mb-4">
        <div className="flex flex-wrap items-end gap-3">
          <div><label className="label" htmlFor="f-f">{t("ai.pivot")}</label>
            <select id="f-f" className="input" value={field} onChange={(e) => setField(e.target.value)}>
              {["user.name", "host.name", "source.ip", "destination.ip"].map((x) => <option key={x} value={x}>{x}</option>)}
            </select></div>
          <div><label className="label" htmlFor="f-v">{t("ai.value")}</label><input id="f-v" className="input" value={value} onChange={(e) => setValue(e.target.value)} /></div>
          <div><label className="label" htmlFor="f-h">{t("ai.hours")}</label><input id="f-h" className="input w-24" type="number" min={1} max={720} value={hours} onChange={(e) => setHours(Number(e.target.value))} /></div>
          <label className="flex items-center gap-1 text-sm"><input type="checkbox" checked={testMode} onChange={(e) => setTestMode(e.target.checked)} />{t("ai.test_mode")}</label>
          <button className="btn" disabled={!value || run.isPending} onClick={() => run.mutate()}>{t("ai.analyze")}</button>
        </div>
      </section>
      <ErrorBox error={run.error} />
      {run.isPending && <p className="text-sm text-slate-600">{t("ai.running")}</p>}
      {r?.request && (
        <section className="card mb-3">
          <h3 className="mb-1 font-medium">{t("ai.request_preview")}</h3>
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all font-mono text-xs">{r.request.user}</pre>
        </section>
      )}
      {r && !r.request && (
        <>
          <p className="mb-2 text-sm text-slate-500">{t("ai.events", { count: r.events })} – {r.disclaimer}</p>
          {r.contradictions.map((c) => <p key={c} className="mb-2 rounded bg-yellow-50 p-2 text-sm text-yellow-900">{c}</p>)}
          {r.initial_access && <Section title={t("ai.initial_access")} items={[r.initial_access]} />}
          <Section title={t("ai.timeline")} items={r.timeline} />
          <Section title={t("ai.scope")} items={r.scope} />
          {r.gaps.length > 0 && <section className="card mb-3"><h3 className="mb-1 font-medium">{t("ai.gaps")}</h3><ul className="list-disc pl-5 text-sm">{r.gaps.map((g) => <li key={g}>{g}</li>)}</ul></section>}
        </>
      )}
    </div>
  );
}
