import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useLocation } from "react-router";
import { api } from "../api";
import { FilePick } from "../FilePick";
import { ErrorBox } from "./Auth";

type Rule = { id: string; name: string; program: string; regex: string; category: string; fields: Record<string, string>; action: string; enabled: boolean };
type Data = { rules: Rule[]; categories: string[]; fields: string[] };
type TestRow = { line: string; match: boolean; fields: Record<string, string> };

// Regel-Vorschlag aus einer Beispielzeile: Text wörtlich, IPv4-Adressen werden zu Gruppen (Quelle/Ziel)
function suggest(line: string): Pick<Rule, "regex" | "fields"> {
  const ip = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
  const names = [["src_ip", "source.ip"], ["dst_ip", "destination.ip"]];
  const fields: Record<string, string> = {};
  let n = 0, last = 0, regex = "";
  const esc = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  for (const m of line.matchAll(ip)) {
    if (n >= names.length) break;
    regex += esc(line.slice(last, m.index)) + `(?P<${names[n][0]}>\\d{1,3}(?:\\.\\d{1,3}){3})`;
    fields[names[n][0]] = names[n][1];
    last = (m.index ?? 0) + m[0].length;
    n++;
  }
  regex += esc(line.slice(last));
  return { regex: regex.slice(0, 480), fields };
}

const EMPTY: Rule = { id: "", name: "", program: "", regex: "", category: "network", fields: {}, action: "", enabled: true };

export default function ParserEditorPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["parsers"], queryFn: () => api<Data>("GET", "/api/parsers") });
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [sel, setSel] = useState(0);
  const [samples, setSamples] = useState("");
  const loc = useLocation();
  const [started, setStarted] = useState(false);
  const list = rules ?? q.data?.rules ?? [];
  // Aus „Nicht erkannte Quellen“ übernommen: neue Regel mit Programmname, Proben und Vorschlag anlegen
  const from = loc.state as { program?: string; samples?: string[] } | null;
  if (from && q.data && !started) {
    setStarted(true);
    const first = from.samples?.[0] ?? "";
    const id = ("r_" + (from.program || "quelle").toLowerCase().replace(/[^a-z0-9_]/g, "_")).slice(0, 31);
    setRules([...q.data.rules, { ...EMPTY, id, name: from.program || id, program: from.program ?? "", ...suggest(first) }]);
    setSel(q.data.rules.length);
    setSamples((from.samples ?? []).join("\n"));
    window.history.replaceState({}, "");
  }
  const rule = list[sel];
  const setRule = (patch: Partial<Rule>) => setRules(list.map((r, i) => (i === sel ? { ...r, ...patch } : r)));
  const save = useMutation({
    mutationFn: () => api<{ rules: Rule[]; applied: boolean }>("PUT", "/api/parsers", { rules: list }),
    onSuccess: (d) => { setRules(null); qc.invalidateQueries({ queryKey: ["parsers"] }); if (!d.applied) alert(t("parsers.not_applied")); },
  });
  const test = useMutation({ mutationFn: () => api<TestRow[]>("POST", "/api/parsers/test", { rule, samples: samples.split("\n").filter(Boolean) }) });
  const exportJson = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify({ format: "siem-parsers", version: 1, rules: list }, null, 2)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url; a.download = `parser-regeln-${new Date().toISOString().slice(0, 10)}.json`; a.click();
    URL.revokeObjectURL(url);
  };
  const [importErr, setImportErr] = useState(false);
  const importJson = async (f: File) => {
    try {
      const d = JSON.parse(await f.text());
      const inc: Rule[] = Array.isArray(d) ? d : d.rules;
      if (!Array.isArray(inc) || inc.some((r) => typeof r?.id !== "string" || typeof r?.regex !== "string")) throw new Error("format");
      const ids = new Set(inc.map((r) => r.id));
      setRules([...list.filter((r) => !ids.has(r.id)), ...inc.map((r) => ({ ...EMPTY, ...r }))]);
      setImportErr(false);
    } catch { setImportErr(true); }
  };
  const groups = rule ? Array.from(rule.regex.matchAll(/\(\?P<([A-Za-z][A-Za-z0-9_]*)>/g)).map((m) => m[1]) : [];
  return (
    <div className="max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold">{t("parsers.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("parsers.intro")}</p>
      <ErrorBox error={q.error ?? save.error ?? test.error} />
      <section className="card">
        <div className="mb-2 flex flex-wrap gap-2">
          {list.map((r, i) => <button key={r.id + i} className={i === sel ? "btn" : "btn-secondary"} onClick={() => setSel(i)}>{r.name || r.id || t("parsers.new")}</button>)}
          {canWrite && <button className="btn-secondary" onClick={() => { setRules([...list, { ...EMPTY }]); setSel(list.length); }}>+ {t("parsers.add")}</button>}
        </div>
        {rule && (
          <div className="grid grid-cols-2 gap-3">
            <div><label className="label" htmlFor="pe-id">{t("parsers.id")}</label><input id="pe-id" className="input" disabled={!canWrite} value={rule.id} onChange={(e) => setRule({ id: e.target.value })} /></div>
            <div><label className="label" htmlFor="pe-n">{t("parsers.name")}</label><input id="pe-n" className="input" disabled={!canWrite} value={rule.name} onChange={(e) => setRule({ name: e.target.value })} /></div>
            <div><label className="label" htmlFor="pe-p">{t("parsers.program")}</label><input id="pe-p" className="input" disabled={!canWrite} value={rule.program} onChange={(e) => setRule({ program: e.target.value })} /></div>
            <div><label className="label" htmlFor="pe-c">{t("parsers.category")}</label>
              <select id="pe-c" className="input" disabled={!canWrite} value={rule.category} onChange={(e) => setRule({ category: e.target.value })}>{q.data?.categories.map((c) => <option key={c}>{c}</option>)}</select></div>
            <div className="col-span-2"><label className="label" htmlFor="pe-r">{t("parsers.regex")}</label><input id="pe-r" className="input font-mono text-xs" disabled={!canWrite} value={rule.regex} onChange={(e) => setRule({ regex: e.target.value })} />
              <p className="text-xs text-slate-500">{t("parsers.regex_hint")}</p></div>
            <div className="col-span-2">
              <span className="label">{t("parsers.fields")}</span>
              {groups.map((g) => (
                <div key={g} className="mb-1 flex items-center gap-2 text-sm"><code className="w-32">{g}</code>→
                  <select className="input w-56" aria-label={g} disabled={!canWrite} value={rule.fields[g] ?? ""}
                    onChange={(e) => { const f = { ...rule.fields }; if (e.target.value) f[g] = e.target.value; else delete f[g]; setRule({ fields: f }); }}>
                    <option value="">–</option>{q.data?.fields.map((f) => <option key={f}>{f}</option>)}</select></div>
              ))}
            </div>
            <div><label className="label" htmlFor="pe-a">{t("parsers.action")}</label><input id="pe-a" className="input" disabled={!canWrite} value={rule.action} onChange={(e) => setRule({ action: e.target.value })} /></div>
            <label className="flex items-center gap-2 pt-6 text-sm"><input type="checkbox" disabled={!canWrite} checked={rule.enabled} onChange={(e) => setRule({ enabled: e.target.checked })} />{t("parsers.enabled")}</label>
            <div className="col-span-2"><label className="label" htmlFor="pe-s">{t("parsers.samples")}</label><textarea id="pe-s" className="input font-mono text-xs" rows={4} value={samples} onChange={(e) => setSamples(e.target.value)} />
              <button className="btn-secondary mt-1" disabled={!samples || test.isPending} onClick={() => test.mutate()}>{t("parsers.test")}</button></div>
            {test.data && (
              <ul className="col-span-2 text-xs">{test.data.map((r, i) => <li key={i} className={r.match ? "text-green-700" : "text-slate-500"}>{r.match ? "✔" : "✘"} {r.line} {r.match && JSON.stringify(r.fields)}</li>)}</ul>
            )}
          </div>
        )}
        {canWrite && (
          <div className="mt-3 flex gap-2">
            <button className="btn" disabled={save.isPending || rules === null} onClick={() => save.mutate()}>{t("parsers.save")}</button>
            {rule && <button className="btn-secondary" onClick={() => { setRules(list.filter((_, i) => i !== sel)); setSel(0); }}>{t("parsers.delete")}</button>}
          </div>
        )}
        <div className="mt-3 flex flex-wrap items-center gap-3 border-t pt-3">
          <button className="btn-secondary" onClick={exportJson}>{t("parsers.export")}</button>
          {canWrite && <FilePick label={t("parsers.import")} accept=".json,application/json" onFile={(f) => void importJson(f)} />}
          {importErr && <span className="error">{t("parsers.import_error")}</span>}
        </div>
        {rules !== null && canWrite && <p className="mt-2 text-xs text-slate-500">{t("parsers.unsaved")}</p>}
        <p className="mt-2 text-xs text-slate-500">{t("parsers.restart_note")}</p>
      </section>
    </div>
  );
}
