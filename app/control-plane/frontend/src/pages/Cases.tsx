import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Case = { id: number; title: string; description: string; status: string; created_by: string; created_at: string; closed_at: string | null; package_sha256: string | null; retention_months: number };
type Item = { id: number; kind: string; added_by: string; added_at: string; sha256: string; content: Record<string, unknown> | null };
type Detail = Case & { items: Item[] };

async function download(id: number) {
  const res = await fetch(`/api/cases/${id}/package`, { credentials: "same-origin" });
  if (!res.ok) throw new Error("download");
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = `fall-${id}.zip`;
  a.click();
  URL.revokeObjectURL(url);
}

function CaseView({ id, canWrite }: { id: number; canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["case", id], queryFn: () => api<Detail>("GET", `/api/cases/${id}`) });
  const [note, setNote] = useState("");
  const [index, setIndex] = useState("");
  const [eid, setEid] = useState("");
  const done = () => { qc.invalidateQueries({ queryKey: ["case", id] }); qc.invalidateQueries({ queryKey: ["cases"] }); };
  const addNote = useMutation({ mutationFn: () => api("POST", `/api/cases/${id}/notes`, { text: note }), onSuccess: () => { setNote(""); done(); } });
  const addEvent = useMutation({ mutationFn: () => api("POST", `/api/cases/${id}/events`, { index, id: eid }), onSuccess: () => { setEid(""); done(); } });
  const close = useMutation({ mutationFn: () => api("POST", `/api/cases/${id}/close`), onSuccess: done });
  const d = q.data;
  if (!d) return <ErrorBox error={q.error} />;
  const open = d.status === "open";
  return (
    <section className="card mt-4">
      <h2 className="font-medium">#{d.id} {d.title} <span className="text-sm text-slate-500">({t(`cases.s.${d.status}`)})</span></h2>
      <p className="text-sm text-slate-600">{d.description}</p>
      <ErrorBox error={addNote.error ?? addEvent.error ?? close.error} />
      <ul className="mt-2 space-y-1 text-sm">
        {d.items.map((i) => (
          <li key={i.id} className="border-b border-slate-100 py-1">
            <span className="text-slate-500">{new Date(i.added_at).toLocaleString()} · {i.added_by} · {t(`cases.k.${i.kind}`)}</span>
            {i.kind === "note" ? <div>{String(i.content?.text ?? "")}</div>
              : <pre className="max-h-32 overflow-auto text-xs">{i.content ? JSON.stringify(i.content, null, 1) : t("cases.hidden")}</pre>}
          </li>
        ))}
      </ul>
      {open && canWrite && (
        <div className="mt-3 space-y-2">
          <div className="flex gap-2"><input className="input flex-1" aria-label={t("cases.note")} value={note} onChange={(e) => setNote(e.target.value)} />
            <button className="btn" disabled={!note || addNote.isPending} onClick={() => addNote.mutate()}>{t("cases.add_note")}</button></div>
          <div className="flex flex-wrap gap-2">
            <input className="input w-72" aria-label={t("cases.index")} value={index} onChange={(e) => setIndex(e.target.value)} />
            <input className="input w-64" aria-label={t("cases.event_id")} value={eid} onChange={(e) => setEid(e.target.value)} />
            <button className="btn" disabled={!index || !eid || addEvent.isPending} onClick={() => addEvent.mutate()}>{t("cases.add_event")}</button>
          </div>
          <button className="btn-secondary" disabled={close.isPending} onClick={() => confirm(t("cases.close_confirm")) && close.mutate()}>{t("cases.close")}</button>
        </div>
      )}
      {!open && (
        <div className="mt-3 text-sm">
          <p>{t("cases.closed_info", { at: d.closed_at ? new Date(d.closed_at).toLocaleString() : "", months: d.retention_months })}</p>
          <code className="block break-all text-xs">SHA-256: {d.package_sha256}</code>
          <button className="btn mt-2" onClick={() => download(d.id)}>{t("cases.download")}</button>
        </div>
      )}
    </section>
  );
}

export default function CasesPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["cases"], queryFn: () => api<Case[]>("GET", "/api/cases") });
  const [title, setTitle] = useState("");
  const [desc, setDesc] = useState("");
  const [sel, setSel] = useState<number | null>(null);
  const create = useMutation({
    mutationFn: () => api<Case>("POST", "/api/cases", { title, description: desc }),
    onSuccess: (c) => { setTitle(""); setDesc(""); setSel(c.id); qc.invalidateQueries({ queryKey: ["cases"] }); },
  });
  return (
    <div className="max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold">{t("cases.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("cases.intro")}</p>
      <ErrorBox error={q.error ?? create.error} />
      {canWrite && (
        <div className="card mb-4 flex flex-wrap items-end gap-3">
          <div><label className="label" htmlFor="c-t">{t("cases.name")}</label><input id="c-t" className="input w-64" value={title} onChange={(e) => setTitle(e.target.value)} /></div>
          <div className="flex-1"><label className="label" htmlFor="c-d">{t("cases.desc")}</label><input id="c-d" className="input w-full" value={desc} onChange={(e) => setDesc(e.target.value)} /></div>
          <button className="btn" disabled={!title || create.isPending} onClick={() => create.mutate()}>{t("cases.create")}</button>
        </div>
      )}
      <section className="card">
        <table className="w-full text-left text-sm">
          <tbody>
            {(q.data ?? []).map((c) => (
              <tr key={c.id} className="cursor-pointer border-b border-slate-100 hover:bg-slate-50" onClick={() => setSel(c.id)}>
                <td className="py-1">#{c.id}</td><td>{c.title}</td><td>{t(`cases.s.${c.status}`)}</td><td>{c.created_by}</td><td>{new Date(c.created_at).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      {sel !== null && <CaseView id={sel} canWrite={canWrite} />}
    </div>
  );
}
