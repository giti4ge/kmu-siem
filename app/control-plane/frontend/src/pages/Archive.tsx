import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Cat = { files: number; bytes: number; sealed: number; last_sealed: string | null; oldest: string | null; newest: string | null };
type Worker = { seal?: { at: string; ok: boolean; sealed?: number; waiting?: number }; verify?: { at: string; ok: boolean; checked_files: number; problem_count: number } };
type Data = { categories: Record<string, Cat>; bytes: number; public_key: string; algorithm: string; worker: Worker };
type Problem = { category?: string; file?: string; problem: string };
type Result = { ok: boolean; checked_files: number; problem_count: number; problems: Problem[] };

type Ret = { default: number; days: Record<string, number>; min: number; max: number; restore_days: number; restore_max_days: number };
type Restore = { id: string; category: string; since: string; until: string; actor: string; expires: string; status: string; events: number; error: string | null };

function Retention({ canWrite, cats }: { canWrite: boolean; cats: string[] }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["archive-ret"], queryFn: () => api<Ret>("GET", "/api/archive/retention") });
  const [edit, setEdit] = useState<Ret | null>(null);
  const save = useMutation({
    mutationFn: (r: Ret) => api("PUT", "/api/archive/retention", { default: r.default, days: r.days }),
    onSuccess: () => { setEdit(null); qc.invalidateQueries({ queryKey: ["archive-ret"] }); },
  });
  const r = edit ?? q.data;
  if (!r) return null;
  const set = (c: string | null, v: number) => setEdit(c === null ? { ...r, default: v } : { ...r, days: { ...r.days, [c]: v } });
  return (
    <section className="card mt-4">
      <h2 className="mb-1 font-medium">{t("archive.ret_title")}</h2>
      <p className="mb-2 text-sm text-slate-600">{t("archive.ret_intro", { min: r.min, max: r.max })}</p>
      <ErrorBox error={q.error ?? save.error} />
      <div className="flex flex-wrap items-end gap-3">
        <div><label className="label" htmlFor="rt-d">{t("archive.ret_default")}</label><input id="rt-d" className="input w-24" type="number" min={r.min} max={r.max} disabled={!canWrite} value={r.default} onChange={(e) => set(null, Number(e.target.value))} /></div>
        {cats.map((c) => (
          <div key={c}><label className="label" htmlFor={`rt-${c}`}>{c}</label><input id={`rt-${c}`} className="input w-24" type="number" min={r.min} max={r.max} disabled={!canWrite} value={r.days[c] ?? r.default} onChange={(e) => set(c, Number(e.target.value))} /></div>
        ))}
        {canWrite && edit && <button className="btn" disabled={save.isPending} onClick={() => save.mutate(edit)}>{t("archive.save")}</button>}
      </div>
    </section>
  );
}

type Tgt = { tsa_url: string; target: { type: string; subdir?: string; endpoint?: string; bucket?: string; region?: string; access_key?: string; prefix?: string; lock_days?: number; has_secret?: boolean }; worker: { replicate?: { at: string; replicated: number; failed: number; error?: string }; stamp?: { at: string; stamped: number; error?: string } } };

function Target({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["archive-tgt"], queryFn: () => api<Tgt>("GET", "/api/archive/target") });
  const [edit, setEdit] = useState<Tgt | null>(null);
  const [secret, setSecret] = useState("");
  const refresh = () => qc.invalidateQueries({ queryKey: ["archive-tgt"] });
  const save = useMutation({
    mutationFn: (v: Tgt) => api("PUT", "/api/archive/target", { tsa_url: v.tsa_url, target: v.target, secret_key: secret || null }),
    onSuccess: () => { setEdit(null); setSecret(""); refresh(); },
  });
  const repl = useMutation({ mutationFn: () => api("POST", "/api/archive/replicate"), onSettled: refresh });
  const stamp = useMutation({ mutationFn: () => api("POST", "/api/archive/timestamp"), onSettled: refresh });
  const v = edit ?? q.data;
  if (!v) return null;
  const set = (patch: Partial<Tgt["target"]>) => setEdit({ ...v, target: { ...v.target, ...patch } });
  const tg = v.target;
  return (
    <section className="card mt-4">
      <h2 className="mb-1 font-medium">{t("archive.tgt_title")}</h2>
      <p className="mb-2 text-sm text-slate-600">{t("archive.tgt_intro")}</p>
      <ErrorBox error={q.error ?? save.error ?? repl.error ?? stamp.error} />
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2"><label className="label" htmlFor="tg-tsa">{t("archive.tsa_url")}</label><input id="tg-tsa" className="input" disabled={!canWrite} value={v.tsa_url} onChange={(e) => setEdit({ ...v, tsa_url: e.target.value })} /></div>
        <div><label className="label" htmlFor="tg-type">{t("archive.tgt_type")}</label>
          <select id="tg-type" className="input" disabled={!canWrite} value={tg.type} onChange={(e) => set({ type: e.target.value })}>
            <option value="none">{t("archive.tgt_none")}</option><option value="dir">{t("archive.tgt_dir")}</option><option value="s3">S3</option></select></div>
        {tg.type === "dir" && <div><label className="label" htmlFor="tg-sub">{t("archive.tgt_subdir")}</label><input id="tg-sub" className="input" disabled={!canWrite} value={tg.subdir ?? ""} onChange={(e) => set({ subdir: e.target.value })} /></div>}
        {tg.type === "s3" && (<>
          <div><label className="label" htmlFor="tg-ep">{t("archive.s3_endpoint")}</label><input id="tg-ep" className="input" disabled={!canWrite} value={tg.endpoint ?? ""} onChange={(e) => set({ endpoint: e.target.value })} /></div>
          <div><label className="label" htmlFor="tg-b">{t("archive.s3_bucket")}</label><input id="tg-b" className="input" disabled={!canWrite} value={tg.bucket ?? ""} onChange={(e) => set({ bucket: e.target.value })} /></div>
          <div><label className="label" htmlFor="tg-r">{t("archive.s3_region")}</label><input id="tg-r" className="input" disabled={!canWrite} value={tg.region ?? "us-east-1"} onChange={(e) => set({ region: e.target.value })} /></div>
          <div><label className="label" htmlFor="tg-p">{t("archive.s3_prefix")}</label><input id="tg-p" className="input" disabled={!canWrite} value={tg.prefix ?? ""} onChange={(e) => set({ prefix: e.target.value })} /></div>
          <div><label className="label" htmlFor="tg-ak">{t("archive.s3_access")}</label><input id="tg-ak" className="input" disabled={!canWrite} value={tg.access_key ?? ""} onChange={(e) => set({ access_key: e.target.value })} /></div>
          <div><label className="label" htmlFor="tg-sk">{t("archive.s3_secret")} {tg.has_secret ? `(${t("archive.tgt_kept")})` : ""}</label><input id="tg-sk" className="input" type="password" autoComplete="new-password" disabled={!canWrite} value={secret} onChange={(e) => setSecret(e.target.value)} /></div>
          <div><label className="label" htmlFor="tg-l">{t("archive.tgt_lock")}</label><input id="tg-l" className="input w-28" type="number" min={0} max={3650} disabled={!canWrite} value={tg.lock_days ?? 0} onChange={(e) => set({ lock_days: Number(e.target.value) })} /></div>
        </>)}
      </div>
      {canWrite && (
        <div className="mt-3 flex flex-wrap gap-2">
          <button className="btn" disabled={!edit || save.isPending} onClick={() => edit && save.mutate(edit)}>{t("archive.save")}</button>
          <button className="btn-secondary" disabled={repl.isPending} onClick={() => repl.mutate()}>{t("archive.tgt_replicate")}</button>
          <button className="btn-secondary" disabled={stamp.isPending} onClick={() => stamp.mutate()}>{t("archive.tsa_now")}</button>
        </div>
      )}
      <p className="mt-2 text-xs text-slate-600">
        {t("archive.tgt_last_repl")}: {q.data?.worker.replicate ? `${new Date(q.data.worker.replicate.at).toLocaleString()} – ${q.data.worker.replicate.replicated} / ${q.data.worker.replicate.failed}` : "–"}
        {" · "}{t("archive.tsa_last")}: {q.data?.worker.stamp ? `${new Date(q.data.worker.stamp.at).toLocaleString()} – ${q.data.worker.stamp.stamped}` : "–"}
      </p>
    </section>
  );
}

function Restores({ canWrite, cats }: { canWrite: boolean; cats: string[] }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["archive-restores"], queryFn: () => api<Restore[]>("GET", "/api/archive/restores"), refetchInterval: 5000 });
  const [cat, setCat] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [days, setDays] = useState(14);
  const [approvalId, setApprovalId] = useState("");
  const done = () => qc.invalidateQueries({ queryKey: ["archive-restores"] });
  const start = useMutation({ mutationFn: () => api("POST", "/api/archive/restores", { category: cat || cats[0], since, until, days, approval_id: approvalId || null }), onSettled: done });
  const del = useMutation({ mutationFn: (id: string) => api("DELETE", `/api/archive/restores/${id}`), onSettled: done });
  return (
    <section className="card mt-4">
      <h2 className="mb-1 font-medium">{t("archive.rest_title")}</h2>
      <p className="mb-2 text-sm text-slate-600">{t("archive.rest_intro")}</p>
      <ErrorBox error={q.error ?? start.error ?? del.error} />
      {canWrite && (
        <div className="mb-3 flex flex-wrap items-end gap-3">
          <div><label className="label" htmlFor="rs-c">{t("archive.category")}</label><select id="rs-c" className="input" value={cat || cats[0] || ""} onChange={(e) => setCat(e.target.value)}>{cats.map((c) => <option key={c}>{c}</option>)}</select></div>
          <div><label className="label" htmlFor="rs-s">{t("archive.since")}</label><input id="rs-s" className="input" type="date" value={since} onChange={(e) => setSince(e.target.value)} /></div>
          <div><label className="label" htmlFor="rs-u">{t("archive.until")}</label><input id="rs-u" className="input" type="date" value={until} onChange={(e) => setUntil(e.target.value)} /></div>
          <div><label className="label" htmlFor="rs-d">{t("archive.rest_days")}</label><input id="rs-d" className="input w-20" type="number" min={1} max={90} value={days} onChange={(e) => setDays(Number(e.target.value))} /></div>
          <div><label className="label" htmlFor="rs-a">{t("archive.rest_approval")}</label><input id="rs-a" className="input w-32" value={approvalId} onChange={(e) => setApprovalId(e.target.value)} /></div>
          <button className="btn" disabled={!since || !until || start.isPending} onClick={() => start.mutate()}>{t("archive.rest_start")}</button>
        </div>
      )}
      <table className="w-full text-left text-sm">
        <tbody>
          {(q.data ?? []).map((r) => (
            <tr key={r.id} className="border-b border-slate-100">
              <td className="py-1">{r.category} {r.since} – {r.until}</td>
              <td className={r.status === "failed" ? "text-red-700" : ""}>{t(`archive.rs.${r.status}`)}{r.status === "done" ? ` (${r.events})` : ""}{r.error ? `: ${r.error}` : ""}</td>
              <td>{t("archive.rest_expires", { at: new Date(r.expires).toLocaleDateString() })}</td>
              <td>{canWrite && r.status !== "running" && <button className="btn-secondary" onClick={() => del.mutate(r.id)}>{t("archive.rest_delete")}</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

const mb = (b: number) => `${(b / 1048576).toFixed(1)} MB`;

export default function ArchivePage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["archive"], queryFn: () => api<Data>("GET", "/api/archive"), refetchInterval: 30000 });
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const done = () => qc.invalidateQueries({ queryKey: ["archive"] });
  const seal = useMutation({ mutationFn: () => api("POST", "/api/archive/seal"), onSettled: done });
  const verify = useMutation({
    mutationFn: () => api<Result>("POST", "/api/archive/verify", { since: since || null, until: until || null }),
    onSettled: done,
  });
  const d = q.data;
  const w = d?.worker;
  return (
    <div className="max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold">{t("archive.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("archive.intro")}</p>
      <ErrorBox error={q.error ?? seal.error ?? verify.error} />
      <section className="card">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b text-slate-500">
              <th className="py-1">{t("archive.category")}</th><th>{t("archive.files")}</th><th>{t("archive.size")}</th>
              <th>{t("archive.sealed")}</th><th>{t("archive.last_sealed")}</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(d?.categories ?? {}).map(([c, v]) => (
              <tr key={c} className="border-b border-slate-100">
                <td className="py-1">{c}</td><td>{v.files}</td><td>{mb(v.bytes)}</td>
                <td className={v.sealed < v.files ? "text-yellow-700" : ""}>{v.sealed}</td>
                <td>{v.last_sealed ? new Date(v.last_sealed).toLocaleString() : "–"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {d && Object.keys(d.categories).length === 0 && <p className="text-sm text-slate-500">{t("archive.empty")}</p>}
        {d && <p className="mt-2 text-sm">{t("archive.total", { size: mb(d.bytes) })}</p>}
      </section>
      <section className="card mt-4">
        <h2 className="mb-1 font-medium">{t("archive.verify_title")}</h2>
        <p className="text-sm">
          {t("archive.last_seal")}: {w?.seal ? `${new Date(w.seal.at).toLocaleString()} – ${w.seal.ok ? t("archive.ok") : t("archive.failed")}` : "–"}
        </p>
        <p className={`text-sm ${w?.verify && !w.verify.ok ? "text-red-700" : ""}`}>
          {t("archive.last_verify")}: {w?.verify ? `${new Date(w.verify.at).toLocaleString()} – ${w.verify.ok ? t("archive.ok") : t("archive.problems", { n: w.verify.problem_count })} (${w.verify.checked_files})` : "–"}
        </p>
        {canWrite && (
          <div className="mt-3 flex flex-wrap items-end gap-3">
            <div><label className="label" htmlFor="ar-s">{t("archive.since")}</label><input id="ar-s" className="input" type="date" value={since} onChange={(e) => setSince(e.target.value)} /></div>
            <div><label className="label" htmlFor="ar-u">{t("archive.until")}</label><input id="ar-u" className="input" type="date" value={until} onChange={(e) => setUntil(e.target.value)} /></div>
            <button className="btn" disabled={verify.isPending} onClick={() => verify.mutate()}>{t("archive.verify")}</button>
            <button className="btn-secondary" disabled={seal.isPending} onClick={() => seal.mutate()}>{t("archive.seal")}</button>
          </div>
        )}
        {verify.data && (
          <div className={`mt-3 rounded p-2 text-sm ${verify.data.ok ? "bg-green-50" : "bg-red-50"}`}>
            {verify.data.ok ? t("archive.result_ok", { n: verify.data.checked_files }) : t("archive.result_bad", { n: verify.data.problem_count })}
            <ul className="mt-1 list-disc pl-5 text-xs">
              {verify.data.problems.slice(0, 20).map((p, i) => (
                <li key={i}>{p.category}/{p.file ?? ""}: {t(`archive.p.${p.problem}`, { defaultValue: p.problem })}</li>
              ))}
            </ul>
          </div>
        )}
      </section>
      <Retention canWrite={canWrite} cats={Object.keys(d?.categories ?? {})} />
      <Restores canWrite={canWrite} cats={Object.keys(d?.categories ?? {})} />
      <Target canWrite={canWrite} />
      <section className="card mt-4">
        <h2 className="mb-1 font-medium">{t("archive.key_title")}</h2>
        <p className="text-sm text-slate-600">{t("archive.key_intro", { alg: d?.algorithm ?? "Ed25519" })}</p>
        <code className="mt-1 block break-all text-xs">{d?.public_key}</code>
      </section>
    </div>
  );
}
