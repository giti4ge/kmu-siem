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
      <section className="card mt-4">
        <h2 className="mb-1 font-medium">{t("archive.key_title")}</h2>
        <p className="text-sm text-slate-600">{t("archive.key_intro", { alg: d?.algorithm ?? "Ed25519" })}</p>
        <code className="mt-1 block break-all text-xs">{d?.public_key}</code>
      </section>
    </div>
  );
}
