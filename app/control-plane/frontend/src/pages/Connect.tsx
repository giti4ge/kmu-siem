import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Tls = { host: string; port: number; ca_sha256: string; ca_subject: string; ca_expires: string; snippets: Record<string, string> };
type Snap = { name: string; bytes: number; sha256: string };

async function downloadCa() {
  const res = await fetch("/api/onboarding/ca.crt", { credentials: "same-origin" });
  if (!res.ok) return;
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = "ca.crt";
  a.click();
  URL.revokeObjectURL(url);
}

function Snapshots({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["snaps"], queryFn: () => api<Snap[]>("GET", "/api/snapshots") });
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const take = useMutation({ mutationFn: () => api<{ changed: boolean }>("POST", "/api/snapshots"), onSettled: () => qc.invalidateQueries({ queryKey: ["snaps"] }) });
  const diff = useMutation({ mutationFn: () => api<{ lines: string[] }>("GET", `/api/snapshots/diff?a=${a}&b=${b}`) });
  const names = (q.data ?? []).map((s) => s.name);
  return (
    <section className="card mt-4">
      <h2 className="mb-1 font-medium">{t("connect.snap_title")}</h2>
      <p className="mb-2 text-sm text-slate-600">{t("connect.snap_intro")}</p>
      <ErrorBox error={q.error ?? take.error ?? diff.error} />
      {canWrite && <button className="btn" disabled={take.isPending} onClick={() => take.mutate()}>{t("connect.snap_take")}</button>}
      {take.data && <span className="ml-2 text-sm">{take.data.changed ? t("connect.snap_changed") : t("connect.snap_same")}</span>}
      <ul className="mt-2 text-sm">{names.map((n) => <li key={n}>{n}</li>)}</ul>
      {names.length > 1 && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <select className="input w-52" aria-label="A" value={a} onChange={(e) => setA(e.target.value)}><option value="" />{names.map((n) => <option key={n}>{n}</option>)}</select>
          <select className="input w-52" aria-label="B" value={b} onChange={(e) => setB(e.target.value)}><option value="" />{names.map((n) => <option key={n}>{n}</option>)}</select>
          <button className="btn-secondary" disabled={!a || !b} onClick={() => diff.mutate()}>{t("connect.snap_diff")}</button>
        </div>
      )}
      {diff.data && <pre className="mt-2 max-h-80 overflow-auto bg-slate-50 p-2 text-xs">{diff.data.lines.join("\n") || t("connect.snap_same")}</pre>}
    </section>
  );
}

export default function ConnectPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["tls"], queryFn: () => api<Tls>("GET", "/api/onboarding/tls") });
  const d = q.data;
  return (
    <div className="max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold">{t("connect.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("connect.intro")}</p>
      <ErrorBox error={q.error} />
      {d && (
        <section className="card">
          <p className="text-sm">{t("connect.target", { host: d.host, port: d.port })}</p>
          <p className="break-all text-xs">{d.ca_subject} · SHA-256 {d.ca_sha256} · {t("connect.expires", { at: new Date(d.ca_expires).toLocaleDateString() })}</p>
          <button className="btn mt-2" onClick={() => downloadCa()}>{t("connect.download_ca")}</button>
          {Object.entries(d.snippets).map(([k, v]) => (
            <div key={k} className="mt-3"><h3 className="text-sm font-medium">{t(`connect.snip.${k}`)}</h3><pre className="overflow-auto bg-slate-50 p-2 text-xs">{v}</pre></div>
          ))}
        </section>
      )}
      <Snapshots canWrite={canWrite} />
    </div>
  );
}
