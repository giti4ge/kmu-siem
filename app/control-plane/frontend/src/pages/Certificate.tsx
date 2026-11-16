import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { FilePick } from "../FilePick";
import { ErrorBox } from "./Auth";

type Tls = {
  custom: boolean; has_backup: boolean; subject?: string; issuer?: string; not_after?: string; fingerprint?: string; san?: string[];
  last?: { ts: string; ok: boolean; what: string; error: string };
};

function toBase64(buf: ArrayBuffer) {
  let s = "";
  new Uint8Array(buf).forEach((b) => { s += String.fromCharCode(b); });
  return btoa(s);
}

// Web-Zertifikat (HTTPS der Appliance): eigenes Zertifikat als PFX einspielen, zurücksetzen
export default function Certificate({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [pending, setPending] = useState(false);
  const q = useQuery({ queryKey: ["tls"], queryFn: () => api<Tls>("GET", "/api/tls"), refetchInterval: pending ? 4000 : false, retry: pending });
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const started = () => { setPending(true); setTimeout(() => { setPending(false); qc.invalidateQueries({ queryKey: ["tls"] }); }, 30000); };
  const upload = useMutation({
    mutationFn: async () => api("POST", "/api/tls/pfx", { pfx_b64: toBase64(await file!.arrayBuffer()), password }),
    onSuccess: () => { setFile(null); setPassword(""); started(); },
  });
  const rollback = useMutation({ mutationFn: () => api("POST", "/api/tls/rollback"), onSuccess: started });
  const reset = useMutation({ mutationFn: () => api("POST", "/api/tls/reset"), onSuccess: started });
  const d = q.data;
  return (
    <section className="card mt-4">
      <h2 className="mb-1 font-medium">{t("tls.title")}</h2>
      <p className="mb-2 text-sm text-slate-600">{t("tls.intro")}</p>
      <ErrorBox error={pending ? null : q.error ?? upload.error ?? rollback.error ?? reset.error} />
      {pending && <p className="mb-2 rounded bg-yellow-50 px-3 py-2 text-sm text-yellow-900">{t("tls.applying")}</p>}
      {d && (
        <dl className="mb-3 grid grid-cols-[10rem_1fr] gap-y-1 text-sm">
          <dt className="text-slate-500">{t("tls.source")}</dt><dd>{d.custom ? t("tls.custom") : t("tls.internal")}</dd>
          <dt className="text-slate-500">{t("tls.subject")}</dt><dd className="break-all">{d.subject}</dd>
          <dt className="text-slate-500">{t("tls.san")}</dt><dd className="break-all">{(d.san ?? []).join(", ")}</dd>
          <dt className="text-slate-500">{t("tls.issuer")}</dt><dd className="break-all">{d.issuer}</dd>
          <dt className="text-slate-500">{t("tls.not_after")}</dt><dd>{d.not_after}</dd>
          <dt className="text-slate-500">{t("tls.fingerprint")}</dt><dd className="break-all font-mono text-xs">{d.fingerprint}</dd>
        </dl>
      )}
      {d?.last && !pending && (
        <p className={`mb-3 text-sm ${d.last.ok ? "text-green-700" : "text-red-700"}`}>
          {d.last.ok ? t("tls.last_ok", { ts: d.last.ts }) : t("tls.last_fail", { ts: d.last.ts, error: d.last.error })}
        </p>
      )}
      {canWrite && (
        <div className="flex flex-col gap-2">
          <p className="text-sm text-slate-600">{t("tls.pfx_hint")}</p>
          <div className="flex flex-wrap items-end gap-3">
            <FilePick label={file ? file.name : t("tls.pfx")} accept=".pfx,.p12" onFile={setFile} />
            <div>
              <label className="label" htmlFor="tls-pw">{t("tls.pfx_password")}</label>
              <input id="tls-pw" className="input w-56" type="password" autoComplete="off" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            <button className="btn" disabled={!file || upload.isPending || pending} onClick={() => upload.mutate()}>{t("tls.install")}</button>
          </div>
          <div className="flex gap-2">
            <button className="btn-secondary" disabled={!d?.has_backup || pending} onClick={() => rollback.mutate()}>{t("tls.rollback")}</button>
            <button className="btn-secondary" disabled={!d?.custom || pending} onClick={() => reset.mutate()}>{t("tls.reset")}</button>
          </div>
          <p className="text-xs text-slate-500">{t("tls.note")}</p>
        </div>
      )}
    </section>
  );
}
