import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import QRCode from "qrcode";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Device = { id: number; name: string; primary: boolean; created_at: string | null };
type View = { devices: Device[]; max: number };

// Mein Konto: mehrere MFA-Geräte (z. B. zweites Handy als Ersatz) verwalten
export default function MfaDevices() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["mfa-devices"], queryFn: () => api<View>("GET", "/api/auth/mfa/devices") });
  const [name, setName] = useState("");
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [delId, setDelId] = useState<number | null>(null);
  const [pw, setPw] = useState("");
  const canvas = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    if (setup && canvas.current) QRCode.toCanvas(canvas.current, setup.uri, { width: 180, margin: 1 });
  }, [setup]);
  const done = (v: View) => { qc.setQueryData(["mfa-devices"], v); setSetup(null); setCode(""); setName(""); setDelId(null); setPw(""); };
  const add = useMutation({ mutationFn: () => api<{ secret: string; uri: string }>("POST", "/api/auth/mfa/devices", { name }), onSuccess: setSetup });
  const enable = useMutation({ mutationFn: () => api<View>("POST", "/api/auth/mfa/devices/enable", { code }), onSuccess: done });
  const del = useMutation({ mutationFn: (id: number) => api<View>("POST", `/api/auth/mfa/devices/${id}/delete`, { current_password: pw }), onSuccess: done });
  const list = q.data?.devices ?? [];
  const count = list.length;
  const max = q.data?.max ?? 5;
  const canAdd = !setup && Boolean(count) && Boolean(max - count);
  return (
    <section className="card mt-4 max-w-xl">
      <h2 className="mb-1 font-medium">{t("mfa.title")}</h2>
      <p className="mb-3 text-sm text-slate-600">{t("mfa.intro")}</p>
      <ErrorBox error={q.error ?? add.error ?? enable.error ?? del.error} />
      {list.length === 0 && <p className="text-sm text-slate-600">{t("mfa.none")}</p>}
      <ul className="mb-3 text-sm">
        {list.map((d) => (
          <li key={d.id} className="flex items-center justify-between border-b border-slate-100 py-1">
            <span>{d.primary ? t("mfa.primary") : d.name}{d.created_at ? <span className="ml-2 text-xs text-slate-500">{d.created_at.slice(0, 10)}</span> : null}</span>
            {list.length > 1 && <button className="btn-secondary" onClick={() => setDelId(d.id)}>{t("mfa.remove")}</button>}
          </li>
        ))}
      </ul>
      {delId !== null && (
        <div className="mb-3 flex items-end gap-2">
          <div>
            <label className="label" htmlFor="mfa-pw">{t("mfa.confirm_password")}</label>
            <input id="mfa-pw" className="input" type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} />
          </div>
          <button className="btn-danger" disabled={!pw || del.isPending} onClick={() => del.mutate(delId)}>{t("mfa.remove")}</button>
          <button className="btn-secondary" onClick={() => { setDelId(null); setPw(""); }}>{t("common.cancel")}</button>
        </div>
      )}
      {canAdd && (
        <div className="flex items-end gap-2">
          <div>
            <label className="label" htmlFor="mfa-name">{t("mfa.device_name")}</label>
            <input id="mfa-name" className="input" maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <button className="btn" disabled={!name.trim() || add.isPending} onClick={() => add.mutate()}>{t("mfa.add")}</button>
        </div>
      )}
      {setup && (
        <div>
          <p className="mb-2 text-sm text-slate-600">{t("mfa.scan")}</p>
          <canvas ref={canvas} className="mb-2" />
          <p className="mb-3 break-all font-mono text-xs text-slate-500">{setup.secret}</p>
          <div className="flex items-end gap-2">
            <div>
              <label className="label" htmlFor="mfa-code">{t("auth.code")}</label>
              <input id="mfa-code" className="input w-32" inputMode="numeric" autoComplete="one-time-code" maxLength={8} value={code} onChange={(e) => setCode(e.target.value)} />
            </div>
            <button className="btn" disabled={code.length < 6 || enable.isPending} onClick={() => enable.mutate()}>{t("mfa.confirm")}</button>
            <button className="btn-secondary" onClick={() => { setSetup(null); setCode(""); }}>{t("common.cancel")}</button>
          </div>
        </div>
      )}
    </section>
  );
}
