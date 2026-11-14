import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type User = { user: string; auth_proto: "sha" | "sha256"; priv_proto: "none" | "aes128" | "aes256"; engine_id: string };
type View = { communities: number; v3_users: User[] };
type Row = User & { auth_key: string; priv_key: string };

const blank = (): Row => ({ user: "", auth_proto: "sha", priv_proto: "aes128", auth_key: "", priv_key: "", engine_id: "" });

export default function SnmpPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["snmp"], queryFn: () => api<View>("GET", "/api/snmp") });
  const [communities, setCommunities] = useState("");
  const [rows, setRows] = useState<Row[]>([]);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (q.data) setRows(q.data.v3_users.map((u) => ({ ...u, auth_key: "", priv_key: "" })));
  }, [q.data]);

  const save = useMutation({
    mutationFn: () =>
      api<View>("PUT", "/api/snmp", {
        communities: communities.trim() ? communities.split("\n").map((x) => x.trim()).filter(Boolean) : null,
        v3_users: rows.map((r) => ({ ...r, auth_key: r.auth_key || null, priv_key: r.priv_key || null })),
      }),
    onSuccess: (d) => { setSaved(true); setCommunities(""); qc.setQueryData(["snmp"], d); },
    onError: () => setSaved(false),
  });
  const set = (i: number, patch: Partial<Row>) => {
    setSaved(false);
    setRows(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  };

  return (
    <div className="max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold">{t("snmp.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("snmp.intro")}</p>
      <ErrorBox error={q.error ?? save.error} />
      <section className="card mb-4">
        <h2 className="mb-2 font-medium">{t("snmp.v2c")}</h2>
        <p className="mb-2 text-sm text-slate-600">{t("snmp.v2c_text", { count: q.data?.communities ?? 0 })}</p>
        <textarea className="input h-20 font-mono text-xs" aria-label={t("snmp.v2c")} value={communities} disabled={!canWrite}
          placeholder={t("snmp.ph_communities")} onChange={(e) => { setSaved(false); setCommunities(e.target.value); }} />
      </section>
      <section className="card mb-4">
        <h2 className="mb-2 font-medium">{t("snmp.v3")}</h2>
        <p className="mb-2 text-sm text-slate-600">{t("snmp.v3_text")}</p>
        {rows.map((r, i) => (
          <div key={i} className="mb-3 grid gap-2 md:grid-cols-6">
            <input className="input" aria-label={t("snmp.user")} placeholder={t("snmp.user")} value={r.user} disabled={!canWrite}
              onChange={(e) => set(i, { user: e.target.value })} />
            <select className="input" aria-label={t("snmp.auth")} value={r.auth_proto} disabled={!canWrite}
              onChange={(e) => set(i, { auth_proto: e.target.value as Row["auth_proto"] })}>
              <option value="sha">{t("snmp.sha1")}</option>
              <option value="sha256">{t("snmp.sha256")}</option>
            </select>
            <input className="input" type="password" autoComplete="off" aria-label={t("snmp.auth_key")} placeholder={t("snmp.auth_key")}
              value={r.auth_key} disabled={!canWrite} onChange={(e) => set(i, { auth_key: e.target.value })} />
            <select className="input" aria-label={t("snmp.priv")} value={r.priv_proto} disabled={!canWrite}
              onChange={(e) => set(i, { priv_proto: e.target.value as Row["priv_proto"] })}>
              <option value="none">{t("snmp.no_priv")}</option>
              <option value="aes128">{t("snmp.aes128")}</option>
              <option value="aes256">{t("snmp.aes256")}</option>
            </select>
            <input className="input" type="password" autoComplete="off" aria-label={t("snmp.priv_key")} placeholder={t("snmp.priv_key")}
              value={r.priv_key} disabled={!canWrite || r.priv_proto === "none"} onChange={(e) => set(i, { priv_key: e.target.value })} />
            <input className="input md:col-span-5 font-mono text-xs" aria-label={t("snmp.engine_id")} placeholder={t("snmp.engine_id")}
              value={r.engine_id} disabled={!canWrite} onChange={(e) => set(i, { engine_id: e.target.value })} />
            {canWrite && (
              <button className="btn" onClick={() => { setSaved(false); setRows(rows.filter((_, j) => j !== i)); }}>
                {t("common.delete")}
              </button>
            )}
          </div>
        ))}
        {canWrite && <button className="btn" onClick={() => setRows([...rows, blank()])}>{t("snmp.add_user")}</button>}
        <p className="mt-2 text-xs text-slate-500">{t("snmp.keys_hint")}</p>
      </section>
      {canWrite && (
        <div className="flex items-center gap-3">
          <button className="btn" disabled={save.isPending} onClick={() => save.mutate()}>{t("common.save")}</button>
          {saved && <span className="text-sm text-green-700">{t("snmp.saved")}</span>}
        </div>
      )}
    </div>
  );
}
