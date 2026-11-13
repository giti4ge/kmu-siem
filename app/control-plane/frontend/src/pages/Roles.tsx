import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, type Role } from "../api";
import { ErrorBox } from "./Auth";

const ACTIONS = ["read", "write", "approve"] as const;

// Berechtigungs-Matrix Modul × Aktion (nur existierende Kombinationen sind wählbar)
function Matrix({ all, value, onChange, readOnly }: { all: string[]; value: string[]; onChange?: (v: string[]) => void; readOnly?: boolean }) {
  const { t } = useTranslation();
  const modules = [...new Set(all.map((p) => p.split(":")[0]))];
  return (
    <table className="table">
      <thead><tr><th>{t("roles.module")}</th>{ACTIONS.map((a) => <th key={a}>{t(`roles.action.${a}`)}</th>)}</tr></thead>
      <tbody>
        {modules.map((m) => (
          <tr key={m}>
            <td>{t(`modules.${m}`)}</td>
            {ACTIONS.map((a) => {
              const p = `${m}:${a}`;
              return (
                <td key={a}>
                  {all.includes(p) && (
                    <input type="checkbox" aria-label={p} checked={value.includes(p)} disabled={readOnly}
                      onChange={(e) => onChange?.(e.target.checked ? [...value, p] : value.filter((x) => x !== p))} />
                  )}
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function RolesPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => api<Role[]>("GET", "/api/roles") });
  const perms = useQuery({ queryKey: ["permissions"], queryFn: () => api<string[]>("GET", "/api/permissions") });
  const [sel, setSel] = useState<Role | "new" | null>(null);
  const done = () => { setSel(null); qc.invalidateQueries({ queryKey: ["roles"] }); };
  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold">{t("nav.roles")}</h1>
        {canWrite && <button className="btn" onClick={() => setSel("new")}>{t("roles.new")}</button>}
      </div>
      <ErrorBox error={roles.error} />
      {sel && perms.data && <RoleEditor role={sel === "new" ? null : sel} all={perms.data} canWrite={canWrite} onDone={done} />}
      <div className="card">
        <table className="table">
          <thead><tr><th>{t("roles.name")}</th><th>{t("roles.description")}</th><th>{t("roles.mfa")}</th><th /></tr></thead>
          <tbody>
            {roles.data?.map((r) => (
              <tr key={r.id}>
                <td>{r.builtin ? t(`roles.builtin.${r.name}`, { defaultValue: r.name }) : r.name}</td>
                <td>{r.builtin ? t(`roles.builtin_desc.${r.name}`, { defaultValue: r.description }) : r.description}</td>
                <td>{r.mfa_required ? t("common.yes") : t("common.no")}</td>
                <td><button className="btn-secondary" onClick={() => setSel(r)}>{r.builtin || !canWrite ? t("common.show") : t("common.edit")}</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RoleEditor({ role, all, canWrite, onDone }: { role: Role | null; all: string[]; canWrite: boolean; onDone: () => void }) {
  const { t } = useTranslation();
  const editable = canWrite && !role?.builtin;
  const [name, setName] = useState(role?.name ?? "");
  const [desc, setDesc] = useState(role?.description ?? "");
  const [mfa, setMfa] = useState(role?.mfa_required ?? false);
  const [perms, setPerms] = useState<string[]>(role?.permissions ?? []);
  const [cats, setCats] = useState((role?.data_scope.categories ?? []).join(", "));
  const body = () => ({
    description: desc, mfa_required: mfa, permissions: perms,
    data_scope: { categories: cats.split(",").map((c) => c.trim()).filter(Boolean), masked_fields: role?.data_scope.masked_fields ?? [] },
  });
  const save = useMutation({
    mutationFn: () => (role ? api("PATCH", `/api/roles/${role.id}`, body()) : api("POST", "/api/roles", { name, ...body() })),
    onSuccess: onDone,
  });
  const del = useMutation({ mutationFn: () => api("DELETE", `/api/roles/${role!.id}`), onSuccess: onDone });
  return (
    <div className="card mb-4 flex flex-col gap-3">
      <ErrorBox error={save.error || del.error} />
      {role?.builtin && <p className="text-sm text-slate-500">{t("roles.builtin_hint")}</p>}
      <div className="grid gap-3 md:grid-cols-2">
        <div><label className="label" htmlFor="r-n">{t("roles.name")}</label>
          <input id="r-n" className="input" value={name} disabled={!!role} onChange={(e) => setName(e.target.value)} pattern="[a-z][a-z0-9-]{1,63}" /></div>
        <div><label className="label" htmlFor="r-d">{t("roles.description")}</label>
          <input id="r-d" className="input" value={desc} disabled={!editable} onChange={(e) => setDesc(e.target.value)} /></div>
        <div className="md:col-span-2"><label className="label" htmlFor="r-c">{t("roles.categories")}</label>
          <input id="r-c" className="input" value={cats} disabled={!editable} onChange={(e) => setCats(e.target.value)} />
          <p className="mt-1 text-xs text-slate-500">{t("roles.categories_hint")}</p></div>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={mfa} disabled={!editable} onChange={(e) => setMfa(e.target.checked)} />{t("roles.mfa")}
      </label>
      <Matrix all={all} value={perms} onChange={setPerms} readOnly={!editable} />
      <div className="flex gap-2">
        {editable && <button className="btn" onClick={() => save.mutate()}>{t("common.save")}</button>}
        <button className="btn-secondary" onClick={onDone}>{t("common.close")}</button>
        {editable && role && <button className="btn-danger" onClick={() => del.mutate()}>{t("common.delete")}</button>}
      </div>
    </div>
  );
}
