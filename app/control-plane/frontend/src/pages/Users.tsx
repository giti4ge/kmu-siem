import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, type Role, type User } from "../api";
import { ErrorBox } from "./Auth";

function RolePicker({ roles, value, onChange }: { roles: Role[]; value: string[]; onChange: (v: string[]) => void }) {
  const { t } = useTranslation();
  return (
    <div className="flex flex-wrap gap-3">
      {roles.map((r) => (
        <label key={r.id} className="flex items-center gap-1 text-sm">
          <input
            type="checkbox"
            checked={value.includes(r.name)}
            onChange={(e) => onChange(e.target.checked ? [...value, r.name] : value.filter((n) => n !== r.name))}
          />
          {r.builtin ? t(`roles.builtin.${r.name}`, { defaultValue: r.name }) : r.name}
        </label>
      ))}
    </div>
  );
}

export default function UsersPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<User[]>("GET", "/api/users") });
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => api<Role[]>("GET", "/api/roles") });
  const [editing, setEditing] = useState<User | null>(null);
  const [creating, setCreating] = useState(false);
  const refresh = () => qc.invalidateQueries({ queryKey: ["users"] });

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold">{t("nav.users")}</h1>
        {canWrite && <button className="btn" onClick={() => { setCreating(true); setEditing(null); }}>{t("users.new")}</button>}
      </div>
      <ErrorBox error={users.error} />
      {creating && roles.data && <CreateUser roles={roles.data} onDone={() => { setCreating(false); refresh(); }} />}
      {editing && roles.data && <EditUser user={editing} roles={roles.data} onDone={() => { setEditing(null); refresh(); }} />}
      <div className="card overflow-x-auto">
        <table className="table">
          <thead>
            <tr>
              <th>{t("users.username")}</th><th>{t("users.display_name")}</th><th>{t("users.roles")}</th>
              <th>{t("users.mfa")}</th><th>{t("users.status")}</th><th>{t("users.last_login")}</th><th />
            </tr>
          </thead>
          <tbody>
            {users.data?.map((u) => (
              <tr key={u.id}>
                <td className="font-mono">{u.username}</td>
                <td>{u.display_name}</td>
                <td>{u.roles.map((r) => t(`roles.builtin.${r.name}`, { defaultValue: r.name })).join(", ")}</td>
                <td>{u.totp_enabled ? t("common.yes") : t("common.no")}</td>
                <td>{u.enabled ? t("users.enabled") : t("users.disabled")}</td>
                <td>{u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "–"}</td>
                <td>{canWrite && <button className="btn-secondary" onClick={() => { setEditing(u); setCreating(false); }}>{t("common.edit")}</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function CreateUser({ roles, onDone }: { roles: Role[]; onDone: () => void }) {
  const { t } = useTranslation();
  const [f, setF] = useState({ username: "", display_name: "", email: "", language: "de", password: "" });
  const [sel, setSel] = useState<string[]>([]);
  const m = useMutation({ mutationFn: () => api("POST", "/api/users", { ...f, roles: sel }), onSuccess: onDone });
  const submit = (e: FormEvent) => { e.preventDefault(); m.mutate(); };
  const field = (k: keyof typeof f, type = "text") => (
    <div>
      <label className="label" htmlFor={`cu-${k}`}>{t(`users.${k}`)}</label>
      <input id={`cu-${k}`} className="input" type={type} value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })}
        required={k === "username" || k === "password"} autoComplete="off" />
    </div>
  );
  return (
    <form onSubmit={submit} className="card mb-4 grid gap-3 md:grid-cols-2">
      <div className="md:col-span-2"><ErrorBox error={m.error} /></div>
      {field("username")}{field("display_name")}{field("email", "email")}{field("password", "password")}
      <div className="md:col-span-2">
        <span className="label">{t("users.roles")}</span>
        <RolePicker roles={roles} value={sel} onChange={setSel} />
      </div>
      <p className="text-xs text-slate-500 md:col-span-2">{t("users.initial_password_hint")}</p>
      <div className="flex gap-2 md:col-span-2">
        <button className="btn" disabled={m.isPending}>{t("common.create")}</button>
        <button type="button" className="btn-secondary" onClick={onDone}>{t("common.cancel")}</button>
      </div>
    </form>
  );
}

function EditUser({ user, roles, onDone }: { user: User; roles: Role[]; onDone: () => void }) {
  const { t } = useTranslation();
  const [display, setDisplay] = useState(user.display_name);
  const [email, setEmail] = useState(user.email);
  const [enabled, setEnabled] = useState(user.enabled);
  const [sel, setSel] = useState(user.roles.map((r) => r.name));
  const [pw, setPw] = useState("");
  const save = useMutation({
    mutationFn: () => api("PATCH", `/api/users/${user.id}`, { display_name: display, email, enabled, roles: sel }),
    onSuccess: onDone,
  });
  const reset = useMutation({ mutationFn: () => api("POST", `/api/users/${user.id}/reset-password`, { new_password: pw }), onSuccess: onDone });
  const mfa = useMutation({ mutationFn: () => api("POST", `/api/users/${user.id}/reset-mfa`), onSuccess: onDone });
  const del = useMutation({ mutationFn: () => api("DELETE", `/api/users/${user.id}`), onSuccess: onDone });
  return (
    <div className="card mb-4 flex flex-col gap-4">
      <h2 className="font-semibold">{t("users.edit_title", { name: user.username })}</h2>
      <ErrorBox error={save.error || reset.error || mfa.error || del.error} />
      <div className="grid gap-3 md:grid-cols-2">
        <div><label className="label" htmlFor="eu-d">{t("users.display_name")}</label>
          <input id="eu-d" className="input" value={display} onChange={(e) => setDisplay(e.target.value)} /></div>
        <div><label className="label" htmlFor="eu-e">{t("users.email")}</label>
          <input id="eu-e" className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></div>
      </div>
      <RolePicker roles={roles} value={sel} onChange={setSel} />
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />{t("users.enabled")}
      </label>
      <div className="flex gap-2">
        <button className="btn" onClick={() => save.mutate()}>{t("common.save")}</button>
        <button className="btn-secondary" onClick={onDone}>{t("common.cancel")}</button>
      </div>
      <hr className="border-slate-200" />
      <div className="flex flex-wrap items-end gap-2">
        <div className="w-64"><label className="label" htmlFor="eu-p">{t("users.reset_password")}</label>
          <input id="eu-p" className="input" type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} /></div>
        <button className="btn-secondary" disabled={pw.length < 12} onClick={() => reset.mutate()}>{t("users.reset_password_do")}</button>
        {user.totp_enabled && <button className="btn-secondary" onClick={() => mfa.mutate()}>{t("users.reset_mfa")}</button>}
        <button className="btn-danger" onClick={() => window.confirm(t("users.delete_confirm", { name: user.username })) && del.mutate()}>
          {t("common.delete")}
        </button>
      </div>
    </div>
  );
}
