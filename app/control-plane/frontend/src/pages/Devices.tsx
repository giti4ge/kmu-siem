import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Device = { id: number; ip: string; name: string; type: string; note: string };
type List = { devices: Device[]; types: string[] };
type Saved = Device & { applied: boolean };

const EMPTY = { ip: "", name: "", type: "", note: "" };

export default function DevicesPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["devices"], queryFn: () => api<List>("GET", "/api/devices") });
  const [form, setForm] = useState(EMPTY);
  const [editing, setEditing] = useState<number | null>(null);
  const [notice, setNotice] = useState<"" | "applied" | "not_applied">("");

  const done = (d?: Saved) => {
    setNotice(d ? (d.applied ? "applied" : "not_applied") : "applied");
    setForm(EMPTY);
    setEditing(null);
    void qc.invalidateQueries({ queryKey: ["devices"] });
  };
  const save = useMutation({
    mutationFn: () =>
      editing === null
        ? api<Saved>("POST", "/api/devices", form)
        : api<Saved>("PUT", `/api/devices/${editing}`, form),
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: (id: number) => api("DELETE", `/api/devices/${id}`),
    onSuccess: () => done(),
  });
  const types = q.data?.types ?? [];

  return (
    <div className="max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold">{t("devices.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("devices.intro")}</p>
      <ErrorBox error={q.error ?? save.error ?? remove.error} />
      {notice === "applied" && <p className="mb-2 text-sm text-green-700">{t("devices.applied")}</p>}
      {notice === "not_applied" && <p className="mb-2 text-sm text-amber-700">{t("devices.not_applied")}</p>}

      {canWrite && (
        <form
          className="card mb-4 grid gap-3 md:grid-cols-5"
          onSubmit={(e) => { e.preventDefault(); save.mutate(); }}
        >
          <div>
            <label className="label" htmlFor="dv-ip">{t("devices.ip")}</label>
            <input id="dv-ip" className="input" value={form.ip} required
              onChange={(e) => setForm({ ...form, ip: e.target.value })} />
          </div>
          <div>
            <label className="label" htmlFor="dv-n">{t("devices.name")}</label>
            <input id="dv-n" className="input" value={form.name} required maxLength={64}
              onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <div>
            <label className="label" htmlFor="dv-t">{t("devices.type")}</label>
            <select id="dv-t" className="input" value={form.type} required
              onChange={(e) => setForm({ ...form, type: e.target.value })}>
              <option value="" />
              {types.map((x) => <option key={x} value={x}>{t(`devices.types.${x}`)}</option>)}
            </select>
          </div>
          <div>
            <label className="label" htmlFor="dv-o">{t("devices.note")}</label>
            <input id="dv-o" className="input" value={form.note} maxLength={255}
              onChange={(e) => setForm({ ...form, note: e.target.value })} />
          </div>
          <div className="flex items-end gap-2">
            <button className="btn" disabled={save.isPending}>{t("common.save")}</button>
            {editing !== null && (
              <button type="button" className="btn-secondary" onClick={() => { setEditing(null); setForm(EMPTY); }}>
                {t("devices.cancel")}
              </button>
            )}
          </div>
        </form>
      )}

      <div className="card">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b text-slate-500">
              <th className="py-1">{t("devices.name")}</th>
              <th>{t("devices.ip")}</th>
              <th>{t("devices.type")}</th>
              <th>{t("devices.note")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {q.data?.devices.map((d) => (
              <tr key={d.id} className="border-b border-slate-100">
                <td className="py-1">{d.name}</td>
                <td className="font-mono">{d.ip}</td>
                <td>{t(`devices.types.${d.type}`, { defaultValue: d.type })}</td>
                <td>{d.note}</td>
                <td className="text-right">
                  {canWrite && (
                    <>
                      <button className="btn-secondary mr-2" onClick={() => {
                        setEditing(d.id);
                        setForm({ ip: d.ip, name: d.name, type: d.type, note: d.note });
                      }}>{t("devices.edit")}</button>
                      <button className="btn-danger" onClick={() => remove.mutate(d.id)}>{t("devices.delete")}</button>
                    </>
                  )}
                </td>
              </tr>
            ))}
            {q.data && q.data.devices.length === 0 && (
              <tr><td colSpan={5} className="py-3 text-slate-500">{t("devices.empty")}</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
