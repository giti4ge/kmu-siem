import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Change = {
  time: string; host: string | null; operation: string | null; actor: string | null; object: string | null;
  attribute: string | null; member: string | null; old_value: string | null; new_value: string | null;
  privileged: boolean; gpo: boolean;
};

const GPO_TAG = "GPO";

export default function ChangesPage() {
  const { t } = useTranslation();
  const [hours, setHours] = useState(24);
  const [text, setText] = useState("");
  const [query, setQuery] = useState("");
  const [priv, setPriv] = useState(false);
  const qs = new URLSearchParams({ hours: String(hours), privileged: String(priv), ...(query ? { q: query } : {}) });
  const q = useQuery({
    queryKey: ["changes", hours, query, priv],
    queryFn: () => api<{ changes: Change[]; truncated: boolean }>("GET", `/api/changes?${qs}`),
  });

  return (
    <div className="max-w-6xl">
      <h1 className="mb-1 text-xl font-semibold">{t("changes.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("changes.intro")}</p>
      <ErrorBox error={q.error} />
      <div className="card mb-4 flex flex-wrap items-end gap-3">
        <div>
          <label className="label" htmlFor="c-h">{t("changes.period")}</label>
          <select id="c-h" className="input" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            {[1, 6, 24, 72, 168, 720].map((h) => <option key={h} value={h}>{t("changes.hours", { count: h })}</option>)}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="c-q">{t("changes.search")}</label>
          <input id="c-q" className="input" value={text} onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") setQuery(text.trim()); }} />
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={priv} onChange={(e) => setPriv(e.target.checked)} />
          {t("changes.privileged_only")}
        </label>
        <button className="btn" onClick={() => setQuery(text.trim())}>{t("changes.apply")}</button>
      </div>
      <div className="card overflow-x-auto">
        {q.data && q.data.changes.length === 0 && <p className="text-sm text-slate-600">{t("changes.empty")}</p>}
        {q.data && q.data.changes.length > 0 && (
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b text-slate-500">
                <th className="py-1">{t("changes.time")}</th><th>{t("changes.actor")}</th><th>{t("changes.operation")}</th>
                <th>{t("changes.object")}</th><th>{t("changes.change")}</th><th>{t("changes.host")}</th>
              </tr>
            </thead>
            <tbody>
              {q.data.changes.map((c, i) => (
                <tr key={`${c.time}-${i}`} className="border-b border-slate-100 align-top">
                  <td className="whitespace-nowrap py-1">{new Date(c.time).toLocaleString()}</td>
                  <td>{c.actor ?? "–"}</td>
                  <td>
                    {c.operation}
                    {c.privileged && <span className="ml-1 rounded bg-red-100 px-1 text-xs text-red-700">{t("changes.privileged")}</span>}
                    {c.gpo && <span className="ml-1 rounded bg-amber-100 px-1 text-xs text-amber-700">{GPO_TAG}</span>}
                  </td>
                  <td className="break-all">{c.object ?? "–"}{c.attribute ? ` · ${c.attribute}` : ""}</td>
                  <td className="break-all">
                    {c.member ? c.member : c.old_value !== null || c.new_value !== null
                      ? `${c.old_value ?? "∅"} → ${c.new_value ?? "∅"}` : "–"}
                  </td>
                  <td>{c.host ?? "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {q.data?.truncated && <p className="mt-2 text-xs text-slate-500">{t("changes.truncated")}</p>}
      </div>
    </div>
  );
}
