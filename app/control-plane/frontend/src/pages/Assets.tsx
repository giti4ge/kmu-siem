import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Asset = {
  mac: string; switch: string | null; switch_ip: string | null; port: string | null; vlan: string | null;
  first_seen: string | null; last_seen: string | null; ip: string | null; hostname: string | null;
};

const DAY_MS = 24 * 3600 * 1000;

export default function AssetsPage() {
  const { t } = useTranslation();
  const [days, setDays] = useState(30);
  const [filter, setFilter] = useState("");
  const q = useQuery({
    queryKey: ["assets", days],
    queryFn: () => api<{ assets: Asset[]; truncated: boolean }>("GET", `/api/assets?days=${days}`),
    refetchInterval: 60000,
  });
  const rows = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return (q.data?.assets ?? []).filter((a) =>
      !f || [a.mac, a.ip, a.hostname, a.switch, a.port, a.vlan].some((v) => (v ?? "").toLowerCase().includes(f)));
  }, [q.data, filter]);
  const fmt = (v: string | null) => (v ? new Date(v).toLocaleString() : "–");
  const isNew = (a: Asset) => !!a.first_seen && Date.now() - new Date(a.first_seen).getTime() < DAY_MS;

  return (
    <div className="max-w-6xl">
      <h1 className="mb-1 text-xl font-semibold">{t("assets.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("assets.intro")}</p>
      <ErrorBox error={q.error} />
      <div className="card mb-4 flex flex-wrap items-end gap-3">
        <div>
          <label className="label" htmlFor="a-d">{t("assets.period")}</label>
          <select id="a-d" className="input" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {[7, 30, 90, 365].map((d) => <option key={d} value={d}>{t("assets.days", { count: d })}</option>)}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="a-f">{t("assets.search")}</label>
          <input id="a-f" className="input" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </div>
        <p className="text-sm text-slate-600">{t("assets.count", { count: rows.length })}</p>
      </div>
      <div className="card overflow-x-auto">
        {q.data && rows.length === 0 && <p className="text-sm text-slate-600">{t("assets.empty")}</p>}
        {rows.length > 0 && (
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b text-slate-500">
                <th className="py-1">{t("assets.mac")}</th><th>{t("assets.ip")}</th><th>{t("assets.hostname")}</th><th>{t("assets.switch")}</th><th>{t("assets.port")}</th>
                <th>{t("assets.vlan")}</th><th>{t("assets.first_seen")}</th><th>{t("assets.last_seen")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, 1000).map((a) => (
                <tr key={a.mac} className="border-b border-slate-100">
                  <td className="py-1 font-mono text-xs">
                    {a.mac}
                    {isNew(a) && <span className="ml-1 rounded bg-amber-100 px-1 text-xs text-amber-700">{t("assets.new")}</span>}
                  </td>
                  <td>{a.ip ?? "–"}</td><td>{a.hostname ?? "–"}</td><td>{a.switch ?? "–"}</td><td>{a.port ?? "–"}</td><td>{a.vlan ?? "–"}</td>
                  <td>{fmt(a.first_seen)}</td><td>{fmt(a.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {q.data?.truncated && <p className="mt-2 text-xs text-slate-500">{t("assets.truncated")}</p>}
      </div>
    </div>
  );
}
