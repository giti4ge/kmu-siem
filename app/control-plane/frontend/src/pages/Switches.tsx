import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Iface = {
  index: number; name: string; admin: string; oper: string; speed_mbps: number; in_errors: number; out_errors: number;
};
type Device = {
  ip: string; name: string; sys_descr: string; last_seen: string; stale: boolean;
  ports_total: number; ports_up: number; interfaces: Iface[];
};

function portClass(i: Iface): string {
  if (i.admin !== "up") return "border-dashed border-slate-300 bg-white text-slate-400";
  if (i.oper === "up") return "border-green-600 bg-green-100 text-green-900";
  return "border-slate-400 bg-slate-200 text-slate-700";
}

export default function SwitchesPage() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["switches"], queryFn: () => api<{ devices: Device[] }>("GET", "/api/switches"), refetchInterval: 30000 });
  const [selected, setSelected] = useState<string | null>(null);
  const devices = q.data?.devices ?? [];
  const dev = devices.find((d) => d.ip === selected) ?? devices[0];

  return (
    <div className="max-w-6xl">
      <h1 className="mb-1 text-xl font-semibold">{t("switches.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("switches.intro")}</p>
      <ErrorBox error={q.error} />
      {q.data && devices.length === 0 && <div className="card text-sm text-slate-600">{t("switches.empty")}</div>}
      {devices.length > 0 && (
        <div className="mb-4 flex flex-wrap gap-2">
          {devices.map((d) => (
            <button key={d.ip} className={`btn ${dev?.ip === d.ip ? "ring-2 ring-slate-500" : ""}`} onClick={() => setSelected(d.ip)}>
              {d.name} · {d.ports_up}/{d.ports_total}
              {d.stale && <span className="ml-1 text-red-700">{t("switches.stale_short")}</span>}
            </button>
          ))}
        </div>
      )}
      {dev && (
        <>
          <section className="card mb-4">
            <h2 className="font-medium">{dev.name} <span className="text-sm font-normal text-slate-500">{dev.ip}</span></h2>
            <p className="mb-1 break-all text-xs text-slate-500">{dev.sys_descr}</p>
            <p className={`mb-3 text-sm ${dev.stale ? "text-red-700" : "text-slate-600"}`}>
              {dev.stale ? t("switches.stale") : t("switches.last_seen")}: {new Date(dev.last_seen).toLocaleString()}
            </p>
            <div className="flex flex-wrap gap-1" role="list" aria-label={t("switches.ports")}>
              {dev.interfaces.map((i) => (
                <div key={i.index} role="listitem" title={`${i.name}: ${t(`switches.state.${i.oper}`, { defaultValue: i.oper })}`}
                  className={`flex h-9 w-12 items-center justify-center rounded border text-xs ${portClass(i)}`}>
                  {i.name.replace(/^.*?(\d+(\/\d+)*)$/, "$1")}
                </div>
              ))}
            </div>
            <p className="mt-2 text-xs text-slate-500">{t("switches.legend")}</p>
          </section>
          <section className="card overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b text-slate-500">
                  <th className="py-1">{t("switches.port")}</th><th>{t("switches.admin")}</th><th>{t("switches.oper")}</th>
                  <th>{t("switches.speed")}</th><th>{t("switches.errors_in")}</th><th>{t("switches.errors_out")}</th>
                </tr>
              </thead>
              <tbody>
                {dev.interfaces.map((i) => (
                  <tr key={i.index} className="border-b border-slate-100">
                    <td className="py-1">{i.name}</td>
                    <td>{t(`switches.state.${i.admin}`, { defaultValue: i.admin })}</td>
                    <td>{t(`switches.state.${i.oper}`, { defaultValue: i.oper })}</td>
                    <td>{i.speed_mbps > 0 ? `${i.speed_mbps} ${t("switches.mbps")}` : "–"}</td>
                    <td>{i.in_errors}</td>
                    <td>{i.out_errors}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </>
      )}
    </div>
  );
}
