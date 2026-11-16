import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FilePick } from "../FilePick";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { ErrorBox } from "./Auth";

type Host = { ip: string; hostname: string; ports: number[]; suggested_type: string };
type Scan = { status: string; network?: string; hosts?: number; results: Host[]; error?: string };
type Mibs = { modules: { module: string; objects: number; unresolved: number; file: string }[]; matches: { module: string; name: string; oid: string }[] };

function MibSection({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const mibs = useQuery({ queryKey: ["mibs", q], queryFn: () => api<Mibs>("GET", `/api/snmp/mibs?q=${encodeURIComponent(q)}`) });
  const upload = useMutation({
    mutationFn: async (file: File) => {
      const buf = new Uint8Array(await file.arrayBuffer());
      let bin = "";
      buf.forEach((b) => { bin += String.fromCharCode(b); });
      return api("POST", "/api/snmp/mibs", { filename: file.name, content_b64: btoa(bin) });
    },
    onSettled: () => qc.invalidateQueries({ queryKey: ["mibs"] }),
  });
  const del = useMutation({ mutationFn: (m: string) => api("DELETE", `/api/snmp/mibs/${m}`), onSettled: () => qc.invalidateQueries({ queryKey: ["mibs"] }) });
  return (
    <section className="card mt-4">
      <h2 className="mb-1 font-medium">{t("disc.mib_title")}</h2>
      <p className="mb-2 text-sm text-slate-600">{t("disc.mib_intro")}</p>
      <ErrorBox error={mibs.error ?? upload.error ?? del.error} />
      {canWrite && <FilePick label={t("disc.mib_file")} accept=".mib,.my,.txt,.zip" onFile={(f) => upload.mutate(f)} />}
      <ul className="mt-2 text-sm">
        {(mibs.data?.modules ?? []).map((m) => (
          <li key={m.module}>{m.module} – {t("disc.mib_objects", { n: m.objects })}{m.unresolved ? ` (${t("disc.mib_unresolved", { n: m.unresolved })})` : ""}
            {canWrite && <button className="btn-secondary ml-2" onClick={() => del.mutate(m.module)}>{t("disc.delete")}</button>}</li>
        ))}
      </ul>
      <div className="mt-3"><label className="label" htmlFor="mib-q">{t("disc.mib_search")}</label><input id="mib-q" className="input w-64" value={q} onChange={(e) => setQ(e.target.value)} /></div>
      <ul className="mt-1 font-mono text-xs">
        {(mibs.data?.matches ?? []).map((m) => <li key={m.module + m.name}>{m.name} = {m.oid}</li>)}
      </ul>
    </section>
  );
}

export default function DiscoveryPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [net, setNet] = useState("192.168.1.0/24");
  const q = useQuery({
    queryKey: ["scan"], queryFn: () => api<Scan>("GET", "/api/discovery"),
    refetchInterval: (query) => (query.state.data?.status === "running" ? 3000 : false),
  });
  const start = useMutation({ mutationFn: () => api<Scan>("POST", "/api/discovery", { network: net }), onSuccess: (d) => qc.setQueryData(["scan"], d) });
  const add = useMutation({ mutationFn: (h: Host) => api("POST", "/api/devices", { ip: h.ip, name: h.hostname || h.ip, type: h.suggested_type }) });
  const d = q.data;
  return (
    <div className="max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold">{t("disc.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("disc.intro")}</p>
      <ErrorBox error={q.error ?? start.error ?? add.error} />
      <section className="card">
        {canWrite && (
          <div className="mb-3 flex items-end gap-3">
            <div><label className="label" htmlFor="d-n">{t("disc.network")}</label><input id="d-n" className="input w-48" value={net} onChange={(e) => setNet(e.target.value)} /></div>
            <button className="btn" disabled={start.isPending || d?.status === "running"} onClick={() => start.mutate()}>{t("disc.scan")}</button>
          </div>
        )}
        {d?.status === "running" && <p className="text-sm">{t("disc.running", { network: d.network })}</p>}
        {d?.status === "failed" && <p className="text-sm text-red-700">{t("disc.failed")}: {d.error}</p>}
        <table className="w-full text-left text-sm">
          <thead><tr className="border-b text-slate-500"><th className="py-1">{t("disc.ip")}</th><th>{t("disc.host")}</th><th>{t("disc.ports")}</th><th>{t("disc.type")}</th><th /></tr></thead>
          <tbody>
            {(d?.results ?? []).map((h) => (
              <tr key={h.ip} className="border-b border-slate-100">
                <td className="py-1">{h.ip}</td><td>{h.hostname}</td><td>{h.ports.join(", ")}</td><td>{h.suggested_type || "–"}</td>
                <td>{canWrite && h.suggested_type && <button className="btn-secondary" disabled={add.isPending} onClick={() => add.mutate(h)}>{t("disc.add")}</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <MibSection canWrite={canWrite} />
    </div>
  );
}
