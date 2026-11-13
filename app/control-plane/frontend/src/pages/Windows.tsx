import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api";
import { ErrorBox } from "./Auth";

const ROLES = ["dc", "exchange", "member", "client"] as const;
type Role = (typeof ROLES)[number];

type Wec = {
  settings: { domain: string; fqdn: string; service_account: string; roles: Record<Role, string[]> };
  configured: boolean;
  keytab: boolean;
  principal: string | null;
  audit_policy: { subcategory: string; success: boolean; failure: boolean }[];
};

function toBase64(buf: ArrayBuffer): string {
  let s = "";
  new Uint8Array(buf).forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s);
}

export default function WindowsPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["wec"], queryFn: () => api<Wec>("GET", "/api/wec"), refetchInterval: 15000 });
  const [domain, setDomain] = useState("");
  const [fqdn, setFqdn] = useState("");
  const [account, setAccount] = useState("svc-siem-wec");
  const [ous, setOus] = useState<Record<Role, string>>({ dc: "", exchange: "", member: "", client: "" });
  const [sha, setSha] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!q.data) return;
    const s = q.data.settings;
    setDomain(s.domain);
    setFqdn(s.fqdn);
    setAccount(s.service_account);
    setOus({
      dc: s.roles.dc.join("\n"), exchange: s.roles.exchange.join("\n"),
      member: s.roles.member.join("\n"), client: s.roles.client.join("\n"),
    });
  }, [q.data]);

  const save = useMutation({
    mutationFn: () =>
      api<Wec>("PUT", "/api/wec/settings", {
        domain, fqdn, service_account: account,
        roles: Object.fromEntries(ROLES.map((r) => [r, ous[r].split("\n").map((x) => x.trim()).filter(Boolean)])),
      }),
    onSuccess: (d) => { setError(null); setSaved(true); qc.setQueryData(["wec"], d); },
    onError: (e) => { setSaved(false); setError(e); },
  });

  const download = async () => {
    setError(null);
    const res = await fetch("/api/wec/script", { credentials: "same-origin" });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      setError(new ApiError(res.status, d?.detail?.error ?? `http_${res.status}`));
      return;
    }
    setSha(res.headers.get("X-Script-SHA256") ?? "");
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = "siem-wec-onboarding.ps1";
    a.click();
    URL.revokeObjectURL(url);
  };

  const upload = async (file: File | undefined) => {
    if (!file) return;
    setError(null);
    try {
      const d = await api<Wec>("PUT", "/api/wec/keytab", { keytab_b64: toBase64(await file.arrayBuffer()) });
      qc.setQueryData(["wec"], d);
    } catch (e) {
      setError(e);
    }
  };

  const d = q.data;
  return (
    <div className="max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold">{t("wec.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("wec.intro")}</p>
      <ErrorBox error={q.error ?? error} />

      <section className="card mb-4">
        <h2 className="mb-3 font-medium">{t("wec.step1")}</h2>
        <div className="grid gap-3 md:grid-cols-3">
          <div>
            <label className="label" htmlFor="w-d">{t("wec.domain")}</label>
            <input id="w-d" className="input" value={domain} disabled={!canWrite} placeholder={t("wec.ph_domain")}
              onChange={(e) => setDomain(e.target.value)} />
          </div>
          <div>
            <label className="label" htmlFor="w-f">{t("wec.fqdn")}</label>
            <input id="w-f" className="input" value={fqdn} disabled={!canWrite} placeholder={t("wec.ph_fqdn")}
              onChange={(e) => setFqdn(e.target.value)} />
          </div>
          <div>
            <label className="label" htmlFor="w-a">{t("wec.account")}</label>
            <input id="w-a" className="input" value={account} disabled={!canWrite}
              onChange={(e) => setAccount(e.target.value)} />
          </div>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          {ROLES.map((r) => (
            <div key={r}>
              <label className="label" htmlFor={`w-${r}`}>{t(`wec.roles.${r}`)}</label>
              <textarea id={`w-${r}`} className="input h-20 font-mono text-xs" value={ous[r]} disabled={!canWrite}
                placeholder={t("wec.ph_ou")} onChange={(e) => setOus({ ...ous, [r]: e.target.value })} />
              <p className="mt-1 text-xs text-slate-500">{t(`wec.roles_hint.${r}`)}</p>
            </div>
          ))}
        </div>
        {canWrite && (
          <div className="mt-3 flex items-center gap-3">
            <button className="btn" disabled={save.isPending} onClick={() => save.mutate()}>{t("common.save")}</button>
            {saved && <span className="text-sm text-green-700">{t("wec.saved")}</span>}
          </div>
        )}
      </section>

      <section className="card mb-4">
        <h2 className="mb-2 font-medium">{t("wec.step2")}</h2>
        <p className="mb-3 text-sm text-slate-600">{t("wec.step2_text")}</p>
        <button className="btn" disabled={!canWrite || !d?.configured} onClick={download}>{t("wec.download")}</button>
        {sha && (
          <p className="mt-2 break-all font-mono text-xs text-slate-600">{t("wec.sha256")}: {sha}</p>
        )}
      </section>

      <section className="card mb-4">
        <h2 className="mb-2 font-medium">{t("wec.step3")}</h2>
        <p className="mb-3 text-sm text-slate-600">{t("wec.step3_text", { principal: d?.principal ?? "HTTP/…" })}</p>
        <input type="file" aria-label={t("wec.keytab")} disabled={!canWrite || !d?.configured}
          onChange={(e) => { void upload(e.target.files?.[0]); e.target.value = ""; }} />
      </section>

      <section className="card mb-4">
        <h2 className="mb-2 font-medium">{t("wec.status")}</h2>
        <dl className="grid grid-cols-[12rem_1fr] gap-y-1 text-sm">
          <dt className="text-slate-500">{t("wec.configured")}</dt>
          <dd>{d?.configured ? t("common.yes") : t("common.no")}</dd>
          <dt className="text-slate-500">{t("wec.keytab_state")}</dt>
          <dd>{d?.keytab ? t("common.yes") : t("common.no")}</dd>
        </dl>
      </section>

      <section className="card">
        <h2 className="mb-2 font-medium">{t("wec.audit_title")}</h2>
        <p className="mb-2 text-sm text-slate-600">{t("wec.audit_text")}</p>
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b text-slate-500">
              <th className="py-1">{t("wec.subcategory")}</th>
              <th>{t("wec.success")}</th>
              <th>{t("wec.failure")}</th>
            </tr>
          </thead>
          <tbody>
            {d?.audit_policy.map((p) => (
              <tr key={p.subcategory} className="border-b border-slate-100">
                <td className="py-1">{p.subcategory}</td>
                <td>{p.success ? t("common.yes") : t("common.no")}</td>
                <td>{p.failure ? t("common.yes") : t("common.no")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
