import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../api";
import { ErrorBox } from "./Auth";

const RUN_CMD = "sudo sh siem-linux-onboarding.sh";

export default function LinuxPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const [server, setServer] = useState(window.location.hostname);
  const [audit, setAudit] = useState(true);
  const [sha, setSha] = useState("");
  const [error, setError] = useState<unknown>(null);

  const download = async () => {
    setError(null);
    const qs = new URLSearchParams({ server: server.trim(), audit: String(audit) });
    const res = await fetch(`/api/linux/script?${qs}`, { credentials: "same-origin" });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      setError(new ApiError(res.status, d?.detail?.error ?? `http_${res.status}`));
      return;
    }
    setSha(res.headers.get("X-Script-SHA256") ?? "");
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = "siem-linux-onboarding.sh";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-3xl">
      <h1 className="mb-1 text-xl font-semibold">{t("linux.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("linux.intro")}</p>
      <ErrorBox error={error} />
      <section className="card mb-4">
        <h2 className="mb-3 font-medium">{t("linux.step1")}</h2>
        <label className="label" htmlFor="l-s">{t("linux.server")}</label>
        <input id="l-s" className="input" value={server} disabled={!canWrite} onChange={(e) => setServer(e.target.value)} />
        <p className="mt-1 text-xs text-slate-500">{t("linux.server_hint")}</p>
        <label className="mt-3 flex items-center gap-2 text-sm">
          <input type="checkbox" checked={audit} disabled={!canWrite} onChange={(e) => setAudit(e.target.checked)} />
          {t("linux.audit")}
        </label>
        <button className="btn mt-3" disabled={!canWrite || !server.trim()} onClick={download}>{t("linux.download")}</button>
        {sha && <p className="mt-2 break-all font-mono text-xs text-slate-600">{t("wec.sha256")}: {sha}</p>}
      </section>
      <section className="card">
        <h2 className="mb-2 font-medium">{t("linux.step2")}</h2>
        <p className="text-sm text-slate-600">{t("linux.step2_text")}</p>
        <pre className="mt-2 overflow-x-auto rounded bg-slate-100 p-2 text-xs">{RUN_CMD}</pre>
      </section>
    </div>
  );
}
