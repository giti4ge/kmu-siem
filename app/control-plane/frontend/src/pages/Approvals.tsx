import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api";
import { ErrorBox } from "./Auth";

type Item = { id: string; action: string; params: Record<string, unknown>; requester: string; status: string; created: string; expires: string; decided_by: string | null };

export default function ApprovalsPage({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const cfg = useQuery({ queryKey: ["appr-cfg"], queryFn: () => api<{ enabled: boolean }>("GET", "/api/approvals/config") });
  const list = useQuery({ queryKey: ["appr"], queryFn: () => api<Item[]>("GET", "/api/approvals"), refetchInterval: 15000 });
  const refresh = () => qc.invalidateQueries({ queryKey: ["appr"] });
  const toggle = useMutation({ mutationFn: (enabled: boolean) => api("PUT", "/api/approvals/config", { enabled }), onSuccess: () => qc.invalidateQueries({ queryKey: ["appr-cfg"] }) });
  const decide = useMutation({ mutationFn: (v: { id: string; ok: boolean }) => api("POST", `/api/approvals/${v.id}/${v.ok ? "approve" : "reject"}`), onSettled: refresh });
  const [pseudo, setPseudo] = useState("");
  const [reason, setReason] = useState("");
  const [approvalId, setApprovalId] = useState("");
  const reveal = useMutation({ mutationFn: () => api<{ name: string }>("POST", "/api/approvals/reveal", { pseudonym: pseudo, reason, approval_id: approvalId || null }),
    onError: (e) => { if (e instanceof ApiError && e.approvalId) setApprovalId(e.approvalId); }, onSettled: refresh });
  return (
    <div className="max-w-4xl">
      <h1 className="mb-1 text-xl font-semibold">{t("appr.title")}</h1>
      <p className="mb-4 text-sm text-slate-600">{t("appr.intro")}</p>
      <ErrorBox error={cfg.error ?? list.error ?? toggle.error ?? decide.error} />
      <section className="card">
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" disabled={!canWrite} checked={cfg.data?.enabled ?? false} onChange={(e) => toggle.mutate(e.target.checked)} />
          {t("appr.enable")}
        </label>
      </section>
      <section className="card mt-4">
        <h2 className="mb-1 font-medium">{t("appr.list")}</h2>
        <table className="w-full text-left text-sm">
          <tbody>
            {(list.data ?? []).slice().reverse().map((i) => (
              <tr key={i.id} className="border-b border-slate-100">
                <td className="py-1 font-mono text-xs">{i.id}</td>
                <td>{t(`appr.a.${i.action}`, { defaultValue: i.action })}</td>
                <td className="text-xs">{JSON.stringify(i.params)}</td>
                <td>{i.requester}</td>
                <td>{t(`appr.s.${i.status}`)}{i.decided_by ? ` (${i.decided_by})` : ""}</td>
                <td>{i.status === "pending" && (
                  <span className="flex gap-1">
                    <button className="btn" disabled={decide.isPending} onClick={() => decide.mutate({ id: i.id, ok: true })}>{t("appr.approve")}</button>
                    <button className="btn-secondary" disabled={decide.isPending} onClick={() => decide.mutate({ id: i.id, ok: false })}>{t("appr.reject")}</button>
                  </span>)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="card mt-4">
        <h2 className="mb-1 font-medium">{t("appr.reveal_title")}</h2>
        <p className="mb-2 text-sm text-slate-600">{t("appr.reveal_intro")}</p>
        <ErrorBox error={reveal.error} />
        <div className="flex flex-wrap items-end gap-3">
          <div><label className="label" htmlFor="rv-p">{t("appr.pseudonym")}</label><input id="rv-p" className="input w-40" value={pseudo} onChange={(e) => setPseudo(e.target.value)} /></div>
          <div><label className="label" htmlFor="rv-r">{t("appr.reason")}</label><input id="rv-r" className="input w-64" value={reason} onChange={(e) => setReason(e.target.value)} /></div>
          <div><label className="label" htmlFor="rv-a">{t("appr.approval_id")}</label><input id="rv-a" className="input w-36" value={approvalId} onChange={(e) => setApprovalId(e.target.value)} /></div>
          <button className="btn" disabled={!pseudo || reveal.isPending} onClick={() => reveal.mutate()}>{t("appr.reveal")}</button>
        </div>
        {reveal.data && <p className="mt-2 text-sm">{t("appr.revealed", { name: reveal.data.name })}</p>}
      </section>
    </div>
  );
}
