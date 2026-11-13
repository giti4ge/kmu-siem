import { useInfiniteQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, type AuditEntry } from "../api";
import { ErrorBox } from "./Auth";

const PAGE = 100;

export default function AuditPage() {
  const { t } = useTranslation();
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const q = useInfiniteQuery({
    queryKey: ["audit", actor, action],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => {
      const p = new URLSearchParams({ limit: String(PAGE) });
      if (pageParam) p.set("before_seq", String(pageParam));
      if (actor) p.set("actor", actor);
      if (action) p.set("action", action);
      return api<AuditEntry[]>("GET", `/api/audit?${p}`);
    },
    getNextPageParam: (last) => (last.length === PAGE ? last[last.length - 1].seq : undefined),
  });
  const verify = useMutation({
    mutationFn: () => api<{ ok: boolean; entries: number; first_bad_seq: number | null; reason: string | null }>("GET", "/api/audit/verify"),
  });
  const rows = q.data?.pages.flat() ?? [];
  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold">{t("nav.audit")}</h1>
        <button className="btn" onClick={() => verify.mutate()}>{t("audit.verify")}</button>
      </div>
      {verify.data && (
        <div className={`mb-4 rounded px-3 py-2 text-sm ${verify.data.ok ? "bg-green-50 text-green-800" : "bg-red-50 text-red-800"}`}>
          {verify.data.ok
            ? t("audit.verify_ok", { count: verify.data.entries })
            : t("audit.verify_fail", { seq: verify.data.first_bad_seq ?? "–", reason: t(`audit.reason.${verify.data.reason}`) })}
        </div>
      )}
      <ErrorBox error={q.error || verify.error} />
      <div className="mb-3 flex gap-2">
        <input className="input max-w-48" placeholder={t("audit.actor")} value={actor} onChange={(e) => setActor(e.target.value)} />
        <input className="input max-w-48" placeholder={t("audit.action")} value={action} onChange={(e) => setAction(e.target.value)} />
      </div>
      <div className="card overflow-x-auto">
        <table className="table">
          <thead><tr><th>#</th><th>{t("audit.time")}</th><th>{t("audit.actor")}</th><th>{t("audit.action")}</th>
            <th>{t("audit.target")}</th><th>{t("audit.outcome")}</th><th>{t("audit.ip")}</th><th>{t("audit.details")}</th></tr></thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.seq} className={e.outcome !== "success" ? "bg-red-50" : ""}>
                <td>{e.seq}</td><td className="whitespace-nowrap">{new Date(e.ts).toLocaleString()}</td>
                <td>{e.actor}</td><td className="font-mono">{e.action}</td><td>{e.target}</td>
                <td>{t(`audit.outcome_${e.outcome}`, { defaultValue: e.outcome })}</td><td>{e.ip}</td>
                <td className="max-w-xs truncate font-mono text-xs">{e.details === "{}" ? "" : e.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {q.hasNextPage && <button className="btn-secondary mt-3" onClick={() => q.fetchNextPage()}>{t("common.more")}</button>}
      </div>
    </div>
  );
}
