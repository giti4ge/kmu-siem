import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api, type Me } from "../api";

export default function Dashboard({ me }: { me: Me }) {
  const { t } = useTranslation();
  const info = useQuery({
    queryKey: ["system-info"],
    queryFn: () => api<{ version: string }>("GET", "/api/system/info"),
    enabled: me.permissions.includes("system:read"),
  });
  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">{t("nav.dashboard")}</h1>
      <div className="card">
        <p className="text-sm text-slate-700">{t("dashboard.welcome", { name: me.user.display_name || me.user.username })}</p>
        <p className="mt-2 text-sm text-slate-500">{t("dashboard.coming")}</p>
        {info.data && <p className="mt-4 text-xs text-slate-500">{t("dashboard.version", { version: info.data.version })}</p>}
      </div>
    </div>
  );
}
