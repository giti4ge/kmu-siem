import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Navigate, NavLink, Route, Routes } from "react-router";
import { api, ApiError, type Me, setCsrf } from "./api";
import { setLanguage } from "./i18n";
import AuditPage from "./pages/Audit";
import Dashboard from "./pages/Dashboard";
import { EnrollPage, LoginPage, MfaPage, PasswordPage } from "./pages/Auth";
import RolesPage from "./pages/Roles";
import UsersPage from "./pages/Users";

export function useMe() {
  return useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      try {
        const me = await api<Me>("GET", "/api/auth/me");
        setCsrf(me.csrf_token);
        return me;
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
  });
}

// Navigation: nur Module anzeigen, für die eine Leseberechtigung besteht
const NAV = [
  { to: "/", key: "nav.dashboard", perm: "dashboard:read" },
  { to: "/system/users", key: "nav.users", perm: "users:read" },
  { to: "/system/roles", key: "nav.roles", perm: "users:read" },
  { to: "/system/audit", key: "nav.audit", perm: "audit:read" },
];

export default function App() {
  const { data: me, isLoading } = useMe();
  if (isLoading) return null;
  if (!me) return <LoginPage />;
  if (me.stage === "mfa_verify") return <MfaPage />;
  if (me.stage === "password_change") return <PasswordPage forced />;
  if (me.stage === "mfa_enroll") return <EnrollPage />;
  return <Shell me={me} />;
}

function Shell({ me }: { me: Me }) {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const can = (p: string) => me.permissions.includes(p);
  const logout = async () => {
    await api("POST", "/api/auth/logout").catch(() => undefined);
    qc.clear();
    qc.setQueryData(["me"], null);
  };
  return (
    <div className="flex min-h-screen">
      <aside className="w-56 shrink-0 bg-slate-900 p-4 text-slate-200">
        <div className="mb-6 text-lg font-semibold text-white">{t("app.name")}</div>
        <nav className="flex flex-col gap-1">
          {NAV.filter((n) => can(n.perm)).map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end
              className={({ isActive }) =>
                `rounded px-2 py-1.5 text-sm ${isActive ? "bg-slate-700 text-white" : "hover:bg-slate-800"}`
              }
            >
              {t(n.key)}
            </NavLink>
          ))}
          <NavLink to="/account" className="rounded px-2 py-1.5 text-sm hover:bg-slate-800">
            {t("nav.account")}
          </NavLink>
        </nav>
      </aside>
      <div className="flex-1">
        <header className="flex items-center justify-end gap-3 border-b border-slate-200 bg-white px-6 py-3 text-sm">
          <select
            className="rounded border border-slate-300 px-1 py-0.5"
            value={i18n.language}
            onChange={(e) => setLanguage(e.target.value as "de" | "en")}
            aria-label={t("app.language")}
          >
            <option value="de">{t("lang.de")}</option>
            <option value="en">{t("lang.en")}</option>
          </select>
          <span className="text-slate-600">{me.user.display_name || me.user.username}</span>
          <button className="btn-secondary" onClick={logout}>
            {t("auth.logout")}
          </button>
        </header>
        <main className="p-6">
          <Routes>
            <Route path="/" element={<Dashboard me={me} />} />
            {can("users:read") && <Route path="/system/users" element={<UsersPage canWrite={can("users:write")} />} />}
            {can("users:read") && <Route path="/system/roles" element={<RolesPage canWrite={can("users:write")} />} />}
            {can("audit:read") && <Route path="/system/audit" element={<AuditPage />} />}
            <Route path="/account" element={<PasswordPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
