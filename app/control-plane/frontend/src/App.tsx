import { useQuery, useQueryClient } from "@tanstack/react-query";
import { VersionTag } from "./FilePick";
import { useTranslation } from "react-i18next";
import { Navigate, NavLink, Route, Routes, useLocation } from "react-router";
import { api, ApiError, type Me, setCsrf } from "./api";
import { setLanguage } from "./i18n";
import AuditPage from "./pages/Audit";
import DevicesPage from "./pages/Devices";
import Dashboard from "./pages/Dashboard";
import MfaDevices from "./pages/MfaDevices";
import { EnrollPage, LoginPage, MfaPage, PasswordPage } from "./pages/Auth";
import RolesPage from "./pages/Roles";
import SystemLogPage from "./pages/SystemLog";
import UnparsedPage from "./pages/Unparsed";
import UsersPage from "./pages/Users";
import LinuxPage from "./pages/Linux";
import ActiveResponsePage from "./pages/ActiveResponse";
import AlertsPage from "./pages/Alerts";
import ForensicsPage from "./pages/Forensics";
import ApprovalsPage from "./pages/Approvals";
import ArchivePage from "./pages/Archive";
import CasesPage from "./pages/Cases";
import ConnectPage from "./pages/Connect";
import DiscoveryPage from "./pages/Discovery";
import ParserEditorPage from "./pages/ParserEditor";
import MaintenancePage from "./pages/Maintenance";
import NotificationsPage from "./pages/Notifications";
import ReportsPage from "./pages/Reports";
import RetentionPage from "./pages/Retention";
import SophosPage from "./pages/Sophos";
import ChangesPage from "./pages/Changes";
import SnmpPage from "./pages/Snmp";
import SwitchesPage from "./pages/Switches";
import AssetsPage from "./pages/Assets";
import FortigatePage from "./pages/Fortigate";
import WindowsPage from "./pages/Windows";

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

// Navigation: nur Module anzeigen, für die eine Leseberechtigung besteht; gruppiert nach Aufgabe
type NavItem = { to: string; key: string; perm: string };
const GROUPS: { id: string; items: NavItem[] }[] = [
  { id: "overview", items: [
    { to: "/", key: "dashboard", perm: "dashboard:read" },
    { to: "/reports", key: "reports", perm: "reports:read" },
  ] },
  { id: "events", items: [
    { to: "/alerts", key: "alerts", perm: "alerts:read" },
    { to: "/forensics", key: "forensics", perm: "logs:read" },
    { to: "/cases", key: "cases", perm: "logs:read" },
    { to: "/changes", key: "changes", perm: "changes:read" },
    { to: "/sources/unparsed", key: "unparsed", perm: "logs:read" },
    { to: "/system/archive", key: "archive", perm: "archive:read" },
  ] },
  { id: "sources", items: [
    { to: "/sources/devices", key: "devices", perm: "sources:read" },
    { to: "/assets", key: "assets", perm: "assets:read" },
    { to: "/switches", key: "switches", perm: "switches:read" },
    { to: "/sources/windows", key: "windows", perm: "sources:read" },
    { to: "/sources/linux", key: "linux", perm: "sources:read" },
    { to: "/sources/fortigate", key: "fortigate", perm: "sources:read" },
    { to: "/sources/snmp", key: "snmp", perm: "sources:read" },
    { to: "/sources/sophos", key: "sophos", perm: "sources:read" },
    { to: "/sources/discovery", key: "discovery", perm: "sources:read" },
    { to: "/sources/parsers", key: "parsers", perm: "sources:read" },
    { to: "/sources/connect", key: "connect", perm: "sources:read" },
  ] },
  { id: "security", items: [
    { to: "/active-response", key: "ar", perm: "alerts:read" },
    { to: "/system/approvals", key: "approvals", perm: "privacy:read" },
    { to: "/system/retention", key: "retention", perm: "privacy:read" },
  ] },
  { id: "appliance", items: [
    { to: "/system/maintenance", key: "maintenance", perm: "system:read" },
    { to: "/system/notifications", key: "notifications", perm: "system:read" },
    { to: "/system/log", key: "syslog", perm: "system:read" },
  ] },
  { id: "admin", items: [
    { to: "/system/users", key: "users", perm: "users:read" },
    { to: "/system/roles", key: "roles", perm: "users:read" },
    { to: "/system/audit", key: "audit", perm: "audit:read" },
  ] },
];
const ALL_ITEMS: NavItem[] = [...GROUPS.flatMap((g) => g.items), { to: "/account", key: "account", perm: "" }];

// Einklappbare Hilfe mit Praxisbeispiel zur aktuellen Seite
function PageHelp() {
  const { t } = useTranslation();
  const { pathname } = useLocation();
  const item = ALL_ITEMS.find((i) => i.to === pathname);
  if (!item) return null;
  return (
    <details className="mb-4 max-w-4xl rounded border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700">
      <summary className="cursor-pointer text-slate-600">{t("help.show")}</summary>
      <p className="mt-2">{t(`help.${item.key}.text`)}</p>
      <p className="mt-1"><strong>{t("help.example")}:</strong> {t(`help.${item.key}.example`)}</p>
    </details>
  );
}

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
          {GROUPS.map((g) => {
            const items = g.items.filter((n) => can(n.perm));
            const dash = g.id === "overview" && can("logs:read");
            if (items.length === 0 && !dash) return null;
            const link = ({ isActive }: { isActive: boolean }) =>
              `rounded px-2 py-1.5 text-sm ${isActive ? "bg-slate-700 text-white" : "hover:bg-slate-800"}`;
            return (
              <div key={g.id} className="mb-2 flex flex-col gap-1">
                <div className="mt-2 px-2 text-xs font-semibold uppercase tracking-wide text-slate-500">{t(`navgroup.${g.id}`)}</div>
                {items.map((n) => (
                  <NavLink key={n.to} to={n.to} end className={link}>{t(`nav.${n.key}`)}</NavLink>
                ))}
                {dash && (
                  <a href="/dashboards/app/home" target="_blank" rel="noopener" className="rounded px-2 py-1.5 text-sm hover:bg-slate-800">
                    {t("nav.dashboards")}
                  </a>
                )}
              </div>
            );
          })}
          <NavLink to="/account" className={({ isActive }) => `rounded px-2 py-1.5 text-sm ${isActive ? "bg-slate-700 text-white" : "hover:bg-slate-800"}`}>
            {t("nav.account")}
          </NavLink>
        </nav>
        <VersionTag className="mt-6 text-slate-400" />
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
          <PageHelp />
          <Routes>
            <Route path="/" element={<Dashboard me={me} />} />
            {can("users:read") && <Route path="/system/users" element={<UsersPage canWrite={can("users:write")} />} />}
            {can("users:read") && <Route path="/system/roles" element={<RolesPage canWrite={can("users:write")} />} />}
            {can("audit:read") && <Route path="/system/audit" element={<AuditPage />} />}
            {can("system:read") && <Route path="/system/log" element={<SystemLogPage />} />}
            {can("sources:read") && <Route path="/sources/windows" element={<WindowsPage canWrite={can("sources:write")} />} />}
            {can("alerts:read") && <Route path="/active-response" element={<ActiveResponsePage canSettings={can("system:write")} canBlock={can("alerts:write")} />} />}
            {can("logs:read") && <Route path="/forensics" element={<ForensicsPage canSettings={can("system:write")} />} />}
            {can("reports:read") && <Route path="/reports" element={<ReportsPage />} />}
            {can("alerts:read") && <Route path="/alerts" element={<AlertsPage canWrite={can("alerts:write")} canRules={can("rules:read")} />} />}
            {can("system:read") && <Route path="/system/notifications" element={<NotificationsPage canWrite={can("system:write")} />} />}
            {can("logs:read") && <Route path="/cases" element={<CasesPage canWrite={can("alerts:write")} />} />}
            {can("sources:read") && <Route path="/sources/discovery" element={<DiscoveryPage canWrite={can("sources:write")} />} />}
            {can("sources:read") && <Route path="/sources/parsers" element={<ParserEditorPage canWrite={can("sources:write")} />} />}
            {can("sources:read") && <Route path="/sources/connect" element={<ConnectPage canWrite={can("sources:write")} />} />}
            {can("privacy:read") && <Route path="/system/approvals" element={<ApprovalsPage canWrite={can("privacy:write")} />} />}
            {can("archive:read") && <Route path="/system/archive" element={<ArchivePage canWrite={can("archive:write")} />} />}
            {can("system:read") && <Route path="/system/maintenance" element={<MaintenancePage canWrite={can("system:write")} />} />}
            {can("privacy:read") && <Route path="/system/retention" element={<RetentionPage canWrite={can("privacy:write")} />} />}
            {can("sources:read") && <Route path="/sources/fortigate" element={<FortigatePage canWrite={can("sources:write")} />} />}
            {can("sources:read") && <Route path="/sources/snmp" element={<SnmpPage canWrite={can("sources:write")} />} />}
            {can("sources:read") && <Route path="/sources/sophos" element={<SophosPage canWrite={can("sources:write")} />} />}
            {can("sources:read") && <Route path="/sources/linux" element={<LinuxPage canWrite={can("sources:write")} />} />}
            {can("sources:read") && <Route path="/sources/devices" element={<DevicesPage canWrite={can("sources:write")} />} />}
            {can("assets:read") && <Route path="/assets" element={<AssetsPage />} />}
            {can("switches:read") && <Route path="/switches" element={<SwitchesPage />} />}
            {can("changes:read") && <Route path="/changes" element={<ChangesPage />} />}
            {can("logs:read") && <Route path="/sources/unparsed" element={<UnparsedPage canWrite={can("sources:write")} />} />}
            <Route path="/account" element={<><PasswordPage /><MfaDevices /></>} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
