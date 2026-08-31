import {
  Activity,
  BadgePoundSterling,
  Bell,
  BookCheck,
  BriefcaseBusiness,
  ChevronRight,
  CircleUserRound,
  Crosshair,
  FileCheck2,
  KeyRound,
  Landmark,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  SendHorizontal,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  UserCog,
  UsersRound,
  WalletCards,
  X,
} from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router";
import { useAuth } from "../auth";
import type { AdminPermissionScope, Role } from "../types";
import { humanize } from "../utils";

const customerNavigation = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/accounts", label: "Accounts", icon: WalletCards },
  { to: "/transfer", label: "Send money", icon: SendHorizontal },
  { to: "/activity", label: "Activity", icon: Activity },
  { to: "/notifications", label: "Notifications", icon: Bell },
  { to: "/trust", label: "Trust claim", icon: FileCheck2 },
];

const operationsNavigation = [
  { to: "/", label: "Overview", icon: LayoutDashboard, roles: ["BANK_ADMIN", "ASPIS_ADMIN", "RISK_ANALYST", "COMPLIANCE_AUDITOR"] },
  { to: "/admin-users", label: "Admin users", icon: UserCog, roles: ["BANK_ADMIN"], scope: "admin_users" },
  { to: "/customers", label: "Customers", icon: UsersRound, roles: ["BANK_ADMIN"], scope: "customers" },
  { to: "/transactions", label: "Transactions", icon: BriefcaseBusiness, roles: ["BANK_ADMIN", "RISK_ANALYST"], scope: "transactions" },
  { to: "/risk", label: "Risk queue", icon: ShieldAlert, roles: ["BANK_ADMIN", "RISK_ANALYST"], scope: "risk" },
  { to: "/audit", label: "Audit trail", icon: BookCheck, roles: ["BANK_ADMIN", "RISK_ANALYST", "COMPLIANCE_AUDITOR"], scope: "audit" },
  { to: "/asvs", label: "ASVS assurance", icon: ShieldCheck, roles: ["BANK_ADMIN", "ASPIS_ADMIN", "ASPIS_AUDITOR"], scope: "asvs" },
  { to: "/aspis-auditors", label: "Auditor approvals", icon: UserCheck, roles: ["BANK_ADMIN", "ASPIS_ADMIN"], scope: "aspis_auditors" },
  { to: "/security", label: "MFA security", icon: KeyRound, roles: ["BANK_ADMIN", "ASPIS_ADMIN", "ASPIS_AUDITOR"] },
  { to: "/reconciliation", label: "Reconciliation", icon: Landmark, roles: ["BANK_ADMIN", "COMPLIANCE_AUDITOR"], scope: "reconciliation" },
  { to: "/workflows", label: "Workflow graph", icon: Network, roles: ["BANK_ADMIN"], scope: "workflows" },
  { to: "/attack-lab", label: "Attack lab", icon: Crosshair, roles: ["BANK_ADMIN", "RISK_ANALYST"], scope: "attack_lab" },
  { to: "/financials", label: "Company financials", icon: BadgePoundSterling, roles: ["BANK_ADMIN", "RISK_ANALYST"], scope: "company_financials" },
] satisfies Array<{ to: string; label: string; icon: typeof LayoutDashboard; roles: Role[]; scope?: AdminPermissionScope }>;

const routeTitles: Record<string, string> = {
  "/": "Overview",
  "/accounts": "Accounts",
  "/transfer": "Send money",
  "/activity": "Activity",
  "/notifications": "Notifications",
  "/trust": "Trust claim",
  "/admin-users": "Admin users",
  "/customers": "Customers",
  "/transactions": "Transactions",
  "/risk": "Risk queue",
  "/audit": "Audit trail",
  "/asvs": "ASVS assurance",
  "/aspis-auditors": "Auditor approvals",
  "/security": "MFA security",
  "/reconciliation": "Reconciliation",
  "/workflows": "Workflow graph",
  "/attack-lab": "Attack lab",
  "/financials": "Company financials",
};

export function AppShell() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  if (!user) return null;
  const canUseOperation = (item: (typeof operationsNavigation)[number]) =>
    (item.roles as readonly Role[]).includes(user.role)
    && (
      user.role !== "BANK_ADMIN"
      || !item.scope
      || user.is_super_admin
      || user.admin_permissions.includes(item.scope)
    );
  const navigation = user.role === "CUSTOMER"
    ? customerNavigation
    : operationsNavigation.filter(canUseOperation);
  const workspaceLabel = user.role === "CUSTOMER"
    ? "PERSONAL BANKING"
    : user.role === "ASPIS_AUDITOR"
      ? "ASPIS ASSURANCE"
      : user.role === "ASPIS_ADMIN"
        ? "ASPIS ADMINISTRATION"
        : "BANK OPERATIONS";
  const displayName = user.legal_name ?? user.email.split("@")[0];
  const initials = displayName.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();

  return (
    <div className="app-shell">
      <aside className={mobileOpen ? "sidebar open" : "sidebar"}>
        <div className="sidebar-head">
          <div className="brand"><span className="brand-mark"><BadgePoundSterling /></span><span>Bantam</span></div>
          <button className="icon-button mobile-close" aria-label="Close navigation" onClick={() => setMobileOpen(false)}><X size={20} /></button>
        </div>
        <div className="workspace-label"><span>{workspaceLabel}</span><ChevronRight size={14} /></div>
        <nav className="sidebar-nav">
          {navigation.map((item) => {
            const Icon = item.icon;
            return <NavLink key={item.to} to={item.to} end={item.to === "/"} onClick={() => setMobileOpen(false)}><Icon size={19} /><span>{item.label}</span></NavLink>;
          })}
        </nav>
        <div className="sidebar-foot">
          <div className="security-block"><FileCheck2 size={18} /><div><strong>Demo environment</strong><span>Synthetic funds only</span></div></div>
          <div className="user-summary"><span className="avatar">{initials}</span><div><strong>{displayName}</strong><span>{humanize(user.role)}</span></div><button className="icon-button" aria-label="Sign out" onClick={logout}><LogOut size={18} /></button></div>
        </div>
      </aside>
      {mobileOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}

      <section className="main-shell">
        <header className="topbar">
          <button className="icon-button menu-button" aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Menu size={21} /></button>
          <div><p className="topbar-kicker">Bantam / X-Bank</p><strong>{routeTitles[location.pathname] ?? "Bantam"}</strong></div>
          <div className="topbar-actions"><span className="live-pill"><i /> API connected</span><button className="profile-chip"><CircleUserRound size={18} /><span>{displayName}</span></button></div>
        </header>
        <main className="page-content"><Outlet /></main>
      </section>
    </div>
  );
}
