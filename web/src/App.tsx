import { BadgePoundSterling, LockKeyhole } from "lucide-react";
import { Navigate, Outlet, Route, Routes, useLocation } from "react-router";
import { useAuth } from "./auth";
import { AppShell } from "./components/AppShell";
import { Button, LoadingState, Panel } from "./components/ui";
import { AccountsPage } from "./pages/customer/AccountsPage";
import { ActivityPage } from "./pages/customer/ActivityPage";
import { CustomerOverview } from "./pages/customer/CustomerOverview";
import { NotificationsPage } from "./pages/customer/NotificationsPage";
import { TransferPage } from "./pages/customer/TransferPage";
import { TrustPage } from "./pages/customer/TrustPage";
import { LoginPage } from "./pages/LoginPage";
import { RegisterPage } from "./pages/RegisterPage";
import { SecurityPage } from "./pages/SecurityPage";
import { AdminUsersPage } from "./pages/operations/AdminUsersPage";
import { AspisAuditorsPage } from "./pages/operations/AspisAuditorsPage";
import { AttackLabPage } from "./pages/operations/AttackLabPage";
import { AuditPage } from "./pages/operations/AuditPage";
import { AsvsPage } from "./pages/operations/AsvsPage";
import { CustomersPage } from "./pages/operations/CustomersPage";
import { FinancialsPage } from "./pages/operations/FinancialsPage";
import { OperationsOverview } from "./pages/operations/OperationsOverview";
import { ReconciliationPage } from "./pages/operations/ReconciliationPage";
import { RiskPage } from "./pages/operations/RiskPage";
import { TransactionsPage } from "./pages/operations/TransactionsPage";
import { WorkflowGraphPage } from "./pages/operations/WorkflowGraphPage";
import type { PropsWithChildren } from "react";
import type { AdminPermissionScope, Role } from "./types";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route index element={<RoleHome />} />
          <Route path="accounts" element={<RoleGate roles={["CUSTOMER"]}><AccountsPage /></RoleGate>} />
          <Route path="transfer" element={<RoleGate roles={["CUSTOMER"]}><TransferPage /></RoleGate>} />
          <Route path="activity" element={<RoleGate roles={["CUSTOMER"]}><ActivityPage /></RoleGate>} />
          <Route path="notifications" element={<RoleGate roles={["CUSTOMER"]}><NotificationsPage /></RoleGate>} />
          <Route path="trust" element={<RoleGate roles={["CUSTOMER"]}><TrustPage /></RoleGate>} />
          <Route path="admin-users" element={<RoleGate roles={["BANK_ADMIN"]} scope="admin_users"><AdminUsersPage /></RoleGate>} />
          <Route path="customers" element={<RoleGate roles={["BANK_ADMIN"]} scope="customers"><CustomersPage /></RoleGate>} />
          <Route path="transactions" element={<RoleGate roles={["BANK_ADMIN", "RISK_ANALYST"]} scope="transactions"><TransactionsPage /></RoleGate>} />
          <Route path="risk" element={<RoleGate roles={["BANK_ADMIN", "RISK_ANALYST"]} scope="risk"><RiskPage /></RoleGate>} />
          <Route path="audit" element={<RoleGate roles={["BANK_ADMIN", "RISK_ANALYST", "COMPLIANCE_AUDITOR"]} scope="audit"><AuditPage /></RoleGate>} />
          <Route path="asvs" element={<RoleGate roles={["BANK_ADMIN", "ASPIS_ADMIN", "ASPIS_AUDITOR"]} scope="asvs"><AsvsPage /></RoleGate>} />
          <Route path="aspis-auditors" element={<RoleGate roles={["BANK_ADMIN", "ASPIS_ADMIN"]} scope="aspis_auditors"><AspisAuditorsPage /></RoleGate>} />
          <Route path="security" element={<RoleGate roles={["BANK_ADMIN", "ASPIS_ADMIN", "ASPIS_AUDITOR"]}><SecurityPage /></RoleGate>} />
          <Route path="reconciliation" element={<RoleGate roles={["BANK_ADMIN", "COMPLIANCE_AUDITOR"]} scope="reconciliation"><ReconciliationPage /></RoleGate>} />
          <Route path="workflows" element={<RoleGate roles={["BANK_ADMIN"]} scope="workflows"><WorkflowGraphPage /></RoleGate>} />
          <Route path="attack-lab" element={<RoleGate roles={["BANK_ADMIN", "RISK_ANALYST"]} scope="attack_lab"><AttackLabPage /></RoleGate>} />
          <Route path="financials" element={<RoleGate roles={["BANK_ADMIN", "RISK_ANALYST"]} scope="company_financials"><FinancialsPage /></RoleGate>} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Route>
    </Routes>
  );
}

function RequireAuth() {
  const { session, user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <div className="app-loading"><div className="brand"><span className="brand-mark"><BadgePoundSterling /></span><span>Bantam</span></div><LoadingState label="Verifying secure session" /></div>;
  if (!session || !user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <Outlet />;
}

function RoleHome() {
  const { user } = useAuth();
  if (user?.role === "CUSTOMER") return <CustomerOverview />;
  if (user?.role === "ASPIS_AUDITOR") return <Navigate to="/asvs" replace />;
  if (user?.role === "ASPIS_ADMIN") {
    return <Navigate to="/aspis-auditors" replace />;
  }
  return <OperationsOverview />;
}

function RoleGate({
  roles,
  scope,
  children,
}: PropsWithChildren<{ roles: Role[]; scope?: AdminPermissionScope }>) {
  const { user } = useAuth();
  if (!user || !roles.includes(user.role)) return <Forbidden />;
  if (
    user.role === "BANK_ADMIN"
    && scope
    && !user.is_super_admin
    && !user.admin_permissions.includes(scope)
  ) {
    return <Forbidden />;
  }
  return children;
}

function Forbidden() {
  return <Panel className="forbidden"><span><LockKeyhole size={25} /></span><p className="eyebrow">Role protected</p><h1>This workspace is not available to your role.</h1><p>The API enforces the same access rule. Return to the overview to use the controls assigned to your demo identity.</p><Button onClick={() => window.location.assign("/")}>Return to overview</Button></Panel>;
}

function NotFound() {
  return <Panel className="forbidden"><p className="eyebrow">404</p><h1>That page does not exist.</h1><p>Use the Bantam navigation to return to a known workspace.</p><Button onClick={() => window.location.assign("/")}>Return to overview</Button></Panel>;
}
