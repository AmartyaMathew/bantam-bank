import { useQuery } from "@tanstack/react-query";
import { Activity, ArrowRight, BookCheck, CircleAlert, Fingerprint, Scale, ShieldAlert, ShieldCheck, UsersRound } from "lucide-react";
import { Link } from "react-router";
import { api } from "../../api";
import { useAuth } from "../../auth";
import { EmptyState, Panel, StatusPill } from "../../components/ui";
import { formatDate, formatMoney, humanize, shortId } from "../../utils";

export function OperationsOverview() {
  const { user } = useAuth();
  const canViewTransactions = user?.role === "BANK_ADMIN" || user?.role === "RISK_ANALYST";
  const canViewCustomers = user?.role === "BANK_ADMIN";
  const transactions = useQuery({ queryKey: ["operator-transactions", 0], queryFn: () => api.operatorTransactions(), enabled: canViewTransactions });
  const alerts = useQuery({ queryKey: ["risk-alerts", "OPEN"], queryFn: () => api.riskAlerts("OPEN"), enabled: canViewTransactions });
  const customers = useQuery({ queryKey: ["customers"], queryFn: api.customers, enabled: canViewCustomers });
  const audit = useQuery({ queryKey: ["audit-events"], queryFn: api.auditEvents });
  const transactionItems = transactions.data?.transactions ?? [];
  const alertItems = alerts.data?.alerts ?? [];
  const customerItems = customers.data?.customers ?? [];
  const eventItems = audit.data?.events ?? [];
  const totalFlow = transactionItems.reduce((sum, transaction) => sum + transaction.amount_minor, 0);
  const title = user?.role === "COMPLIANCE_AUDITOR" ? "Compliance control room" : user?.role === "RISK_ANALYST" ? "Risk operations" : "Bank operations";

  return <div className="page-stack"><header className="welcome-header ops-welcome"><div><p className="eyebrow">Control plane</p><h1>{title}</h1><p>Monitor synthetic banking activity, investigate risk and verify ledger controls.</p></div><span className="demo-tag"><CircleAlert size={16} /> NON-PRODUCTION</span></header>{canViewCustomers && <Link className="asvs-overview-entry" to="/asvs"><span><ShieldCheck size={23} /></span><div><p className="eyebrow">Application assurance</p><strong>Open the ASVS control room</strong><small>Verify five reviewed access-control properties and inspect sealed evidence.</small></div><Fingerprint size={20} /><ArrowRight size={18} /></Link>}<div className="metric-grid">{canViewCustomers && <Metric icon={<UsersRound />} label="Customers" value={customerItems.length.toString()} detail={`${customerItems.filter((customer) => customer.kyc_status === "PENDING_REVIEW").length} awaiting KYC`} />}{canViewTransactions && <Metric icon={<Activity />} label="Transactions" value={transactionItems.length.toString()} detail={`${formatMoney(totalFlow)} observed flow`} />}{canViewTransactions && <Metric icon={<ShieldAlert />} label="Open risk alerts" value={alertItems.length.toString()} detail={alertItems.some((alert) => alert.severity === "CRITICAL") ? "Critical review required" : "No critical alerts"} tone={alertItems.length ? "warning" : "positive"} />}<Metric icon={<BookCheck />} label="Audit events" value={eventItems.length.toString()} detail="Append-only evidence" /></div><div className="dashboard-grid">{canViewTransactions ? <Panel padded={false}><div className="panel-heading panel-heading-padded"><div><p className="eyebrow">Latest ledger movement</p><h2>Transactions</h2></div><Link className="text-link" to="/transactions">Investigate <ArrowRight size={15} /></Link></div>{transactionItems.length === 0 ? <EmptyState title="No transactions" description="Seed and customer activity will appear here." /> : <div className="ops-compact-list">{transactionItems.slice(0, 6).map((transaction) => <article key={transaction.transaction_id}><span className="round-icon mini"><Scale size={16} /></span><div><strong>{transaction.description || humanize(transaction.transaction_type)}</strong><small>{shortId(transaction.transaction_id)} · {formatDate(transaction.created_at, true)}</small></div><div><strong>{formatMoney(transaction.amount_minor)}</strong><StatusPill value={transaction.status} /></div></article>)}</div>}</Panel> : <Panel padded={false}><div className="panel-heading panel-heading-padded"><div><p className="eyebrow">Evidence stream</p><h2>Recent audit activity</h2></div><Link className="text-link" to="/audit">View all <ArrowRight size={15} /></Link></div><AuditPreview events={eventItems.slice(0, 6)} /></Panel>}<Panel padded={false}><div className="panel-heading panel-heading-padded"><div><p className="eyebrow">Control events</p><h2>{canViewTransactions ? "Open risk queue" : "Recent evidence"}</h2></div><Link className="text-link" to={canViewTransactions ? "/risk" : "/audit"}>Open queue <ArrowRight size={15} /></Link></div>{canViewTransactions ? alertItems.length === 0 ? <EmptyState title="Queue is clear" description="Risk workers have not raised an open alert." /> : <div className="ops-compact-list alerts">{alertItems.slice(0, 6).map((alert) => <article key={alert.risk_alert_id}><span className="round-icon mini danger"><ShieldAlert size={16} /></span><div><strong>{humanize(alert.rule_id)}</strong><small>{alert.explanation}</small></div><StatusPill value={alert.severity} /></article>)}</div> : <AuditPreview events={eventItems.slice(0, 6)} />}</Panel></div></div>;
}

function Metric({ icon, label, value, detail, tone = "neutral" }: { icon: React.ReactNode; label: string; value: string; detail: string; tone?: "neutral" | "positive" | "warning" }) {
  return <Panel className={`metric-card metric-${tone}`}><div className="metric-card-head"><span>{label}</span><i>{icon}</i></div><strong>{value}</strong><small>{detail}</small></Panel>;
}

function AuditPreview({ events }: { events: Array<{ audit_event_id: string; action: string; resource_type: string; created_at: string }> }) {
  return events.length === 0 ? <EmptyState title="No audit evidence" description="Authenticated actions will be recorded here." /> : <div className="ops-compact-list">{events.map((event) => <article key={event.audit_event_id}><span className="round-icon mini"><BookCheck size={16} /></span><div><strong>{humanize(event.action)}</strong><small>{humanize(event.resource_type)} · {formatDate(event.created_at, true)}</small></div></article>)}</div>;
}
