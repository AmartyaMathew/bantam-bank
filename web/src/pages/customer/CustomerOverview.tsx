import { useMutation, useQueries, useQuery } from "@tanstack/react-query";
import { ArrowDownLeft, ArrowRight, ArrowUpRight, Bell, SendHorizontal, ShieldCheck, WalletCards } from "lucide-react";
import { Link } from "react-router";
import { api } from "../../api";
import { useAuth } from "../../auth";
import { Button, EmptyState, ErrorState, LoadingState, Panel, StatusPill, useToast } from "../../components/ui";
import type { Transaction } from "../../types";
import { formatDate, formatMoney } from "../../utils";

export function CustomerOverview() {
  const { user, refreshUser } = useAuth();
  const toast = useToast();
  const accountsQuery = useQuery({ queryKey: ["accounts"], queryFn: api.accounts });
  const notificationsQuery = useQuery({ queryKey: ["notifications"], queryFn: api.notifications });
  const submitKYC = useMutation({ mutationFn: api.submitKYC, onSuccess: async () => { await refreshUser(); toast.success("KYC submitted", "A bank administrator can now review this synthetic profile."); }, onError: (error) => toast.error("KYC submission failed", error) });
  const accounts = accountsQuery.data?.accounts ?? [];
  const transactionQueries = useQueries({
    queries: accounts.map((account) => ({
      queryKey: ["transactions", account.account_id],
      queryFn: () => api.accountTransactions(account.account_id),
    })),
  });

  if (accountsQuery.isLoading) return <LoadingState label="Opening your accounts" />;
  if (accountsQuery.error) return <ErrorState error={accountsQuery.error} onRetry={() => accountsQuery.refetch()} />;

  const accountIds = new Set(accounts.map((account) => account.account_id));
  const transactions = transactionQueries
    .flatMap((query) => query.data?.transactions ?? [])
    .filter((transaction, index, all) => all.findIndex((item) => item.transaction_id === transaction.transaction_id) === index)
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5);
  const total = accounts.reduce((sum, account) => sum + account.balance_minor, 0);

  return (
    <div className="page-stack">
      <header className="welcome-header"><div><p className="eyebrow">Good to see you</p><h1>{user?.legal_name?.split(" ")[0] ?? "Customer"}, here’s your money at a glance.</h1><p>All balances below are synthetic and backed by Bantam’s immutable demo ledger.</p></div><span className="demo-tag"><ShieldCheck size={16} /> DEMO MODE</span></header>

      {(user?.kyc_status === "PENDING_KYC" || user?.kyc_status === "KYC_REJECTED") && <div className="kyc-banner"><ShieldCheck size={21} /><div><strong>Complete identity verification</strong><span>Your profile must enter KYC review before you can open an account or send funds.</span></div><Button onClick={() => submitKYC.mutate()} disabled={submitKYC.isPending}>{submitKYC.isPending ? "Submitting…" : "Submit KYC"}</Button></div>}

      <div className="customer-hero-grid">
        <section className="balance-hero">
          <div className="balance-hero-top"><div><span>Total balance</span><strong>{formatMoney(total)}</strong><small>Across {accounts.length} active {accounts.length === 1 ? "account" : "accounts"}</small></div><span className="balance-emblem"><WalletCards /></span></div>
          <div className="balance-actions"><Link className="button button-light" to="/transfer"><SendHorizontal size={17} /> Send money</Link><Link className="button button-dark-outline" to="/accounts">View accounts <ArrowRight size={16} /></Link></div>
          <span className="card-shape shape-a" /><span className="card-shape shape-b" />
        </section>
        <Panel className="security-summary">
          <div className="panel-heading"><div><p className="eyebrow">Customer status</p><h2>Identity & access</h2></div><ShieldCheck size={22} /></div>
          <div className="security-row"><span>KYC status</span>{user?.kyc_status ? <StatusPill value={user.kyc_status} /> : <span>—</span>}</div>
          <div className="security-row"><span>Risk rating</span>{user?.risk_rating ? <StatusPill value={user.risk_rating} /> : <span>—</span>}</div>
          <div className="security-row"><span>Multi-factor</span><StatusPill value={user?.mfa_enabled ? "ACTIVE" : "DISABLED"} /></div>
          <Link className="text-link" to="/trust">Issue an account-status claim <ArrowRight size={15} /></Link>
        </Panel>
      </div>

      <div className="dashboard-grid">
        <Panel className="activity-panel" padded={false}>
          <div className="panel-heading panel-heading-padded"><div><p className="eyebrow">Latest movements</p><h2>Recent activity</h2></div><Link className="text-link" to="/activity">See all <ArrowRight size={15} /></Link></div>
          {transactions.length === 0 ? <EmptyState title="No activity yet" description="Your completed transfers and deposits will appear here." /> : <div className="transaction-list">{transactions.map((transaction) => <TransactionRow key={transaction.transaction_id} transaction={transaction} accountIds={accountIds} />)}</div>}
        </Panel>
        <Panel className="notification-preview">
          <div className="panel-heading"><div><p className="eyebrow">Updates</p><h2>Notifications</h2></div><span className="round-icon"><Bell size={19} /></span></div>
          {notificationsQuery.isLoading ? <LoadingState label="Checking notifications" /> : (notificationsQuery.data?.notifications.length ?? 0) === 0 ? <EmptyState title="You’re all caught up" description="Transfer confirmations and account updates will appear here." /> : <div className="compact-notifications">{notificationsQuery.data?.notifications.slice(0, 3).map((notification) => <article key={notification.notification_id}><span /><div><strong>{notification.subject}</strong><p>{notification.body}</p><small>{formatDate(notification.created_at, true)}</small></div></article>)}</div>}
          <Link className="text-link" to="/notifications">Open notification centre <ArrowRight size={15} /></Link>
        </Panel>
      </div>
    </div>
  );
}

export function TransactionRow({ transaction, accountIds }: { transaction: Transaction; accountIds: Set<string> }) {
  const outgoing = accountIds.has(transaction.source_account_id) && transaction.transaction_type === "TRANSFER";
  const Icon = outgoing ? ArrowUpRight : ArrowDownLeft;
  return <article className="transaction-row"><span className={outgoing ? "transaction-icon outgoing" : "transaction-icon incoming"}><Icon size={18} /></span><div className="transaction-main"><strong>{transaction.description || transaction.transaction_type}</strong><span>{formatDate(transaction.created_at, true)} · {transaction.transaction_type.replace("_", " ")}</span></div><div className="transaction-value"><strong className={outgoing ? "money-out" : "money-in"}>{outgoing ? "−" : "+"}{formatMoney(transaction.amount_minor, transaction.currency)}</strong><StatusPill value={transaction.status} /></div></article>;
}
