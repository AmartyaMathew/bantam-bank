import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Landmark, Plus, ShieldCheck, WalletCards } from "lucide-react";
import { Link } from "react-router";
import { api } from "../../api";
import { Button, EmptyState, ErrorState, LoadingState, PageHeader, Panel, StatusPill, useToast } from "../../components/ui";
import { formatDate, formatMoney, shortId } from "../../utils";

export function AccountsPage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const accountsQuery = useQuery({ queryKey: ["accounts"], queryFn: api.accounts });
  const openMutation = useMutation({
    mutationFn: api.openAccount,
    onSuccess: (account) => { queryClient.invalidateQueries({ queryKey: ["accounts"] }); toast.success("Account opened", account.account_reference); },
    onError: (error) => toast.error("Could not open account", error),
  });
  if (accountsQuery.isLoading) return <LoadingState />;
  if (accountsQuery.error) return <ErrorState error={accountsQuery.error} onRetry={() => accountsQuery.refetch()} />;
  const accounts = accountsQuery.data?.accounts ?? [];
  return <div className="page-stack"><PageHeader eyebrow="Personal banking" title="Your accounts" description="Each balance is a projection of immutable double-entry ledger postings." action={<Button onClick={() => openMutation.mutate()} disabled={openMutation.isPending}><Plus size={17} /> {openMutation.isPending ? "Opening…" : "Open GBP account"}</Button>} />{accounts.length === 0 ? <EmptyState title="No accounts yet" description="Open a GBP current account after KYC verification." /> : <div className="account-grid">{accounts.map((account, index) => <Panel className="account-card" key={account.account_id}><div className="account-card-head"><span className={index % 2 ? "round-icon plum" : "round-icon"}>{index % 2 ? <Landmark size={20} /> : <WalletCards size={20} />}</span><StatusPill value={account.status} /></div><p>{account.account_type === "CURRENT" ? "Bantam Current" : account.account_type}</p><h2>{formatMoney(account.balance_minor, account.currency)}</h2><div className="account-meta"><span>Reference<strong>{account.account_reference}</strong></span><span>Opened<strong>{formatDate(account.opened_at)}</strong></span></div><div className="account-id"><ShieldCheck size={15} /><code>{shortId(account.account_id)}</code></div><Link className="button button-secondary" to={`/activity?account=${account.account_id}`}>View activity <ArrowRight size={16} /></Link></Panel>)}</div>}</div>;
}
