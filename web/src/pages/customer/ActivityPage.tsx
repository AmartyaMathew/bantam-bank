import { useQueries, useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { api } from "../../api";
import { EmptyState, ErrorState, LoadingState, PageHeader, Panel } from "../../components/ui";
import { TransactionRow } from "./CustomerOverview";

export function ActivityPage() {
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const accountsQuery = useQuery({ queryKey: ["accounts"], queryFn: api.accounts });
  const accounts = accountsQuery.data?.accounts ?? [];
  const transactionQueries = useQueries({ queries: accounts.map((account) => ({ queryKey: ["transactions", account.account_id], queryFn: () => api.accountTransactions(account.account_id) })) });
  const selectedAccount = params.get("account") ?? "all";
  const accountIds = useMemo(() => new Set(accounts.map((account) => account.account_id)), [accounts]);
  const transactions = useMemo(() => transactionQueries.flatMap((query) => query.data?.transactions ?? []).filter((transaction, index, all) => all.findIndex((item) => item.transaction_id === transaction.transaction_id) === index).filter((transaction) => selectedAccount === "all" || transaction.source_account_id === selectedAccount || transaction.destination_account_id === selectedAccount).filter((transaction) => !search || `${transaction.description} ${transaction.transaction_type} ${transaction.transaction_id}`.toLowerCase().includes(search.toLowerCase())).sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()), [transactionQueries, selectedAccount, search]);
  if (accountsQuery.isLoading) return <LoadingState label="Loading account activity" />;
  if (accountsQuery.error) return <ErrorState error={accountsQuery.error} onRetry={() => accountsQuery.refetch()} />;
  return <div className="page-stack"><PageHeader eyebrow="Ledger activity" title="Transactions" description="A complete view of money movements across your Bantam accounts." /><Panel padded={false}><div className="table-toolbar"><label className="search-field"><Search size={17} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search description or transaction ID" /></label><select value={selectedAccount} onChange={(event) => { const value = event.target.value; setParams(value === "all" ? {} : { account: value }); }}><option value="all">All accounts</option>{accounts.map((account) => <option value={account.account_id} key={account.account_id}>{account.account_reference}</option>)}</select></div>{transactionQueries.some((query) => query.isLoading) ? <LoadingState label="Reading ledger entries" /> : transactions.length === 0 ? <EmptyState title="No matching transactions" description="Try another account or search term." /> : <div className="transaction-list roomy">{transactions.map((transaction) => <TransactionRow key={transaction.transaction_id} transaction={transaction} accountIds={accountIds} />)}</div>}</Panel></div>;
}
