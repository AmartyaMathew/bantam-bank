import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Flag, RotateCcw, Search, Snowflake, UnlockKeyhole } from "lucide-react";
import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../../api";
import { useAuth } from "../../auth";
import { Button, EmptyState, ErrorState, LoadingState, Modal, PageHeader, Panel, StatusPill, useToast } from "../../components/ui";
import type { RiskAlert, Transaction } from "../../types";
import { formatDate, formatMoney, parseMoney, shortId } from "../../utils";

type Action =
  | { type: "alert"; transaction: Transaction }
  | { type: "reverse"; transaction: Transaction }
  | { type: "freeze" | "unfreeze"; transaction: Transaction };

export function TransactionsPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [minimum, setMinimum] = useState("0");
  const [appliedMinimum, setAppliedMinimum] = useState(0);
  const [search, setSearch] = useState("");
  const [action, setAction] = useState<Action | null>(null);
  const [reason, setReason] = useState("");
  const [severity, setSeverity] = useState<RiskAlert["severity"]>("HIGH");
  const query = useQuery({ queryKey: ["operator-transactions", appliedMinimum], queryFn: () => api.operatorTransactions(appliedMinimum) });
  const transactions = (query.data?.transactions ?? []).filter((transaction) => !search || `${transaction.description} ${transaction.transaction_id} ${transaction.source_account_id} ${transaction.destination_account_id}`.toLowerCase().includes(search.toLowerCase()));

  const operation = useMutation({
    mutationFn: async () => {
      if (!action) return;
      if (action.type === "alert") return api.createRiskAlert(action.transaction.transaction_id, severity, reason || "Manual review requested from transaction monitoring");
      if (action.type === "reverse") return api.reverseTransaction(action.transaction.transaction_id, reason || "Operator reversal", crypto.randomUUID());
      return api.setAccountStatus(action.transaction.source_account_id, action.type === "freeze" ? "FROZEN" : "ACTIVE", reason || `Account ${action.type}d during risk review`);
    },
    onSuccess: () => {
      toast.success("Control action completed");
      setAction(null);
      setReason("");
      queryClient.invalidateQueries({ queryKey: ["operator-transactions"] });
      queryClient.invalidateQueries({ queryKey: ["risk-alerts"] });
    },
    onError: (error) => toast.error("Control action failed", error),
  });

  if (query.isLoading) return <LoadingState label="Reading transaction ledger" />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;
  const submitAction = (event: FormEvent) => { event.preventDefault(); operation.mutate(); };

  return <div className="page-stack"><PageHeader eyebrow="Transaction monitoring" title="Ledger transactions" description="Search money movements, create investigations and perform controlled operator actions." /><Panel padded={false}><div className="table-toolbar wrap"><label className="search-field"><Search size={17} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search IDs, accounts or description" /></label><div className="amount-filter"><span>Minimum £</span><input value={minimum} inputMode="decimal" onChange={(event) => setMinimum(event.target.value)} /><Button variant="secondary" onClick={() => setAppliedMinimum(parseMoney(minimum))}>Apply</Button></div></div>{transactions.length === 0 ? <EmptyState title="No matching transactions" description="Lower the amount threshold or change the search." /> : <div className="table-wrap"><table><thead><tr><th>Transaction</th><th>Route</th><th>Amount</th><th>Type</th><th>Status</th><th>Posted</th><th>Actions</th></tr></thead><tbody>{transactions.map((transaction) => <tr key={transaction.transaction_id}><td><div className="stacked-cell"><strong>{transaction.description || "No description"}</strong><code>{shortId(transaction.transaction_id)}</code></div></td><td><div className="route-cell"><code>{shortId(transaction.source_account_id)}</code><span>→</span><code>{shortId(transaction.destination_account_id)}</code></div></td><td><strong>{formatMoney(transaction.amount_minor, transaction.currency)}</strong></td><td>{transaction.transaction_type.replaceAll("_", " ")}</td><td><StatusPill value={transaction.status} /></td><td>{formatDate(transaction.posted_at ?? transaction.created_at, true)}</td><td><div className="icon-actions"><button title="Create risk alert" onClick={() => setAction({ type: "alert", transaction })}><Flag size={17} /></button><button title="Freeze source account" onClick={() => setAction({ type: "freeze", transaction })}><Snowflake size={17} /></button><button title="Unfreeze source account" onClick={() => setAction({ type: "unfreeze", transaction })}><UnlockKeyhole size={17} /></button>{user?.role === "BANK_ADMIN" && transaction.status === "POSTED" && <button title="Reverse transaction" onClick={() => setAction({ type: "reverse", transaction })}><RotateCcw size={17} /></button>}</div></td></tr>)}</tbody></table></div>}</Panel><Modal open={Boolean(action)} title={action?.type === "alert" ? "Create risk alert" : action?.type === "reverse" ? "Reverse transaction" : action?.type === "freeze" ? "Freeze source account" : "Unfreeze source account"} description={action ? `Transaction ${shortId(action.transaction.transaction_id)}` : undefined} onClose={() => !operation.isPending && setAction(null)}>{action && <form className="modal-form" onSubmit={submitAction}>{action.type === "alert" && <label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value as RiskAlert["severity"])}><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></label>}<label>{action.type === "alert" ? "Explanation" : "Reason"}<textarea value={reason} onChange={(event) => setReason(event.target.value)} rows={4} placeholder="Record why this controlled action is necessary" required /></label><div className="action-summary"><span>Amount<strong>{formatMoney(action.transaction.amount_minor)}</strong></span><span>Source account<code>{shortId(action.transaction.source_account_id)}</code></span></div><div className="modal-actions"><Button type="button" variant="secondary" onClick={() => setAction(null)}>Cancel</Button><Button type="submit" variant={action.type === "reverse" || action.type === "freeze" ? "danger" : "primary"} disabled={operation.isPending}>{operation.isPending ? "Applying…" : "Confirm action"}</Button></div></form>}</Modal></div>;
}
