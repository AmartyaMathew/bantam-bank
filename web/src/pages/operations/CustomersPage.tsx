import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Search, UserCheck, UserRoundX } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "../../api";
import { Button, EmptyState, ErrorState, LoadingState, PageHeader, Panel, StatusPill, useToast } from "../../components/ui";
import { formatDate, shortId } from "../../utils";

export function CustomersPage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [search, setSearch] = useState("");
  const [kyc, setKyc] = useState("ALL");
  const query = useQuery({ queryKey: ["customers"], queryFn: api.customers });
  const decision = useMutation({
    mutationFn: ({ id, value }: { id: string; value: "APPROVE" | "REJECT" }) => api.decideKYC(id, value, `${value === "APPROVE" ? "Approved" : "Rejected"} in Bantam demo operations console`),
    onSuccess: (_, variables) => { queryClient.invalidateQueries({ queryKey: ["customers"] }); toast.success(`KYC ${variables.value === "APPROVE" ? "approved" : "rejected"}`); },
    onError: (error) => toast.error("KYC decision failed", error),
  });
  const customers = useMemo(() => (query.data?.customers ?? []).filter((customer) => kyc === "ALL" || customer.kyc_status === kyc).filter((customer) => !search || `${customer.legal_name} ${customer.email} ${customer.customer_id}`.toLowerCase().includes(search.toLowerCase())), [query.data, search, kyc]);
  if (query.isLoading) return <LoadingState label="Loading customer records" />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;
  return <div className="page-stack"><PageHeader eyebrow="Customer operations" title="Customers & KYC" description="Review synthetic customer profiles and make controlled identity decisions." /><Panel padded={false}><div className="table-toolbar"><label className="search-field"><Search size={17} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search name, email or customer ID" /></label><select value={kyc} onChange={(event) => setKyc(event.target.value)}><option value="ALL">All KYC states</option><option value="PENDING_REVIEW">Pending review</option><option value="KYC_VERIFIED">Verified</option><option value="KYC_REJECTED">Rejected</option></select></div>{customers.length === 0 ? <EmptyState title="No matching customers" description="Change the search or KYC filter." /> : <div className="table-wrap"><table><thead><tr><th>Customer</th><th>KYC</th><th>Risk</th><th>Status</th><th>Created</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{customers.map((customer) => <tr key={customer.customer_id}><td><div className="identity-cell"><span className="avatar small">{customer.legal_name.split(/\s+/).map((part) => part[0]).join("").slice(0, 2)}</span><div><strong>{customer.legal_name}</strong><span>{customer.email}</span><code>{shortId(customer.customer_id)}</code></div></div></td><td><StatusPill value={customer.kyc_status} /></td><td><StatusPill value={customer.risk_rating} /></td><td><StatusPill value={customer.status} /></td><td>{formatDate(customer.created_at)}</td><td>{customer.kyc_status === "PENDING_REVIEW" ? <div className="table-actions"><Button variant="secondary" onClick={() => decision.mutate({ id: customer.customer_id, value: "APPROVE" })} disabled={decision.isPending}><UserCheck size={15} /> Approve</Button><Button variant="ghost" onClick={() => decision.mutate({ id: customer.customer_id, value: "REJECT" })} disabled={decision.isPending}><UserRoundX size={15} /> Reject</Button></div> : <span className="decision-complete"><Check size={15} /> Decided</span>}</td></tr>)}</tbody></table></div>}</Panel></div>;
}
