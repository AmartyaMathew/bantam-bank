import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, ShieldAlert, ShieldCheck, XCircle } from "lucide-react";
import { useState } from "react";
import { api } from "../../api";
import { Button, EmptyState, ErrorState, LoadingState, PageHeader, Panel, StatusPill, useToast } from "../../components/ui";
import type { RiskAlert } from "../../types";
import { formatDate, humanize, shortId } from "../../utils";

export function RiskPage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [status, setStatus] = useState<RiskAlert["status"]>("OPEN");
  const query = useQuery({ queryKey: ["risk-alerts", status], queryFn: () => api.riskAlerts(status) });
  const review = useMutation({
    mutationFn: ({ id, next }: { id: string; next: "REVIEWED" | "DISMISSED" }) => api.reviewRiskAlert(id, next, `${next === "REVIEWED" ? "Reviewed" : "Dismissed"} from Bantam risk console`),
    onSuccess: (_, variables) => { queryClient.invalidateQueries({ queryKey: ["risk-alerts"] }); toast.success(`Alert ${variables.next.toLowerCase()}`); },
    onError: (error) => toast.error("Could not update alert", error),
  });
  if (query.isLoading) return <LoadingState label="Loading the risk queue" />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;
  const alerts = query.data?.alerts ?? [];
  return <div className="page-stack"><PageHeader eyebrow="Risk operations" title="Alert queue" description="Investigate worker-generated and manually raised transaction alerts." /><div className="segmented-control" role="tablist">{(["OPEN", "REVIEWED", "DISMISSED"] as const).map((value) => <button role="tab" aria-selected={status === value} className={status === value ? "active" : ""} onClick={() => setStatus(value)} key={value}>{humanize(value)}</button>)}</div>{alerts.length === 0 ? <Panel><EmptyState title={`No ${status.toLowerCase()} alerts`} description={status === "OPEN" ? "The active queue is clear." : "No alerts have reached this state."} /></Panel> : <div className="alert-grid">{alerts.map((alert) => <Panel className={`risk-card severity-${alert.severity.toLowerCase()}`} key={alert.risk_alert_id}><div className="risk-card-head"><span className="risk-icon"><ShieldAlert size={20} /></span><div><StatusPill value={alert.severity} /><StatusPill value={alert.status} /></div></div><p className="eyebrow">{humanize(alert.rule_id)}</p><h2>{alert.explanation}</h2><div className="risk-details"><span>Transaction<code>{shortId(alert.transaction_id)}</code></span><span>Customer<code>{alert.customer_id ? shortId(alert.customer_id) : "System"}</code></span><span>Raised<strong>{formatDate(alert.created_at, true)}</strong></span></div>{alert.status === "OPEN" && <div className="risk-actions"><Button variant="secondary" onClick={() => review.mutate({ id: alert.risk_alert_id, next: "DISMISSED" })} disabled={review.isPending}><XCircle size={16} /> Dismiss</Button><Button onClick={() => review.mutate({ id: alert.risk_alert_id, next: "REVIEWED" })} disabled={review.isPending}><CheckCircle2 size={16} /> Mark reviewed</Button></div>}{alert.reviewed_at && <div className="reviewed-note"><ShieldCheck size={16} /> Reviewed {formatDate(alert.reviewed_at, true)}</div>}</Panel>)}</div>}</div>;
}
