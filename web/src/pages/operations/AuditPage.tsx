import { useQuery } from "@tanstack/react-query";
import { BookCheck, ChevronDown, ChevronUp, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "../../api";
import { EmptyState, ErrorState, LoadingState, PageHeader, Panel } from "../../components/ui";
import { formatDate, humanize, shortId } from "../../utils";

export function AuditPage() {
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const query = useQuery({ queryKey: ["audit-events"], queryFn: api.auditEvents, refetchInterval: 15_000 });
  const events = useMemo(() => (query.data?.events ?? []).filter((event) => !search || `${event.action} ${event.actor_id} ${event.resource_type} ${event.resource_id}`.toLowerCase().includes(search.toLowerCase())), [query.data, search]);
  if (query.isLoading) return <LoadingState label="Reading audit evidence" />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;
  return <div className="page-stack"><PageHeader eyebrow="Compliance evidence" title="Append-only audit trail" description="Trace authenticated actions, correlation IDs and control metadata." action={<span className="live-pill"><i /> Live evidence</span>} /><Panel padded={false}><div className="table-toolbar"><label className="search-field"><Search size={17} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search actor, action or resource" /></label><span className="result-count">{events.length} events</span></div>{events.length === 0 ? <EmptyState title="No matching evidence" description="Change the audit search." /> : <div className="audit-list">{events.map((event) => <article key={event.audit_event_id}><button className="audit-row" onClick={() => setExpanded((current) => current === event.audit_event_id ? null : event.audit_event_id)}><span className="round-icon mini"><BookCheck size={16} /></span><div><strong>{humanize(event.action)}</strong><span>{humanize(event.resource_type)} · {shortId(event.resource_id)}</span></div><div><code>{shortId(event.actor_id)}</code><small>{formatDate(event.created_at, true)}</small></div>{expanded === event.audit_event_id ? <ChevronUp size={17} /> : <ChevronDown size={17} />}</button>{expanded === event.audit_event_id && <div className="audit-detail"><div><span>Request ID</span><code>{event.request_id}</code></div><div><span>Correlation ID</span><code>{event.correlation_id}</code></div><div><span>IP address</span><code>{event.ip_address ?? "Not recorded"}</code></div><pre>{JSON.stringify(event.metadata, null, 2)}</pre></div>}</article>)}</div>}</Panel></div>;
}
