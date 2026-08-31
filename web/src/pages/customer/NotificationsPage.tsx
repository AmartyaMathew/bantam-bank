import { useQuery } from "@tanstack/react-query";
import { Bell, CheckCheck } from "lucide-react";
import { api } from "../../api";
import { EmptyState, ErrorState, LoadingState, PageHeader, Panel } from "../../components/ui";
import { formatDate } from "../../utils";

export function NotificationsPage() {
  const query = useQuery({ queryKey: ["notifications"], queryFn: api.notifications, refetchInterval: 10_000 });
  if (query.isLoading) return <LoadingState label="Checking notifications" />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;
  const notifications = query.data?.notifications ?? [];
  return <div className="page-stack"><PageHeader eyebrow="Event delivery" title="Notifications" description="Messages produced asynchronously from committed banking events." action={<span className="live-pill"><i /> Refreshes every 10s</span>} /><Panel padded={false}>{notifications.length === 0 ? <EmptyState title="No notifications" description="Complete a transfer to see the notification worker deliver an event." /> : <div className="notification-list">{notifications.map((notification) => <article key={notification.notification_id}><span className="notification-icon"><Bell size={19} /></span><div><div className="notification-title"><h3>{notification.subject}</h3>{notification.read_at && <span><CheckCheck size={14} /> Read</span>}</div><p>{notification.body}</p><small>{formatDate(notification.created_at, true)} · {notification.type.replaceAll("_", " ")}</small></div></article>)}</div>}</Panel></div>;
}
