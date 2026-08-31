import {
  Check,
  CircleAlert,
  Clipboard,
  Inbox,
  LoaderCircle,
  ShieldCheck,
  X,
} from "lucide-react";
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";
import type {
  ButtonHTMLAttributes,
  PropsWithChildren,
  ReactNode,
} from "react";
import { ApiError } from "../api";
import { humanize, statusTone } from "../utils";

export function Button({
  className = "",
  variant = "primary",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
}) {
  return <button className={`button button-${variant} ${className}`} {...props} />;
}

export function Panel({
  children,
  className = "",
  padded = true,
}: PropsWithChildren<{ className?: string; padded?: boolean }>) {
  return <section className={`panel ${padded ? "panel-padded" : ""} ${className}`}>{children}</section>;
}

export function PageHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="page-header-action">{action}</div>}
    </header>
  );
}

export function StatusPill({ value }: { value: string }) {
  return <span className={`status-pill status-${statusTone(value)}`}>{humanize(value)}</span>;
}

export function LoadingState({ label = "Loading secure data" }: { label?: string }) {
  return (
    <div className="state-card" role="status">
      <LoaderCircle className="spin" size={22} />
      <span>{label}</span>
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const message = error instanceof Error ? error.message : "Something went wrong.";
  return (
    <div className="state-card state-error" role="alert">
      <CircleAlert size={22} />
      <div>
        <strong>We could not load this section</strong>
        <p>{message}</p>
      </div>
      {onRetry && <Button variant="secondary" onClick={onRetry}>Try again</Button>}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon"><Inbox size={21} /></span>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  );
}

export function Modal({
  open,
  title,
  description,
  children,
  onClose,
}: PropsWithChildren<{
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
}>) {
  if (!open) return null;
  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section className="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title" onMouseDown={(event) => event.stopPropagation()}>
        <div className="modal-heading">
          <div>
            <h2 id="modal-title">{title}</h2>
            {description && <p>{description}</p>}
          </div>
          <button className="icon-button" aria-label="Close dialog" onClick={onClose}><X size={20} /></button>
        </div>
        {children}
      </section>
    </div>
  );
}

interface ToastMessage {
  id: string;
  title: string;
  message?: string;
  tone: "success" | "error" | "info";
}

interface ToastContextValue {
  success: (title: string, message?: string) => void;
  error: (title: string, error?: unknown) => void;
  info: (title: string, message?: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: PropsWithChildren) {
  const [messages, setMessages] = useState<ToastMessage[]>([]);
  const push = useCallback((message: Omit<ToastMessage, "id">) => {
    const id = crypto.randomUUID();
    setMessages((current) => [...current, { ...message, id }]);
    window.setTimeout(() => setMessages((current) => current.filter((item) => item.id !== id)), 4500);
  }, []);
  const value = useMemo<ToastContextValue>(() => ({
    success: (title, message) => push({ title, message, tone: "success" }),
    info: (title, message) => push({ title, message, tone: "info" }),
    error: (title, error) => push({
      title,
      message: error instanceof ApiError ? `${error.message} (${error.code})` : error instanceof Error ? error.message : undefined,
      tone: "error",
    }),
  }), [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-region" aria-live="polite">
        {messages.map((message) => (
          <div className={`toast toast-${message.tone}`} key={message.id}>
            {message.tone === "success" ? <Check size={18} /> : message.tone === "error" ? <CircleAlert size={18} /> : <ShieldCheck size={18} />}
            <div><strong>{message.title}</strong>{message.message && <p>{message.message}</p>}</div>
            <button aria-label="Dismiss" onClick={() => setMessages((current) => current.filter((item) => item.id !== message.id))}><X size={16} /></button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const value = useContext(ToastContext);
  if (!value) throw new Error("useToast must be used within ToastProvider");
  return value;
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const toast = useToast();
  return (
    <button className="copy-button" onClick={async () => {
      await navigator.clipboard.writeText(value);
      toast.success("Copied", value);
    }}>
      <Clipboard size={14} /> {label}
    </button>
  );
}
