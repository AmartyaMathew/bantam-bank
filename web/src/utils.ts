export function formatMoney(minor: number, currency = "GBP"): string {
  return new Intl.NumberFormat("en-GB", {
    style: "currency",
    currency,
    minimumFractionDigits: 2,
  }).format(minor / 100);
}

export function parseMoney(value: string): number {
  const normalized = value.replace(/[^0-9.]/g, "");
  const amount = Number.parseFloat(normalized);
  return Number.isFinite(amount) ? Math.round(amount * 100) : 0;
}

export function formatDate(value: string, includeTime = false): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    ...(includeTime ? { hour: "2-digit", minute: "2-digit" } : {}),
  }).format(date);
}

export function shortId(value: string): string {
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-5)}` : value;
}

export function humanize(value: string): string {
  return value
    .toLowerCase()
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function statusTone(value: string): "positive" | "warning" | "negative" | "neutral" {
  if (["ACTIVE", "POSTED", "PASS", "KYC_VERIFIED", "REVIEWED"].includes(value)) return "positive";
  if (["PENDING", "PENDING_KYC", "PENDING_REVIEW", "OPEN", "MEDIUM", "INCONCLUSIVE"].includes(value)) return "warning";
  if (["FAILED", "FAIL", "ERROR", "FROZEN", "CLOSED", "KYC_REJECTED", "CRITICAL", "HIGH"].includes(value)) {
    return "negative";
  }
  return "neutral";
}

/** Format a whole-pound planning figure. Financial assumptions are held in
 *  major units, unlike ledger amounts which are always minor units. */
export function formatGbp(value: number, fractionDigits = 0): string {
  return new Intl.NumberFormat("en-GB", {
    style: "currency",
    currency: "GBP",
    maximumFractionDigits: fractionDigits,
  }).format(value);
}

export function formatCompactGbp(value: number): string {
  if (Math.abs(value) >= 1_000_000) return `£${(value / 1_000_000).toFixed(1)}m`;
  if (Math.abs(value) >= 1_000) return `£${Math.round(value / 1_000)}k`;
  return formatGbp(value);
}

export function formatPercent(value: number, fractionDigits = 1): string {
  return new Intl.NumberFormat("en-GB", {
    style: "percent",
    minimumFractionDigits: fractionDigits,
    maximumFractionDigits: fractionDigits,
  }).format(value);
}
