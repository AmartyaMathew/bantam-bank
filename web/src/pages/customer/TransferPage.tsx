import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, CheckCircle2, CircleAlert, KeyRound, LockKeyhole, SendHorizontal, ShieldCheck } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { api } from "../../api";
import { Button, ErrorState, LoadingState, Modal, PageHeader, Panel, StatusPill, useToast } from "../../components/ui";
import type { SCAChallenge, Transaction, TransferInput } from "../../types";
import { formatDate, formatMoney, parseMoney, shortId } from "../../utils";

const BOB_ACCOUNT = "30000000-0000-0000-0000-000000000003";

interface PendingTransfer {
  input: TransferInput;
  challenge: SCAChallenge;
  key: string;
}

export function TransferPage() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const accountsQuery = useQuery({ queryKey: ["accounts"], queryFn: api.accounts });
  const [source, setSource] = useState("");
  const [destination, setDestination] = useState(BOB_ACCOUNT);
  const [amount, setAmount] = useState("25.00");
  const [description, setDescription] = useState("Dinner split");
  const [submitting, setSubmitting] = useState(false);
  const [pending, setPending] = useState<PendingTransfer | null>(null);
  const [scaCode, setScaCode] = useState("");
  const [receipt, setReceipt] = useState<Transaction | null>(null);
  const idempotencyKey = useRef<string | null>(null);
  const accounts = accountsQuery.data?.accounts ?? [];
  const activeAccounts = useMemo(() => accounts.filter((account) => account.status === "ACTIVE"), [accounts]);
  const selectedSource = source || activeAccounts[0]?.account_id || "";

  const completeTransfer = async (input: TransferInput, key: string) => {
    setSubmitting(true);
    try {
      const transaction = await api.createTransfer(input, key);
      setReceipt(transaction);
      setPending(null);
      setScaCode("");
      idempotencyKey.current = null;
      await queryClient.invalidateQueries({ queryKey: ["accounts"] });
      await queryClient.invalidateQueries({ queryKey: ["transactions"] });
      await queryClient.invalidateQueries({ queryKey: ["notifications"] });
      toast.success("Transfer posted", `${formatMoney(transaction.amount_minor)} sent successfully.`);
    } catch (error) {
      toast.error("Transfer failed", error);
    } finally {
      setSubmitting(false);
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const amountMinor = parseMoney(amount);
    if (!selectedSource || !destination || amountMinor <= 0) {
      toast.error("Check transfer details", new Error("Choose a source, destination and positive amount."));
      return;
    }
    if (selectedSource === destination) {
      toast.error("Accounts must differ", new Error("Choose a destination other than the source account."));
      return;
    }
    setSubmitting(true);
    const key = idempotencyKey.current ?? crypto.randomUUID();
    idempotencyKey.current = key;
    const input: TransferInput = {
      source_account_id: selectedSource,
      destination_account_id: destination.trim(),
      amount_minor: amountMinor,
      currency: "GBP",
      description: description.trim(),
    };
    try {
      const challenge = await api.createSCAChallenge(selectedSource, input.destination_account_id, amountMinor);
      if (challenge.required) {
        setPending({ input, challenge, key });
        setScaCode(challenge.demo_code ?? "");
        setSubmitting(false);
      } else {
        await completeTransfer(input, key);
      }
    } catch (error) {
      toast.error("Could not prepare transfer", error);
      setSubmitting(false);
    }
  };

  if (accountsQuery.isLoading) return <LoadingState label="Preparing secure transfer" />;
  if (accountsQuery.error) return <ErrorState error={accountsQuery.error} onRetry={() => accountsQuery.refetch()} />;

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Payments" title="Send money" description="Transfers post atomically to both accounts and are protected against duplicate submission." />
      <div className="transfer-layout">
        <Panel className="transfer-form-panel">
          <form className="transfer-form" onSubmit={submit}>
            <div className="form-section-heading"><span>1</span><div><h2>Transfer details</h2><p>Choose the source and destination accounts.</p></div></div>
            <label>From account<select value={selectedSource} onChange={(event) => setSource(event.target.value)} required>{activeAccounts.map((account) => <option value={account.account_id} key={account.account_id}>{account.account_reference} · {formatMoney(account.balance_minor)}</option>)}</select></label>
            <label>Destination account ID<input value={destination} onChange={(event) => setDestination(event.target.value)} required spellCheck={false} /><small>Demo Bob account: <button type="button" className="inline-link" onClick={() => setDestination(BOB_ACCOUNT)}>use seeded destination</button></small></label>
            <div className="field-row"><label>Amount<div className="money-input"><span>£</span><input inputMode="decimal" value={amount} onChange={(event) => setAmount(event.target.value)} required /></div></label><label>Currency<select value="GBP" disabled><option>GBP</option></select></label></div>
            <label>Description<input value={description} onChange={(event) => setDescription(event.target.value)} maxLength={140} placeholder="What is this for?" /></label>
            <div className="transfer-review"><div><span>Amount to send</span><strong>{formatMoney(parseMoney(amount))}</strong></div><div><span>Available balance</span><strong>{formatMoney(activeAccounts.find((account) => account.account_id === selectedSource)?.balance_minor ?? 0)}</strong></div></div>
            <Button type="submit" disabled={submitting || activeAccounts.length === 0}>{submitting ? "Securing transfer…" : <>Review and send <ArrowRight size={17} /></>}</Button>
          </form>
        </Panel>

        <aside className="transfer-aside">
          <Panel><span className="feature-icon"><ShieldCheck size={20} /></span><h3>Transaction-bound security</h3><p>High-value transfers require a one-time code bound to the payer, payee and exact amount.</p></Panel>
          <Panel><span className="feature-icon warm"><KeyRound size={20} /></span><h3>Safe retries</h3><p>A unique idempotency key prevents accidental double posting if the network retries your request.</p></Panel>
          <div className="demo-threshold"><CircleAlert size={18} /><div><strong>SCA demo threshold</strong><span>Transfers of £5,000.00 or more require a challenge.</span></div></div>
        </aside>
      </div>

      <Modal open={Boolean(pending)} title="Confirm this transfer" description="Strong customer authentication is required for this amount." onClose={() => !submitting && setPending(null)}>
        {pending && <form className="sca-form" onSubmit={(event) => { event.preventDefault(); void completeTransfer({ ...pending.input, sca_challenge_id: pending.challenge.challenge_id, sca_code: scaCode }, pending.key); }}><div className="sca-shield"><LockKeyhole size={28} /></div><div className="sca-summary"><div><span>Amount</span><strong>{formatMoney(pending.input.amount_minor)}</strong></div><div><span>Destination</span><code>{shortId(pending.input.destination_account_id)}</code></div><div><span>Expires</span><strong>{formatDate(pending.challenge.expires_at, true)}</strong></div></div>{pending.challenge.demo_code && <div className="demo-code"><span>Demo verification code</span><strong>{pending.challenge.demo_code}</strong><small>In production this would arrive through a separate trusted channel.</small></div>}<label>Six-digit verification code<input inputMode="numeric" pattern="[0-9]{6}" maxLength={6} value={scaCode} onChange={(event) => setScaCode(event.target.value.replace(/\D/g, ""))} required autoFocus /></label><div className="modal-actions"><Button type="button" variant="secondary" onClick={() => setPending(null)} disabled={submitting}>Cancel</Button><Button type="submit" disabled={submitting || scaCode.length !== 6}>{submitting ? "Posting…" : "Confirm transfer"}</Button></div></form>}
      </Modal>

      <Modal open={Boolean(receipt)} title="Transfer complete" description="The balanced ledger transaction has been committed." onClose={() => setReceipt(null)}>
        {receipt && <div className="receipt"><CheckCircle2 className="receipt-check" size={42} /><strong className="receipt-amount">{formatMoney(receipt.amount_minor, receipt.currency)}</strong><span>{receipt.description}</span><div className="receipt-grid"><div><small>Status</small><StatusPill value={receipt.status} /></div><div><small>Transaction</small><code>{shortId(receipt.transaction_id)}</code></div><div><small>Posted</small><strong>{formatDate(receipt.posted_at ?? receipt.created_at, true)}</strong></div></div><Button onClick={() => setReceipt(null)}><SendHorizontal size={17} /> Make another transfer</Button></div>}
      </Modal>
    </div>
  );
}
