import { Check, Clock3, ShieldCheck, UserCheck, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../../api";
import {
  Button,
  EmptyState,
  LoadingState,
  PageHeader,
  Panel,
  StatusPill,
} from "../../components/ui";
import type { AspisAuditorRequest } from "../../types";

export function AspisAuditorsPage() {
  const [requests, setRequests] = useState<AspisAuditorRequest[] | null>(null);
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [working, setWorking] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    const result = await api.aspisAuditorRequests();
    setRequests(result.requests);
  }, []);

  useEffect(() => {
    void load().catch((caught) => {
      setError(
        caught instanceof Error ? caught.message : "Approval queue failed.",
      );
    });
  }, [load]);

  const decide = async (
    request: AspisAuditorRequest,
    decision: "APPROVE" | "REJECT",
  ) => {
    setWorking(request.request_id);
    setError("");
    try {
      await api.decideAspisAuditorRequest(
        request.request_id,
        decision,
        reasons[request.request_id] ?? "",
      );
      await load();
    } catch (caught) {
      if (caught instanceof ApiError && caught.code === "MFA_STEP_UP_REQUIRED") {
        setError(
          "Your MFA verification is older than five minutes. Sign out and sign "
          + "in again before deciding this request.",
        );
      } else {
        setError(
          caught instanceof Error ? caught.message : "The decision was not saved.",
        );
      }
    } finally {
      setWorking("");
    }
  };

  if (!requests) return <LoadingState label="Loading auditor requests" />;
  const pending = requests.filter((request) => request.status === "PENDING");
  const decided = requests.filter((request) => request.status !== "PENDING");

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Aspis access"
        title="Auditor approvals"
        description="Applicants receive no assurance access until an MFA-authenticated administrator approves them."
      />

      {pending.length === 0 ? (
        <Panel>
          <EmptyState
            title="No requests awaiting review"
            description="New Aspis auditor signups will appear here."
          />
        </Panel>
      ) : (
        <div className="approval-list">
          {pending.map((request) => (
            <Panel className="approval-card" key={request.request_id}>
              <div className="approval-identity">
                <span className="mfa-icon"><UserCheck size={21} /></span>
                <div>
                  <strong>{request.email}</strong>
                  <span>
                    <Clock3 size={14} />
                    Requested {new Date(request.requested_at).toLocaleString()}
                  </span>
                </div>
                <StatusPill value={request.status} />
              </div>
              <label>
                Decision note
                <textarea
                  maxLength={500}
                  value={reasons[request.request_id] ?? ""}
                  onChange={(event) => setReasons((current) => ({
                    ...current,
                    [request.request_id]: event.target.value,
                  }))}
                  placeholder="Optional for approval; required for rejection"
                />
              </label>
              <div className="approval-actions">
                <Button
                  type="button"
                  disabled={working === request.request_id}
                  onClick={() => void decide(request, "APPROVE")}
                >
                  <Check size={17} /> Approve auditor
                </Button>
                <Button
                  type="button"
                  variant="danger"
                  disabled={
                    working === request.request_id
                    || !(reasons[request.request_id] ?? "").trim()
                  }
                  onClick={() => void decide(request, "REJECT")}
                >
                  <X size={17} /> Reject
                </Button>
              </div>
            </Panel>
          ))}
        </div>
      )}

      {decided.length > 0 && (
        <Panel>
          <div className="section-heading">
            <div>
              <p className="eyebrow">Decision history</p>
              <h2>Recently reviewed</h2>
            </div>
            <ShieldCheck size={22} />
          </div>
          <div className="approval-history">
            {decided.map((request) => (
              <div className="approval-history-row" key={request.request_id}>
                <div>
                  <strong>{request.email}</strong>
                  <span>{request.decision_reason || "No decision note"}</span>
                </div>
                <StatusPill value={request.status} />
              </div>
            ))}
          </div>
        </Panel>
      )}

      {error && <p className="form-error" role="alert">{error}</p>}
    </div>
  );
}
