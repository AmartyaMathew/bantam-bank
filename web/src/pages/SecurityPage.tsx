import { KeyRound, ShieldCheck, Smartphone, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { MfaChallengePanel } from "../components/MfaChallengePanel";
import { Button, LoadingState, PageHeader, Panel } from "../components/ui";
import type { MfaFlow, MfaMethod, MfaState } from "../types";

export function SecurityPage() {
  const { user, acceptSession, refreshUser } = useAuth();
  const [state, setState] = useState<MfaState | null>(null);
  const [flow, setFlow] = useState<MfaFlow | null>(null);
  const [method, setMethod] = useState<MfaMethod>("passkey");
  const [label, setLabel] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setState(await api.mfaState());
  }, []);

  useEffect(() => {
    void load().catch((caught) => {
      setError(caught instanceof Error ? caught.message : "MFA settings failed.");
    });
  }, [load]);

  const begin = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      setFlow(await api.beginMfaEnrollment(password, method, label));
      setPassword("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "MFA setup failed.");
    } finally {
      setSubmitting(false);
    }
  };

  const removePasskey = async (credentialId: string) => {
    setError("");
    try {
      await api.removePasskey(credentialId);
      await Promise.all([load(), refreshUser()]);
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : "The passkey was not removed.",
      );
    }
  };

  const removeTotp = async () => {
    setError("");
    try {
      await api.removeTotp();
      await Promise.all([load(), refreshUser()]);
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : "The authenticator app was not removed.",
      );
    }
  };

  if (!state) return <LoadingState label="Loading MFA settings" />;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Account security"
        title="Multi-factor authentication"
        description={
          state.required
            ? "MFA is mandatory for administrators. Keep at least one factor enrolled."
            : "MFA is optional for Aspis auditors. Enrolling a factor makes it required on future sign-ins."
        }
      />

      <Panel className="mfa-summary">
        <span className="mfa-icon"><ShieldCheck size={22} /></span>
        <div>
          <strong>{state.enabled ? "MFA enabled" : "MFA not enabled"}</strong>
          <p>
            Passkeys are phishing-resistant and preferred. Authenticator-app
            codes are available as a fallback.
          </p>
        </div>
      </Panel>

      {flow ? (
        <Panel>
          <MfaChallengePanel
            flow={flow}
            onSession={async (session) => {
              await acceptSession(session);
              setFlow(null);
              await load();
            }}
            onCancel={() => setFlow(null)}
          />
        </Panel>
      ) : (
        <Panel>
          <h2>Add a factor</h2>
          <form className="mfa-enrollment-form" onSubmit={begin}>
            <label>
              Factor type
              <select
                value={method}
                onChange={(event) => setMethod(event.target.value as MfaMethod)}
              >
                <option value="passkey" disabled={!state.passkeys_available}>
                  Passkey{state.passkeys_available ? "" : " (not configured here)"}
                </option>
                <option value="totp">Authenticator app</option>
              </select>
            </label>
            <label>
              Label
              <input
                value={label}
                maxLength={80}
                onChange={(event) => setLabel(event.target.value)}
                placeholder={
                  method === "passkey" ? "Work laptop" : "Authenticator app"
                }
              />
            </label>
            <label>
              Confirm your password
              <input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </label>
            <Button
              type="submit"
              disabled={
                submitting || !password
                || (method === "passkey" && !state.passkeys_available)
              }
            >
              {method === "passkey"
                ? <><KeyRound size={17} /> Add passkey</>
                : <><Smartphone size={17} /> Add authenticator app</>}
            </Button>
          </form>
        </Panel>
      )}

      <div className="mfa-factor-grid">
        <Panel>
          <h2>Passkeys</h2>
          {state.passkeys.length === 0 ? (
            <p className="muted-copy">No passkeys enrolled.</p>
          ) : state.passkeys.map((passkey) => (
            <div className="mfa-factor" key={passkey.webauthn_credential_id}>
              <KeyRound size={19} />
              <div>
                <strong>{passkey.label}</strong>
                <span>
                  Added {new Date(passkey.created_at).toLocaleDateString()}
                  {passkey.backed_up ? " · synced" : ""}
                </span>
              </div>
              <Button
                type="button"
                variant="ghost"
                aria-label={`Remove ${passkey.label}`}
                onClick={() => void removePasskey(passkey.webauthn_credential_id)}
              >
                <Trash2 size={16} />
              </Button>
            </div>
          ))}
        </Panel>

        <Panel>
          <h2>Authenticator app</h2>
          {state.totp ? (
            <div className="mfa-factor">
              <Smartphone size={19} />
              <div>
                <strong>{state.totp.label}</strong>
                <span>
                  Added {new Date(state.totp.confirmed_at).toLocaleDateString()}
                </span>
              </div>
              <Button
                type="button"
                variant="ghost"
                aria-label="Remove authenticator app"
                onClick={() => void removeTotp()}
              >
                <Trash2 size={16} />
              </Button>
            </div>
          ) : (
            <p className="muted-copy">No authenticator app enrolled.</p>
          )}
        </Panel>
      </div>

      {error && <p className="form-error" role="alert">{error}</p>}
      {user?.role === "ASPIS_AUDITOR" && !state.enabled && (
        <p className="security-note">
          Your auditor account will continue using password-only sign-in until
          you add a factor.
        </p>
      )}
    </div>
  );
}
