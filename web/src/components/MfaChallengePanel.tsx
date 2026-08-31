import { KeyRound, ShieldCheck, Smartphone } from "lucide-react";
import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { api } from "../api";
import type {
  LoginResponse,
  MfaFlow,
  MfaMethod,
} from "../types";
import { createPasskey, getPasskey } from "../webauthn";
import { Button, CopyButton } from "./ui";

export function MfaChallengePanel({
  flow,
  onSession,
  onCancel,
}: {
  flow: MfaFlow;
  onSession: (session: LoginResponse) => Promise<void>;
  onCancel: () => void;
}) {
  const [current, setCurrent] = useState<MfaFlow>(flow);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const passkeysSupported = typeof window.PublicKeyCredential !== "undefined";

  useEffect(() => {
    setCurrent(flow);
    setCode("");
    setError("");
  }, [flow]);

  const choose = async (method: MfaMethod) => {
    setError("");
    setSubmitting(true);
    try {
      setCurrent(await api.setupMfa(current.transaction_id, method));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "MFA setup failed.");
    } finally {
      setSubmitting(false);
    }
  };

  const usePasskey = async () => {
    const passkeyOptions = current.passkey_options;
    if (!passkeyOptions) return;
    setError("");
    setSubmitting(true);
    try {
      const credential = current.status === "mfa_enrollment_setup"
        ? await createPasskey(passkeyOptions)
        : await getPasskey(passkeyOptions);
      const session = await api.completePasskeyMfa(
        current.transaction_id,
        credential,
      );
      await onSession(session);
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : "Passkey verification failed.",
      );
    } finally {
      setSubmitting(false);
    }
  };

  const submitCode = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const session = await api.completeTotpMfa(current.transaction_id, code);
      await onSession(session);
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : "Authenticator verification failed.",
      );
    } finally {
      setSubmitting(false);
    }
  };

  const needsChoice = current.status === "mfa_enrollment_required";
  const passkeyReady = Boolean(current.passkey_options);
  const totpReady = current.status === "mfa_enrollment_setup"
    ? current.method === "totp"
    : current.methods.includes("totp");

  return (
    <section className="mfa-panel" aria-live="polite">
      <div className="mfa-heading">
        <span className="mfa-icon"><ShieldCheck size={22} /></span>
        <div>
          <p className="eyebrow">Multi-factor verification</p>
          <h3>
            {needsChoice
              ? "Protect this administrator account"
              : current.status === "mfa_enrollment_setup"
                ? "Finish setting up MFA"
                : "Verify it is you"}
          </h3>
          <p>
            {needsChoice
              ? "Administrators must enrol a passkey or authenticator app before continuing."
              : "Complete the factor linked to this account."}
          </p>
        </div>
      </div>

      {needsChoice && (
        <div className="mfa-methods">
          {current.methods.includes("passkey") && (
            <Button
              type="button"
              onClick={() => void choose("passkey")}
              disabled={submitting || !passkeysSupported}
            >
              <KeyRound size={17} /> Set up a passkey
            </Button>
          )}
          <Button
            type="button"
            variant="secondary"
            onClick={() => void choose("totp")}
            disabled={submitting}
          >
            <Smartphone size={17} /> Use an authenticator app
          </Button>
        </div>
      )}

      {passkeyReady && (
        <div className="mfa-method-card">
          <KeyRound size={21} />
          <div>
            <strong>
              {current.status === "mfa_enrollment_setup"
                ? "Create passkey"
                : "Use passkey"}
            </strong>
            <p>Your device will ask for its PIN, biometric, or security-key touch.</p>
          </div>
          <Button
            type="button"
            onClick={() => void usePasskey()}
            disabled={submitting || !passkeysSupported}
          >
            Continue
          </Button>
        </div>
      )}

      {current.status === "mfa_enrollment_setup"
        && current.method === "totp"
        && current.totp_secret && (
        <div className="totp-setup">
          <p>
            Add an account in your authenticator app using this setup key, then
            enter its six-digit code.
          </p>
          <div className="secret-value">
            <code>{current.totp_secret}</code>
            <CopyButton value={current.totp_secret} label="Copy key" />
          </div>
        </div>
      )}

      {totpReady && (
        <form className="mfa-code-form" onSubmit={submitCode}>
          <label>
            Authenticator code
            <input
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              value={code}
              onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))}
              placeholder="123456"
              required
            />
          </label>
          <Button type="submit" disabled={submitting || code.length !== 6}>
            <Smartphone size={17} /> Verify code
          </Button>
        </form>
      )}

      {!passkeysSupported
        && current.status !== "mfa_enrollment_setup"
        && current.methods.includes("passkey") && (
        <p className="form-error">
          This browser does not expose WebAuthn. Use an authenticator app instead.
        </p>
      )}
      {error && <p className="form-error" role="alert">{error}</p>}
      <Button type="button" variant="ghost" onClick={onCancel}>
        Cancel
      </Button>
    </section>
  );
}
