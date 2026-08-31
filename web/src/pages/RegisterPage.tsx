import {
  ArrowLeft,
  ArrowRight,
  BadgePoundSterling,
  ShieldCheck,
  UserPlus,
} from "lucide-react";
import { useState } from "react";
import type { FormEvent } from "react";
import { Link, Navigate } from "react-router";
import { api } from "../api";
import { useAuth } from "../auth";
import { Button } from "../components/ui";

type RegistrationKind = "CUSTOMER" | "ASPIS_AUDITOR";

export function RegisterPage() {
  const { session } = useAuth();
  const [kind, setKind] = useState<RegistrationKind>("CUSTOMER");
  const [form, setForm] = useState({
    legal_name: "",
    date_of_birth: "",
    email: "",
    phone: "",
    password: "",
  });
  const [error, setError] = useState("");
  const [accepted, setAccepted] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  if (session) return <Navigate to="/" replace />;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      if (kind === "ASPIS_AUDITOR") {
        await api.registerAspisAuditor({
          email: form.email,
          password: form.password,
        });
      } else {
        await api.register(form);
      }
      setAccepted(true);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Registration failed.");
    } finally {
      setSubmitting(false);
    }
  };

  const update = (key: keyof typeof form, value: string) =>
    setForm((current) => ({ ...current, [key]: value }));

  if (accepted) {
    return (
      <main className="register-page">
        <section className="register-card">
          <div className="register-brand">
            <div className="brand">
              <span className="brand-mark"><BadgePoundSterling /></span>
              <span>Bantam</span>
            </div>
            <span className="demo-tag"><ShieldCheck size={14} /> REQUEST ACCEPTED</span>
          </div>
          <div className="register-heading">
            <span className="feature-icon"><ShieldCheck size={21} /></span>
            <p className="eyebrow">Privacy-preserving onboarding</p>
            <h1>
              {kind === "ASPIS_AUDITOR"
                ? "Request awaiting review"
                : "Continue to sign in"}
            </h1>
            <p>
              {kind === "ASPIS_AUDITOR"
                ? "If eligible, an MFA-authenticated administrator must approve the request before the Aspis workspace becomes available."
                : "If the address was eligible, the requested synthetic workspace is ready. Bantam deliberately gives the same response for existing addresses."}
            </p>
          </div>
          <Link className="button button-primary" to="/login">
            Continue to sign in <ArrowRight size={17} />
          </Link>
        </section>
      </main>
    );
  }

  const auditor = kind === "ASPIS_AUDITOR";
  return (
    <main className="register-page">
      <section className="register-card">
        <div className="register-brand">
          <div className="brand">
            <span className="brand-mark"><BadgePoundSterling /></span>
            <span>Bantam</span>
          </div>
          <span className="demo-tag"><ShieldCheck size={14} /> SYNTHETIC IDENTITY</span>
        </div>
        <Link className="back-link" to="/login">
          <ArrowLeft size={16} /> Back to sign in
        </Link>
        <div className="register-heading">
          <span className="feature-icon"><UserPlus size={21} /></span>
          <p className="eyebrow">{auditor ? "Aspis trial" : "Customer onboarding"}</p>
          <h1>{auditor ? "Create an Aspis auditor" : "Create a Bantam profile"}</h1>
          <p>
            {auditor
              ? "Request access to ASVS evidence and bounded, source-grounded test plans. An administrator must approve the request first."
              : "Create a fictional customer record for exercising the KYC and account-opening workflow."}
          </p>
        </div>
        <form className="registration-form" onSubmit={submit}>
          <label>
            Workspace
            <select
              value={kind}
              onChange={(event) => setKind(event.target.value as RegistrationKind)}
            >
              <option value="CUSTOMER">Synthetic personal banking</option>
              <option value="ASPIS_AUDITOR">Aspis assurance auditor</option>
            </select>
            <small>
              Approved auditors can use only the ASVS workspace, have a
              server-enforced daily generation allowance, and may optionally add MFA.
            </small>
          </label>
          {!auditor && (
            <div className="field-row">
              <label>
                Legal name
                <input
                  value={form.legal_name}
                  onChange={(event) => update("legal_name", event.target.value)}
                  minLength={2}
                  required
                />
              </label>
              <label>
                Date of birth
                <input
                  type="date"
                  value={form.date_of_birth}
                  onChange={(event) => update("date_of_birth", event.target.value)}
                  required
                />
              </label>
            </div>
          )}
          <label>
            Email address
            <input
              type="email"
              value={form.email}
              onChange={(event) => update("email", event.target.value)}
              autoComplete="email"
              required
            />
          </label>
          {!auditor && (
            <label>
              Phone number <span className="optional">Optional</span>
              <input
                type="tel"
                value={form.phone}
                onChange={(event) => update("phone", event.target.value)}
              />
            </label>
          )}
          <label>
            Password
            <input
              type="password"
              value={form.password}
              onChange={(event) => update("password", event.target.value)}
              minLength={14}
              autoComplete="new-password"
              required
            />
            <small>At least 14 characters. Never reuse a real password in this demo.</small>
          </label>
          {error && <p className="form-error" role="alert">{error}</p>}
          <Button type="submit" disabled={submitting}>
            {submitting
              ? "Creating workspace…"
              : <>{auditor ? "Request auditor access" : "Create synthetic account"} <ArrowRight size={17} /></>}
          </Button>
        </form>
      </section>
    </main>
  );
}
