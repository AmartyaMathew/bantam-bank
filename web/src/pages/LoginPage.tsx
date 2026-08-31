import {
  ArrowRight,
  BadgePoundSterling,
  Building2,
  Eye,
  EyeOff,
  LockKeyhole,
  ShieldCheck,
  UserRound,
} from "lucide-react";
import { useState } from "react";
import type { FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router";
import { useAuth } from "../auth";
import { MfaChallengePanel } from "../components/MfaChallengePanel";
import { Button } from "../components/ui";
import type { MfaFlow } from "../types";

const developmentDemo = import.meta.env.DEV;

const demoUsers = developmentDemo ? [
  {
    label: "Alice",
    role: "Customer",
    email: "alice@bantam.local",
    icon: UserRound,
  },
  {
    label: "Admin",
    role: "Bank operations",
    email: "admin@bantam.local",
    icon: Building2,
  },
  {
    label: "Risk",
    role: "Risk analyst",
    email: "risk@bantam.local",
    icon: ShieldCheck,
  },
  {
    label: "Auditor",
    role: "Compliance",
    email: "auditor@bantam.local",
    icon: LockKeyhole,
  },
] as const : [];

const initialEmail = developmentDemo ? "alice@bantam.local" : "";
const initialPassword = developmentDemo ? "BantamDemo123!" : "";

export function LoginPage() {
  const { session, login, acceptSession } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState(initialEmail);
  const [password, setPassword] = useState(initialPassword);
  const [showPassword, setShowPassword] = useState(false);
  const [mfaFlow, setMfaFlow] = useState<MfaFlow | null>(null);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  if (session) return <Navigate to="/" replace />;

  const destination =
    (location.state as { from?: string } | null)?.from ?? "/";

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const result = await login(email, password);
      if ("csrf_token" in result) {
        navigate(destination, { replace: true });
      } else {
        setMfaFlow(result);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Sign in failed.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="login-page">
      <section className="login-story">
        <div className="brand brand-on-dark">
          <span className="brand-mark"><BadgePoundSterling /></span>
          <span>Bantam</span>
        </div>
        <div className="story-content">
          <p className="eyebrow eyebrow-light">Synthetic banking, real controls</p>
          <h1>Every pound accounted for. Every action explainable.</h1>
          <p>
            Bantam is a safe digital-bank laboratory for exploring immutable
            ledgers, strong customer authentication, risk events and audit evidence.
          </p>
          <div className="story-proof">
            <ShieldCheck size={22} />
            <div>
              <strong>Ledger-led by design</strong>
              <span>
                Balances are projections. Double-entry postings remain the source
                of truth.
              </span>
            </div>
          </div>
        </div>
        <div className="login-orbit orbit-one" />
        <div className="login-orbit orbit-two" />
      </section>

      <section className="login-form-side">
        <div className="demo-banner"><span>DEMO</span> Synthetic money only</div>
        <div className="login-card">
          <div className="login-heading">
            <p className="eyebrow">Secure access</p>
            <h2>Welcome to Bantam</h2>
            <p>
              {mfaFlow
                ? "Finish the second verification step."
                : developmentDemo
                  ? "Choose a demo profile or enter credentials."
                  : "Enter your credentials."}
            </p>
          </div>

          {mfaFlow ? (
            <MfaChallengePanel
              flow={mfaFlow}
              onSession={async (nextSession) => {
                await acceptSession(nextSession);
                navigate(destination, { replace: true });
              }}
              onCancel={() => {
                setMfaFlow(null);
                setPassword("");
              }}
            />
          ) : (
            <>
              {developmentDemo && (
                <div className="demo-profiles" aria-label="Demo profiles">
                  {demoUsers.map((demo) => {
                    const Icon = demo.icon;
                    return (
                      <button
                        className={
                          email === demo.email
                            ? "demo-profile active"
                            : "demo-profile"
                        }
                        key={demo.email}
                        onClick={() => {
                          setEmail(demo.email);
                          setPassword(initialPassword);
                        }}
                      >
                        <Icon size={18} />
                        <span><strong>{demo.label}</strong><small>{demo.role}</small></span>
                      </button>
                    );
                  })}
                </div>
              )}

              <form onSubmit={submit} className="auth-form">
                <label>
                  Email address
                  <input
                    type="email"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    autoComplete="username"
                    required
                  />
                </label>
                <label>
                  Password
                  <div className="password-field">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      autoComplete="current-password"
                      required
                    />
                    <button
                      type="button"
                      aria-label={showPassword ? "Hide password" : "Show password"}
                      onClick={() => setShowPassword((value) => !value)}
                    >
                      {showPassword
                        ? <EyeOff size={18} />
                        : <Eye size={18} />}
                    </button>
                  </div>
                </label>
                {error && <p className="form-error" role="alert">{error}</p>}
                <Button type="submit" disabled={submitting}>
                  {submitting
                    ? "Opening secure session…"
                    : <>Sign in <ArrowRight size={17} /></>}
                </Button>
              </form>
              <p className="security-note">
                <LockKeyhole size={14} /> The HttpOnly session expires after 15
                minutes in this demo.
              </p>
              <p className="register-link">
                New to Bantam?{" "}
                <Link to="/register">Create a synthetic account</Link>
              </p>
            </>
          )}
        </div>
      </section>
    </main>
  );
}
