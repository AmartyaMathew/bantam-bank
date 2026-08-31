import type {
  Account,
  AdminPermissionScope,
  AdminUser,
  AdminUserCreateInput,
  AccountStatusClaim,
  AsvsAiExecution,
  AsvsAiGeneration,
  AsvsOverview,
  AsvsRun,
  AspisAuditorRegisterInput,
  AspisAuditorRequest,
  AttackRemediationPlan,
  AttackScenarioOverview,
  AttackScenarioRequest,
  AttackScenarioSet,
  AttackSimulation,
  AttackSimulationRequest,
  AuditEvent,
  CompanyFinancialProfile,
  CompanyFinancialsOverview,
  CompanyFinancialsVersion,
  Customer,
  LoginResponse,
  LoginResult,
  MfaEnrollmentSetup,
  MfaMethod,
  MfaState,
  Notification,
  ReconciliationRun,
  RepositoryGraphSourceRequest,
  RepositoryGraphSources,
  RegisterInput,
  RegisterResponse,
  RiskAlert,
  SCAChallenge,
  Transaction,
  TransferInput,
  UserProfile,
  WorkflowDraft,
  WorkflowGraphOverview,
  WorkflowValidation,
} from "./types";

const API_BASE = "/api";
const SESSION_KEY = "bantam.session";

// Only non-secret session metadata and the CSRF nonce are persisted. The JWT is
// held by the browser in an HttpOnly cookie and cannot be read by application JS.
export interface StoredSession {
  expires_at: string;
  role: LoginResponse["role"];
  csrf_token: string;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function loadSession(): StoredSession | null {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const session = JSON.parse(raw) as StoredSession;
    if (new Date(session.expires_at).getTime() <= Date.now()) {
      sessionStorage.removeItem(SESSION_KEY);
      return null;
    }
    return session;
  } catch {
    sessionStorage.removeItem(SESSION_KEY);
    return null;
  }
}

export function saveSession(session: LoginResponse | StoredSession | null): void {
  if (session) {
    const stored: StoredSession = {
      expires_at: session.expires_at,
      role: session.role,
      csrf_token: session.csrf_token,
    };
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(stored));
  } else {
    sessionStorage.removeItem(SESSION_KEY);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const session = loadSession();
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  headers.set("X-Request-ID", crypto.randomUUID());
  if (init.body) headers.set("Content-Type", "application/json");
  if (session && !["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers.set("X-CSRF-Token", session.csrf_token);
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    credentials: "same-origin",
  });
  const payload = (await response.json().catch(() => null)) as
    | { error?: { code?: string; message?: string } }
    | T
    | null;

  if (!response.ok) {
    const errorPayload = payload as { error?: { code?: string; message?: string } } | null;
    if (response.status === 401 && session) window.dispatchEvent(new Event("bantam:unauthorized"));
    throw new ApiError(
      response.status,
      errorPayload?.error?.code ?? "REQUEST_FAILED",
      errorPayload?.error?.message ?? "The request could not be completed.",
    );
  }

  return payload as T;
}

const json = (value: unknown) => JSON.stringify(value);

export const api = {
  health: () => request<{ status: string; service: string }>("/healthz"),
  login: (email: string, password: string) =>
    request<LoginResult>("/v1/auth/login", {
      method: "POST",
      body: json({ email, password }),
    }),
  setupMfa: (transactionId: string, method: MfaMethod, label = "") =>
    request<MfaEnrollmentSetup>("/v1/auth/mfa/setup", {
      method: "POST",
      body: json({ transaction_id: transactionId, method, label }),
    }),
  completePasskeyMfa: (
    transactionId: string,
    credential: Record<string, unknown>,
  ) =>
    request<LoginResponse>("/v1/auth/mfa/passkey", {
      method: "POST",
      body: json({ transaction_id: transactionId, credential }),
    }),
  completeTotpMfa: (transactionId: string, code: string) =>
    request<LoginResponse>("/v1/auth/mfa/totp", {
      method: "POST",
      body: json({ transaction_id: transactionId, code }),
    }),
  logout: () => request<{ status: string }>("/v1/auth/logout", { method: "POST" }),
  register: (input: RegisterInput) =>
    request<RegisterResponse>("/v1/auth/register", {
      method: "POST",
      body: json(input),
    }),
  registerAspisAuditor: (input: AspisAuditorRegisterInput) =>
    request<RegisterResponse>("/v1/auth/register/aspis-auditor", {
      method: "POST",
      body: json(input),
    }),
  me: () => request<UserProfile>("/v1/me"),
  mfaState: () => request<MfaState>("/v1/me/mfa"),
  beginMfaEnrollment: (
    password: string,
    method: MfaMethod,
    label: string,
  ) =>
    request<MfaEnrollmentSetup>("/v1/me/mfa/enrollment", {
      method: "POST",
      body: json({ password, method, label }),
    }),
  removePasskey: (credentialId: string) =>
    request<{ status: string }>(`/v1/me/mfa/passkeys/${credentialId}`, {
      method: "DELETE",
    }),
  removeTotp: () =>
    request<{ status: string }>("/v1/me/mfa/totp", { method: "DELETE" }),
  submitKYC: () => request<{ kyc_status: string }>("/v1/me/kyc/submit", { method: "POST" }),

  accounts: () => request<{ accounts: Account[] }>("/v1/accounts"),
  openAccount: () => request<Account>("/v1/accounts", { method: "POST", body: json({ currency: "GBP" }) }),
  accountTransactions: (accountId: string) =>
    request<{ transactions: Transaction[] }>(`/v1/accounts/${accountId}/transactions?limit=100`),
  notifications: () => request<{ notifications: Notification[] }>("/v1/notifications?limit=100"),
  issueAccountClaim: () =>
    request<AccountStatusClaim>("/v1/claims/account-status", { method: "POST" }),
  createSCAChallenge: (sourceAccountId: string, destinationAccountId: string, amountMinor: number) =>
    request<SCAChallenge>("/v1/sca/challenges", {
      method: "POST",
      body: json({
        source_account_id: sourceAccountId,
        destination_account_id: destinationAccountId,
        amount_minor: amountMinor,
      }),
    }),
  createTransfer: (input: TransferInput, idempotencyKey: string) =>
    request<Transaction>("/v1/transfers", {
      method: "POST",
      headers: { "Idempotency-Key": idempotencyKey },
      body: json(input),
    }),

  aspisAuditorRequests: () =>
    request<{ requests: AspisAuditorRequest[] }>(
      "/v1/admin/aspis-auditor-requests?limit=250",
    ),
  decideAspisAuditorRequest: (
    requestId: string,
    decision: "APPROVE" | "REJECT",
    reason: string,
  ) =>
    request<{ request_id: string; status: string; email: string }>(
      `/v1/admin/aspis-auditor-requests/${requestId}/decision`,
      {
        method: "POST",
        body: json({ decision, reason }),
      },
    ),
  customers: () => request<{ customers: Customer[] }>("/v1/admin/customers?limit=250"),
  adminUsers: () =>
    request<{
      users: AdminUser[];
      available_permissions: AdminPermissionScope[];
    }>("/v1/admin/users?limit=250"),
  createAdminUser: (input: AdminUserCreateInput) =>
    request<AdminUser>("/v1/admin/users", {
      method: "POST",
      body: json(input),
    }),
  decideKYC: (customerId: string, decision: "APPROVE" | "REJECT", reason: string) =>
    request<{ kyc_status: string }>(`/v1/admin/customers/${customerId}/kyc`, {
      method: "PATCH",
      body: json({ decision, reason }),
    }),
  operatorTransactions: (minimumMinor = 0) =>
    request<{ transactions: Transaction[] }>(
      `/v1/admin/transactions?limit=250&min_amount_minor=${minimumMinor}`,
    ),
  setAccountStatus: (accountId: string, status: "ACTIVE" | "FROZEN", reason: string) =>
    request<{ status: string }>(`/v1/admin/accounts/${accountId}/status`, {
      method: "PATCH",
      body: json({ status, reason }),
    }),
  demoDeposit: (accountId: string, amountMinor: number, description: string, key: string) =>
    request<Transaction>(`/v1/admin/accounts/${accountId}/demo-deposit`, {
      method: "POST",
      headers: { "Idempotency-Key": key },
      body: json({ amount_minor: amountMinor, currency: "GBP", description }),
    }),
  reverseTransaction: (transactionId: string, reason: string, key: string) =>
    request<Transaction>(`/v1/admin/transactions/${transactionId}/reverse`, {
      method: "POST",
      headers: { "Idempotency-Key": key },
      body: json({ reason }),
    }),

  riskAlerts: (status: "OPEN" | "REVIEWED" | "DISMISSED" = "OPEN") =>
    request<{ alerts: RiskAlert[] }>(`/v1/risk/alerts?status=${status}&limit=250`),
  createRiskAlert: (transactionId: string, severity: RiskAlert["severity"], explanation: string) =>
    request<{ risk_alert_id: string; status: string }>("/v1/risk/alerts", {
      method: "POST",
      body: json({ transaction_id: transactionId, severity, explanation }),
    }),
  reviewRiskAlert: (alertId: string, status: "REVIEWED" | "DISMISSED", note: string) =>
    request<{ status: string }>(`/v1/risk/alerts/${alertId}`, {
      method: "PATCH",
      body: json({ status, note }),
    }),
  auditEvents: () => request<{ events: AuditEvent[] }>("/v1/audit/events?limit=300"),
  asvsOverview: () => request<AsvsOverview>("/v1/admin/asvs?limit=10"),
  runAsvs: () =>
    request<AsvsRun>("/v1/admin/asvs/runs", { method: "POST" }),
  generateAsvsTestPlan: () =>
    request<AsvsAiGeneration>("/v1/admin/asvs/test-plans", { method: "POST" }),
  executeAsvsTestPlan: (generationId: string) =>
    request<AsvsAiExecution>(
      `/v1/admin/asvs/test-plans/${generationId}/execute`,
      { method: "POST" },
    ),
  runReconciliation: () =>
    request<ReconciliationRun>("/v1/reconciliation/runs", { method: "POST" }),
  workflowGraph: () =>
    request<WorkflowGraphOverview>("/v1/admin/workflow-graph"),
  validateWorkflow: (input: WorkflowDraft) =>
    request<WorkflowValidation>("/v1/admin/workflows/validate", {
      method: "POST",
      body: json(input),
    }),
  createWorkflow: (input: WorkflowDraft) =>
    request<WorkflowGraphOverview["custom_flows"][number]>("/v1/admin/workflows", {
      method: "POST",
      body: json(input),
    }),
  repositoryGraphSources: () =>
    request<RepositoryGraphSources>("/v1/admin/repository-graphs"),
  generateRepositoryGraph: (input: RepositoryGraphSourceRequest) =>
    request<WorkflowGraphOverview>("/v1/admin/repository-graphs", {
      method: "POST",
      body: json(input),
    }),
  repositoryGraph: (snapshotId: string) =>
    request<WorkflowGraphOverview>(`/v1/admin/repository-graphs/${snapshotId}`),
  validateRepositoryWorkflow: (snapshotId: string, input: WorkflowDraft) =>
    request<WorkflowValidation>(
      `/v1/admin/repository-graphs/${snapshotId}/workflows/validate`,
      { method: "POST", body: json(input) },
    ),
  createRepositoryWorkflow: (snapshotId: string, input: WorkflowDraft) =>
    request<WorkflowGraphOverview["custom_flows"][number]>(
      `/v1/admin/repository-graphs/${snapshotId}/workflows`,
      { method: "POST", body: json(input) },
    ),

  companyFinancials: () =>
    request<CompanyFinancialsOverview>("/v1/admin/company-financials"),
  updateCompanyFinancials: (profile: CompanyFinancialProfile, changeNote: string) =>
    request<CompanyFinancialsVersion>("/v1/admin/company-financials", {
      method: "POST",
      body: json({ profile, change_note: changeNote }),
    }),
  attackScenarioOverview: () =>
    request<AttackScenarioOverview>("/v1/admin/attack-scenarios"),
  generateAttackScenarios: (input: AttackScenarioRequest) =>
    request<AttackScenarioSet>("/v1/admin/attack-scenarios", {
      method: "POST",
      body: json(input),
    }),
  attackScenarioSet: (scenarioSetId: string) =>
    request<AttackScenarioSet>(`/v1/admin/attack-scenarios/${scenarioSetId}`),
  runAttackSimulation: (scenarioSetId: string, input: AttackSimulationRequest) =>
    request<AttackSimulation>(
      `/v1/admin/attack-scenarios/${scenarioSetId}/simulations`,
      { method: "POST", body: json(input) },
    ),
  generateAttackRemediations: (scenarioSetId: string, simulationId: string) =>
    request<AttackRemediationPlan>(
      `/v1/admin/attack-scenarios/${scenarioSetId}/simulations/${simulationId}/remediations`,
      { method: "POST" },
    ),
};
