export type Role =
  | "CUSTOMER"
  | "BANK_ADMIN"
  | "RISK_ANALYST"
  | "COMPLIANCE_AUDITOR"
  | "ASPIS_AUDITOR"
  | "ASPIS_ADMIN"
  | "PENDING_APPROVAL"
  | "SERVICE_ACCOUNT";

export type AdminPermissionScope =
  | "admin_users"
  | "customers"
  | "transactions"
  | "risk"
  | "audit"
  | "asvs"
  | "aspis_auditors"
  | "reconciliation"
  | "workflows"
  | "attack_lab"
  | "company_financials";

export interface LoginResponse {
  expires_at: string;
  role: Role;
  csrf_token: string;
}

export type MfaMethod = "passkey" | "totp";

export interface MfaChallenge {
  status: "mfa_required" | "mfa_enrollment_required";
  transaction_id: string;
  methods: MfaMethod[];
  passkey_options: Record<string, unknown> | null;
  expires_at: string;
}

export interface MfaEnrollmentSetup {
  status: "mfa_enrollment_setup";
  transaction_id: string;
  method: MfaMethod;
  passkey_options?: Record<string, unknown>;
  totp_secret?: string;
  totp_uri?: string;
  expires_at: string;
}

export type LoginResult = LoginResponse | MfaChallenge;
export type MfaFlow = MfaChallenge | MfaEnrollmentSetup;

export interface PasskeyFactor {
  webauthn_credential_id: string;
  label: string;
  device_type: string;
  backed_up: boolean;
  created_at: string;
  last_used_at: string | null;
}

export interface MfaState {
  required: boolean;
  enabled: boolean;
  passkeys_available: boolean;
  passkeys: PasskeyFactor[];
  totp: {
    label: string;
    confirmed_at: string;
    last_used_at: string | null;
  } | null;
}

export interface AspisAuditorRequest {
  request_id: string;
  email: string;
  status: "PENDING" | "APPROVED" | "REJECTED";
  requested_at: string;
  decided_at: string | null;
  decision_reason: string | null;
}

export interface RegisterInput {
  legal_name: string;
  date_of_birth: string;
  email: string;
  phone: string;
  password: string;
}

export interface AspisAuditorRegisterInput {
  email: string;
  password: string;
}

export interface RegisterResponse {
  status: "accepted";
  message: string;
}

export interface UserProfile {
  user_id: string;
  email: string;
  role: Role;
  status: string;
  mfa_enabled: boolean;
  admin_permissions: AdminPermissionScope[];
  is_super_admin: boolean;
  customer_id: string | null;
  legal_name: string | null;
  kyc_status: string | null;
  risk_rating: string | null;
  customer_status: string | null;
}

export interface AdminUser {
  user_id: string;
  email: string;
  role: "BANK_ADMIN";
  status: string;
  mfa_enabled: boolean;
  permissions: AdminPermissionScope[];
  is_super_admin: boolean;
  created_at: string;
}

export interface AdminUserCreateInput {
  email: string;
  password: string;
  permissions: AdminPermissionScope[];
}

export interface Account {
  account_id: string;
  customer_id?: string;
  account_reference: string;
  account_type: string;
  currency: string;
  status: string;
  balance_minor: number;
  opened_at: string;
}

export interface Transaction {
  transaction_id: string;
  idempotency_key: string;
  request_id: string;
  source_account_id: string;
  destination_account_id: string;
  amount_minor: number;
  currency: string;
  description: string;
  transaction_type: "TRANSFER" | "DEMO_DEPOSIT" | "REVERSAL";
  status: "PENDING" | "POSTED" | "FAILED" | "REVERSED";
  failure_reason?: string;
  created_at: string;
  posted_at?: string;
}

export interface Notification {
  notification_id: string;
  type: string;
  subject: string;
  body: string;
  created_at: string;
  read_at: string | null;
}

export interface SCAChallenge {
  challenge_id: string;
  expires_at: string;
  required: boolean;
  demo_code?: string;
}

export interface AccountStatusClaim {
  claim_id: string;
  issuer: string;
  subject_id: string;
  claim_type: string;
  has_active_account: boolean;
  kyc_status: string;
  valid_until: string;
  proof_format: string;
  proof_jwt: string;
}

export interface Customer {
  customer_id: string;
  legal_name: string;
  date_of_birth: string;
  email: string;
  phone: string | null;
  kyc_status: string;
  risk_rating: string;
  status: string;
  created_at: string;
}

export interface RiskAlert {
  risk_alert_id: string;
  transaction_id: string;
  customer_id: string | null;
  rule_id: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: "OPEN" | "REVIEWED" | "DISMISSED";
  explanation: string;
  created_at: string;
  reviewed_at: string | null;
  reviewed_by: string | null;
}

export interface AuditEvent {
  audit_event_id: string;
  actor_type: string;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  request_id: string;
  correlation_id: string;
  ip_address: string | null;
  user_agent: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface ReconciliationResult {
  account_id: string;
  projected_balance_minor: number;
  authoritative_balance_minor: number;
  matches: boolean;
}

export interface ReconciliationRun {
  status: "PASS" | "FAIL";
  accounts_checked: number;
  mismatches: number;
  results: ReconciliationResult[];
}

export type AsvsEvidenceStatus = "pass" | "fail" | "inconclusive" | "error";

export interface AsvsControl {
  control_id: string;
  title: string;
  framework_ids: string[];
  severity: "info" | "low" | "medium" | "high" | "critical";
  remediation: string;
}

export interface AsvsEvidenceRecord {
  control_id: string;
  title: string;
  framework: string;
  framework_ids: string[];
  target: string;
  status: AsvsEvidenceStatus;
  severity: AsvsControl["severity"];
  confidence: number;
  source_evidence: string[];
  execution_evidence: string[];
  counter_evidence: string[];
  remediation: string;
  limitations: string[];
  target_commit: string;
  generated_by: string;
  validated_by: string;
}

export interface AsvsRunSummary {
  run_id: string;
  status: "PASS" | "FAIL" | "INCONCLUSIVE" | "ERROR";
  catalog_version: string;
  target_commit: string;
  controls_total: number;
  controls_passed: number;
  controls_failed: number;
  controls_inconclusive: number;
  controls_error: number;
  evidence_sha256: string;
  duration_ms: number;
  started_at: string;
  completed_at: string;
  initiated_by: string;
}

export interface AsvsRun extends AsvsRunSummary {
  evidence: AsvsEvidenceRecord[];
}

export type AsvsAiGenerationStatus =
  | "PENDING"
  | "READY"
  | "EXECUTING"
  | "EXECUTED"
  | "FAILED";

export interface AsvsGeneratedTest {
  control_id: string;
  scenario_id: string;
  name: string;
  objective: string;
  grounding: string;
  source_refs: string[];
  terraform_refs: string[];
}

export interface AsvsSourceFile {
  repository: "application" | "terraform";
  path: string;
  sha256: string;
  source_bytes: number;
  included_bytes: number;
  truncated: boolean;
  excerpt: string;
}

export interface AsvsSourceContext {
  schema_version: "1.0";
  limits: {
    max_files: number;
    max_bytes: number;
    max_file_excerpt_bytes: number;
  };
  included_files: number;
  included_bytes: number;
  files: AsvsSourceFile[];
}

export interface AsvsAiProvenance {
  schema_version: "1.0";
  source_context: AsvsSourceContext;
  source_sha256: string;
  openapi_snapshot: Record<string, unknown>;
  openapi_sha256: string;
  model_request: {
    method: "POST";
    url: string;
    headers: Record<string, string>;
    body: Record<string, unknown>;
  };
  request_sha256: string;
  disclosure: string;
}

export interface AsvsGeneratedPlan {
  schema_version: "1.0";
  catalog_version: string;
  summary: string;
  rego_module: string;
  tests: AsvsGeneratedTest[];
}

export interface AsvsAiGeneration {
  generation_id: string;
  status: AsvsAiGenerationStatus;
  provider: string;
  model: string;
  catalog_version: string;
  target_commit: string;
  prompt_sha256: string;
  provenance: AsvsAiProvenance;
  plan_sha256: string | null;
  plan: AsvsGeneratedPlan | null;
  compiled_pytest: string | null;
  rego_sha256: string | null;
  provider_request_id: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  error_code: string | null;
  asvs_run_id: string | null;
  created_at: string;
  approved_at: string | null;
  executed_at: string | null;
}

export interface AsvsAiGeneratorOverview {
  enabled: boolean;
  feature_enabled: boolean;
  disabled_reason: string | null;
  provider: string;
  model: string;
  source_status: {
    ready: boolean;
    application: {
      ready: boolean;
      eligible_files: number;
    };
    terraform: {
      ready: boolean;
      eligible_files: number;
    };
  };
  limits: {
    per_session: number;
    per_account_per_day: number;
    per_day: number;
    max_tests: number;
    max_output_tokens: number;
    max_input_bytes: number;
    max_source_files: number;
    max_source_bytes: number;
    timeout_seconds: number;
    automatic_retries: number;
  };
  usage: {
    session: number;
    account_daily: number;
    daily: number;
    session_remaining: number;
    account_daily_remaining: number;
    daily_remaining: number;
  };
  latest_generation: AsvsAiGeneration | null;
}

export interface AsvsAiExecution {
  generation: AsvsAiGeneration;
  run: AsvsRun;
}

export interface AsvsOverview {
  catalog: {
    name: string;
    version: string;
    controls: AsvsControl[];
  };
  runner_enabled: boolean;
  cooldown_seconds: number;
  accepted_exceptions: number;
  ai_generator: AsvsAiGeneratorOverview;
  latest_run: AsvsRun | null;
  history: AsvsRunSummary[];
}

export interface TransferInput {
  source_account_id: string;
  destination_account_id: string;
  amount_minor: number;
  currency: string;
  description: string;
  sca_challenge_id?: string;
  sca_code?: string;
}

export type WorkflowNodeKind =
  | "route"
  | "function"
  | "check"
  | "transaction"
  | "query"
  | "lock"
  | "effect"
  | "constraint"
  | "documentation"
  | "parse_error"
  | "terraform_resource"
  | "terraform_data"
  | "terraform_module"
  | "terraform_variable"
  | "terraform_output"
  | "terraform_provider"
  | "terraform_local"
  | "terraform_block";

export interface WorkflowGraphNode {
  id: string;
  kind: WorkflowNodeKind;
  label: string;
  signature?: string;
  symbol?: string;
  function_symbol?: string;
  file?: string;
  line?: number;
  method?: string;
  path?: string;
  roles?: string[];
  condition?: string;
  failure_outcomes?: string[];
  operation?: string;
  tables?: string[];
  sql?: string;
  durable?: boolean;
  durability?: string;
  constraint?: string;
  database_function?: string;
  address?: string;
  block_type?: string;
  resource_type?: string;
  source?: string;
  description?: string;
  excerpt?: string;
  constraints?: Array<{
    node_id: string;
    name: string;
    database_function: string;
  }>;
}

export interface WorkflowGraphEdge {
  source: string;
  target: string;
  type:
    | "next"
    | "calls"
    | "handled_by"
    | "checks"
    | "contains"
    | "reads"
    | "writes"
    | "enforced_by"
    | "depends_on"
    | "documented_by";
  flow_ids?: string[];
}

export interface DefaultWorkflow {
  flow_id: string;
  name: string;
  description: string;
  actor_roles: string[];
  source: "generated";
  route: { method: string; path: string } | null;
  node_ids: string[];
  documentation_path: string | null;
  documentation: string | null;
}

export interface CustomWorkflow {
  workflow_id: string;
  name: string;
  description: string;
  actor_role: string;
  node_ids: string[];
  graph_digest: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  valid: boolean;
  stale: boolean;
  validation_errors: WorkflowValidationError[];
  documentation_path: null;
  documentation: string;
}

export interface WorkflowGraphOverview {
  version: number;
  generator: string;
  graph_digest: string;
  nodes: WorkflowGraphNode[];
  edges: WorkflowGraphEdge[];
  default_flows: DefaultWorkflow[];
  custom_flows: CustomWorkflow[];
  snapshot_id?: string;
  repository?: string;
  requested_ref?: string;
  root_path?: string;
  resolved_commit?: string;
  language?: "python" | "terraform" | "mixed";
  source_sha256?: string;
  model?: RepositoryGraphModelResult;
  created_by?: string;
  created_at?: string;
}

export interface RepositoryGraphSourceRequest {
  repository: string;
  ref: string;
  root_path: string;
  language: "auto" | "python" | "terraform";
  send_to_mistral: boolean;
}

export interface RepositoryGraphDefaultSource extends RepositoryGraphSourceRequest {
  source_id: string;
  name: string;
  private: boolean;
}

export interface RepositoryGraphSnapshotSummary {
  snapshot_id: string;
  repository: string;
  requested_ref: string;
  root_path: string;
  resolved_commit: string;
  language: "python" | "terraform" | "mixed";
  graph_digest: string;
  model_result: RepositoryGraphModelResult;
  created_by: string;
  created_at: string;
}

export interface RepositoryGraphSources {
  default_sources: RepositoryGraphDefaultSource[];
  github_token_configured: boolean;
  mistral_configured: boolean;
  recent_snapshots: RepositoryGraphSnapshotSummary[];
  limits: {
    max_code_files: number;
    max_source_bytes: number;
    max_graph_bytes: number;
    model_projection_bytes: number;
  };
}

export interface RepositoryGraphNarrative {
  schema_version: string;
  summary: string;
  architecture: Array<{
    name: string;
    explanation: string;
    node_ids: string[];
  }>;
  important_flows: Array<{
    flow_id: string;
    explanation: string;
  }>;
  reading_order: string[];
  limitations: string[];
  /** Optional only so immutable snapshots created before attack trees remain readable. */
  attack_tree?: RepositoryAttackTree;
}

export interface RepositoryAttackTreeNode {
  attack_node_id: string;
  title: string;
  description: string;
  kind: "GOAL" | "SUBGOAL" | "ACTION";
  operator: "AND" | "OR" | "LEAF";
  graph_node_ids: string[];
  flow_ids: string[];
}

export interface RepositoryAttackTree {
  title: string;
  root_attack_node_id: string;
  nodes: RepositoryAttackTreeNode[];
  edges: Array<{
    parent_attack_node_id: string;
    child_attack_node_id: string;
  }>;
  assumptions: string[];
  limitations: string[];
}

export interface RepositoryGraphModelResult {
  status: "READY" | "SKIPPED" | "DISABLED" | "FAILED";
  provider: string;
  model: string;
  explanation: RepositoryGraphNarrative | null;
  error_code: string | null;
  provenance: {
    method: "POST";
    url: string;
    provider: string;
    model: string;
    graph_digest: string;
    projection_sha256: string;
    request_sha256: string;
    projection: {
      complete: boolean;
      included_nodes: number;
      included_edges: number;
    };
    disclosure: string;
  } | null;
  provider_request_id?: string | null;
  input_tokens?: number | null;
  output_tokens?: number | null;
}

export interface WorkflowDraft {
  name: string;
  description: string;
  actor_role: string;
  node_ids: string[];
}

export interface WorkflowValidationError {
  code: string;
  message: string;
}

export interface WorkflowValidation {
  valid: boolean;
  errors: WorkflowValidationError[];
  normalized: WorkflowDraft;
  graph_digest: string;
}

export interface CompanyFinancialProfile {
  schema_version: string;
  legal_entity: string;
  reporting_currency: "GBP";
  fiscal_year: number;
  statement_of_scope: string;
  income: {
    annual_revenue_gbp: number;
    net_income_gbp: number;
    operating_expenses_gbp: number;
  };
  balance_sheet: {
    total_assets_gbp: number;
    customer_deposits_gbp: number;
    shareholder_equity_gbp: number;
    liquid_reserves_gbp: number;
  };
  operations: {
    active_customers: number;
    daily_payment_volume_gbp: number;
    average_payment_gbp: number;
    employees: number;
  };
  risk_appetite: {
    impact_tolerance_gbp: number;
    maximum_credible_single_loss_gbp: number;
    annual_security_budget_gbp: number;
    cost_of_capital_pct: number;
  };
  insurance: { cyber_cover_gbp: number; retention_gbp: number };
  regulatory: {
    regime: string;
    maximum_penalty_pct_of_revenue: number;
    notification_window_hours: number;
  };
  notes: string[];
}

export interface CompanyFinancialsVersion {
  profile_id: string | null;
  version: number;
  source: "REPOSITORY_DEFAULT" | "REVIEWED_VERSION";
  profile: CompanyFinancialProfile;
  profile_digest: string;
  change_note: string;
  created_by: string | null;
  created_at: string | null;
  financial_inputs: Record<string, number>;
}

export interface CompanyFinancialsHistoryEntry {
  profile_id: string;
  version: number;
  profile_digest: string;
  change_note: string;
  created_by: string;
  created_at: string;
}

export interface CompanyFinancialsOverview {
  current: CompanyFinancialsVersion;
  history: CompanyFinancialsHistoryEntry[];
  repository_default: CompanyFinancialProfile;
  input_names: string[];
}

export interface SoftwareComponent {
  component_id: string;
  name: string;
  category: string;
  detection_rule: string;
  detail: string;
  evidence_node_ids: string[];
  evidence_count: number;
}

export interface SoftwareInventory {
  version: number;
  graph_digest: string;
  derivation: string;
  components: SoftwareComponent[];
  busiest_modules: Array<{ path: string; node_count: number }>;
}

export interface ScenarioAttackNode {
  attack_node_id: string;
  title: string;
  description: string;
  kind: "GOAL" | "SUBGOAL" | "ACTION";
  operator: "AND" | "OR" | "LEAF";
  graph_node_ids: string[];
  flow_ids: string[];
  mitre_technique_ids: string[];
  success_probability: number;
  detection_probability: number;
}

export interface LossRange {
  minimum_gbp: number;
  most_likely_gbp: number;
  maximum_gbp: number;
}

export interface AttackScenario {
  scenario_id: string;
  name: string;
  business_service: string;
  narrative: string;
  mitre_techniques: Array<{
    technique_id: string;
    name: string;
    tactic: string;
    url: string;
  }>;
  attack_tree: {
    title: string;
    root_attack_node_id: string;
    nodes: ScenarioAttackNode[];
    edges: Array<{
      parent_attack_node_id: string;
      child_attack_node_id: string;
    }>;
    assumptions: string[];
    limitations: string[];
  };
  financials: {
    annual_attempt_frequency: number;
    primary_loss: LossRange;
    secondary_loss: LossRange;
    detected_loss_multiplier: number;
    rationale: string;
    financial_inputs_used: string[];
  };
}

export interface AttackScenarioModelResult {
  status: "READY" | "SKIPPED" | "DISABLED" | "FAILED";
  provider: string;
  model: string;
  error_code: string | null;
  provenance: {
    method: string;
    url: string;
    provider: string;
    model: string;
    graph_digest: string;
    projection_sha256: string;
    request_sha256: string;
    projection: { complete: boolean; included_nodes: number; included_edges: number };
    disclosure: string;
  } | null;
  scenario_set: {
    schema_version: string;
    summary: string;
    scenarios: AttackScenario[];
    assumptions: string[];
    limitations: string[];
  } | null;
  provider_request_id?: string | null;
  input_tokens?: number | null;
  output_tokens?: number | null;
}

export interface SimulationResult {
  engine_version: string;
  scenario_id: string;
  iterations: number;
  seed: number;
  annual_loss: {
    mean_gbp: number;
    standard_deviation_gbp: number;
    median_gbp: number;
    p90_gbp: number;
    p95_gbp: number;
    p99_gbp: number;
    maximum_gbp: number;
  };
  gross_mean_annual_loss_gbp: number;
  insurance_recovery_mean_gbp: number;
  expected_events_per_year: number;
  probability_of_loss_year: number;
  exceedance_probability: number;
  impact_tolerance_gbp: number;
  maximum_credible_single_loss_gbp: number;
  detected_event_share: number;
  capped_event_share: number;
  mean_as_pct_of_revenue: number | null;
  p95_as_pct_of_equity: number | null;
  attack_path_contributions: Array<{
    attack_node_id: string;
    title: string;
    attempts: number;
    successful_events: number;
    share_of_successful_events: number;
    effective_success_probability: number;
    effective_detection_probability: number;
    graph_node_ids: string[];
    mitre_technique_ids: string[];
  }>;
  histogram: {
    bin_width_gbp: number;
    ceiling_gbp: number;
    overflow_count: number;
    bins: Array<{ lower_gbp: number; upper_gbp: number; count: number }>;
  };
  loss_exceedance_curve: Array<{ loss_gbp: number; annual_probability: number }>;
  applied_remediation_ids: string[];
  interpretation: string;
}

export interface ProgrammeEconomics {
  implementation_cost_gbp: number;
  annual_run_cost_gbp: number;
  first_year_cost_gbp: number;
  annual_loss_reduction_gbp: number;
  net_annual_benefit_gbp: number;
  payback_years: number | null;
  exceedance_change: number;
  basis: string;
}

export interface AttackSimulation {
  simulation_id: string;
  scenario_set_id: string;
  scenario_id: string;
  iterations: number;
  seed: number;
  remediation_plan_id: string | null;
  applied_remediation_ids: string[];
  result: {
    baseline: SimulationResult;
    residual: SimulationResult | null;
    economics: ProgrammeEconomics | null;
  };
  created_by: string;
  created_at: string;
}

export interface Remediation {
  remediation_id: string;
  title: string;
  description: string;
  mitre_mitigation_ids: string[];
  mitre_mitigation_urls: string[];
  target_attack_node_ids: string[];
  graph_node_ids: string[];
  software_component_ids: string[];
  implementation_effort: "DAYS" | "WEEKS" | "MONTHS";
  priority: "IMMEDIATE" | "HIGH" | "MEDIUM" | "LOW";
  estimated_cost_gbp: number;
  annual_run_cost_gbp: number;
  success_probability_reduction: number;
  detection_probability_uplift: number;
  residual_risk_note: string;
  evidence_rationale: string;
}

export interface RemediationModelResult {
  status: "READY" | "DISABLED" | "FAILED";
  provider: string;
  model: string;
  error_code: string | null;
  provenance: Record<string, unknown> | null;
  plan: {
    schema_version: string;
    summary: string;
    remediations: Remediation[];
    monitoring: string[];
    assumptions: string[];
    limitations: string[];
  } | null;
}

export interface AttackRemediationPlan {
  remediation_plan_id: string;
  simulation_id: string;
  scenario_set_id: string;
  scenario_id: string;
  model_result: RemediationModelResult;
  created_by: string;
  created_at: string;
}

export interface AttackScenarioSet {
  scenario_set_id: string;
  graph_source: "BUILTIN" | "REPOSITORY_SNAPSHOT";
  repository_graph_snapshot_id: string | null;
  graph_digest: string;
  financial_profile_version: number;
  financial_profile_digest: string;
  financial_profile: CompanyFinancialProfile;
  software_inventory: SoftwareInventory;
  model_result: AttackScenarioModelResult;
  created_by: string;
  created_at: string;
  simulations: AttackSimulation[];
  remediation_plans: AttackRemediationPlan[];
}

export interface AttackScenarioOverview {
  mistral_configured: boolean;
  builtin_graph: {
    graph_digest: string;
    nodes: number;
    edges: number;
    flows: number;
  };
  software_inventory: SoftwareInventory;
  financials: CompanyFinancialsVersion;
  repository_snapshots: Array<{
    snapshot_id: string;
    repository: string;
    resolved_commit: string;
    graph_digest: string;
    created_at: string;
  }>;
  scenario_sets: Array<{
    scenario_set_id: string;
    graph_source: "BUILTIN" | "REPOSITORY_SNAPSHOT";
    repository_graph_snapshot_id: string | null;
    graph_digest: string;
    financial_profile_version: number;
    financial_profile_digest: string;
    model_status: string;
    model_error_code: string | null;
    created_by: string;
    created_at: string;
    simulation_count: number;
  }>;
  limits: {
    min_scenarios: number;
    max_scenarios: number;
    min_iterations: number;
    max_iterations: number;
    default_iterations: number;
    engine_version: string;
  };
}

export interface AttackScenarioRequest {
  graph_source: "BUILTIN" | "REPOSITORY_SNAPSHOT";
  snapshot_id: string | null;
  scenario_count: number;
  send_to_mistral: boolean;
}

export interface AttackSimulationRequest {
  scenario_id: string;
  iterations: number;
  seed: number;
  remediation_plan_id?: string | null;
  remediation_ids?: string[];
}
