import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Bot,
  Braces,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Clock3,
  Code2,
  FileCheck2,
  Fingerprint,
  Gauge,
  Hash,
  LockKeyhole,
  Play,
  ShieldCheck,
  Sparkles,
  XCircle,
} from "lucide-react";
import { api } from "../../api";
import "./AsvsPage.css";
import {
  Button,
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
  Panel,
  StatusPill,
  useToast,
} from "../../components/ui";
import type {
  AsvsControl,
  AsvsEvidenceRecord,
  AsvsOverview,
} from "../../types";
import { formatDate, humanize, shortId } from "../../utils";

function EvidenceIcon({ status }: { status: string }) {
  if (status === "pass") return <CheckCircle2 aria-hidden="true" />;
  if (status === "fail") return <XCircle aria-hidden="true" />;
  return <CircleAlert aria-hidden="true" />;
}

function EvidenceList({
  title,
  values,
  tone = "neutral",
}: {
  title: string;
  values: string[];
  tone?: "positive" | "negative" | "neutral";
}) {
  if (values.length === 0) return null;
  return (
    <div className={`asvs-evidence-list evidence-${tone}`}>
      <strong>{title}</strong>
      <ul>{values.map((value) => <li key={value}>{value}</li>)}</ul>
    </div>
  );
}

function ControlCard({
  control,
  evidence,
}: {
  control: AsvsControl;
  evidence?: AsvsEvidenceRecord;
}) {
  const status = evidence?.status ?? "not_run";
  return (
    <article className={`asvs-control control-${status}`}>
      <div className="asvs-control-head">
        <span className="asvs-control-icon"><EvidenceIcon status={status} /></span>
        <div>
          <div className="asvs-control-meta">
            <code>{control.control_id}</code>
            <StatusPill value={status.toUpperCase()} />
            <StatusPill value={control.severity.toUpperCase()} />
          </div>
          <h3>{control.title}</h3>
        </div>
      </div>
      <div className="asvs-frameworks">
        {control.framework_ids.map((id) => <span key={id}>ASVS {id}</span>)}
      </div>
      <details>
        <summary>
          <span>{evidence ? "Inspect verification evidence" : "Inspect control definition"}</span>
          <ChevronRight size={16} aria-hidden="true" />
        </summary>
        <div className="asvs-control-detail">
          {evidence ? (
            <>
              <div className="asvs-evidence-facts">
                <span><strong>{Math.round(evidence.confidence * 100)}%</strong> confidence</span>
                <span><strong>{evidence.target}</strong> target</span>
                <span><strong>{evidence.validated_by}</strong> validator</span>
              </div>
              <EvidenceList title="Execution evidence" values={evidence.execution_evidence} tone="positive" />
              <EvidenceList title="Counter-evidence" values={evidence.counter_evidence} tone="negative" />
              <EvidenceList title="Limitations" values={evidence.limitations} />
              <EvidenceList title="Source evidence" values={evidence.source_evidence} />
            </>
          ) : (
            <p className="asvs-not-run">No live evidence has been recorded for this control yet.</p>
          )}
          <div className="asvs-remediation">
            <LockKeyhole size={16} aria-hidden="true" />
            <div><strong>Required safeguard</strong><p>{control.remediation}</p></div>
          </div>
        </div>
      </details>
    </article>
  );
}

function AiPlanLab({
  overview,
  generationPending,
  executionPending,
  onGenerate,
  onExecute,
}: {
  overview: AsvsOverview;
  generationPending: boolean;
  executionPending: boolean;
  onGenerate: () => void;
  onExecute: (generationId: string) => void;
}) {
  const generator = overview.ai_generator;
  const generation = generator.latest_generation;
  const quotaExhausted = generator.usage.session_remaining === 0
    || generator.usage.account_daily_remaining === 0
    || generator.usage.daily_remaining === 0;
  const quotaPercent = Math.min(
    100,
    (generator.usage.account_daily / generator.limits.per_account_per_day) * 100,
  );
  const planReady = generation?.status === "READY"
    && generation.plan
    && generation.plan.rego_module
    && generation.compiled_pytest;

  return (
    <Panel className="asvs-ai-lab">
      <div className="asvs-ai-heading">
        <div className="asvs-ai-title">
          <span><Bot size={24} aria-hidden="true" /></span>
          <div>
            <p className="eyebrow">AI-assisted test authoring</p>
            <h2>Turn ASVS prose into tests and Rego policy</h2>
            <p>
              {generator.model} reads bounded excerpts from the running Bank checkout,
              its live OpenAPI contract, and Terraform-infra. Bantam validates every
              citation, a restricted Rego v1 module, and visible pytest without
              evaluating model output.
            </p>
          </div>
        </div>
        <div className="asvs-ai-badges">
          <span><FileCheck2 size={14} /> Live source snapshot</span>
          <span><Braces size={14} /> Strict JSON schema</span>
          <span><ShieldCheck size={14} /> Rego v1 safe subset</span>
          <span><LockKeyhole size={14} /> No eval or shell</span>
          <span><Gauge size={14} /> Hard quota</span>
        </div>
      </div>

      <div className="asvs-ai-workbench">
        <section className="asvs-ai-source">
          <div className="asvs-ai-section-title">
            <div><p className="eyebrow">Model input</p><h3>ASVS + running source context</h3></div>
            <span>ASVS {overview.catalog.version}</span>
          </div>
          <div className="asvs-ai-requirements">
            {overview.catalog.controls.map((control, index) => (
              <article key={control.control_id}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <div>
                  <code>{control.control_id}</code>
                  <strong>{control.title}</strong>
                  <small>{control.remediation}</small>
                </div>
              </article>
            ))}
          </div>
          <div className="asvs-ai-source-readiness">
            <span className={generator.source_status.application.ready ? "ready" : "missing"}>
              <Code2 size={15} />
              <strong>Application</strong>
              {generator.source_status.application.eligible_files} eligible files
            </span>
            <span className={generator.source_status.terraform.ready ? "ready" : "missing"}>
              <FileCheck2 size={15} />
              <strong>Terraform</strong>
              {generator.source_status.terraform.eligible_files} eligible files
            </span>
            <small>
              At most {generator.limits.max_source_files} files and{" "}
              {Math.round(generator.limits.max_source_bytes / 1000)} KB of redacted
              excerpts leave the platform.
            </small>
          </div>
        </section>

        <section className="asvs-ai-action">
          <div className="asvs-ai-section-title">
            <div><p className="eyebrow">Generation boundary</p><h3>One request, then validation</h3></div>
            <StatusPill value={generator.enabled ? "READY" : "DISABLED"} />
          </div>
          <div className="asvs-ai-steps">
            <div><span>1</span><p><strong>Capture</strong><small>Hash live code, OpenAPI + Terraform</small></p></div>
            <div><span>2</span><p><strong>Ground</strong><small>Cite exact captured paths</small></p></div>
            <div><span>3</span><p><strong>Constrain</strong><small>Validate scenarios + Rego</small></p></div>
            <div><span>4</span><p><strong>Approve</strong><small>Run without eval or shell</small></p></div>
          </div>
          <div className="asvs-ai-quota">
            <div>
              <span>Account daily quota</span>
              <strong>{generator.usage.account_daily}/{generator.limits.per_account_per_day} used</strong>
            </div>
            <div className="asvs-ai-quota-track">
              <span style={{ width: `${quotaPercent}%` }} />
            </div>
            <small>
              {generator.usage.session}/{generator.limits.per_session} used this session
              · {generator.usage.daily}/{generator.limits.per_day} app-wide today
              · {generator.limits.max_output_tokens} output tokens ·
              {" "}{Math.round(generator.limits.max_input_bytes / 1000)} KB request ceiling ·
              {" "}{generator.limits.timeout_seconds}s timeout · no retries
            </small>
          </div>
          {!generator.enabled && (
            <div className="asvs-ai-disabled">
              <LockKeyhole size={17} />
              <p><strong>Generator unavailable</strong><span>{generator.disabled_reason}</span></p>
            </div>
          )}
          <Button
            onClick={onGenerate}
            disabled={!generator.enabled || quotaExhausted || generationPending || executionPending}
          >
            <Sparkles size={16} aria-hidden="true" />
            {generationPending ? "Generating constrained plan…" : "Generate AI test plan"}
          </Button>
        </section>
      </div>

      {generation && (
        <section className="asvs-ai-result">
          <div className="asvs-ai-result-head">
            <div>
              <p className="eyebrow">Latest candidate</p>
              <h3>Validated model output</h3>
            </div>
            <div>
              <StatusPill value={generation.status} />
              <code>{shortId(generation.generation_id)}</code>
            </div>
          </div>

          {generation.status === "FAILED" ? (
            <div className="asvs-ai-failed">
              <CircleAlert size={18} />
              <p>
                The provider request or schema validation failed safely.
                {generation.error_code ? ` ${humanize(generation.error_code)}.` : ""}
                {" "}The attempt counted toward the displayed quota and was not retried.
              </p>
            </div>
          ) : generation.plan ? (
            <>
              <p className="asvs-ai-summary">{generation.plan.summary}</p>
              <div className="asvs-ai-plan-grid">
                {generation.plan.tests.map((test) => (
                  <article key={test.control_id}>
                    <span><CheckCircle2 size={16} /></span>
                    <div>
                      <code>{test.control_id} · {test.scenario_id}</code>
                      <strong>{test.name}</strong>
                      <p>{test.objective}</p>
                      <small>{test.grounding}</small>
                      <div className="asvs-ai-citations">
                        {test.source_refs.map((path) => <code key={path}>{path}</code>)}
                        {test.terraform_refs.map((path) => <code key={path}>{path}</code>)}
                      </div>
                    </div>
                  </article>
                ))}
              </div>
              <div className="asvs-ai-integrity">
                <span><Fingerprint size={15} /> Plan <code>{shortId(generation.plan_sha256 ?? "")}</code></span>
                <span><Hash size={15} /> Rego <code>{shortId(generation.rego_sha256 ?? "")}</code></span>
                <span><Hash size={15} /> Source <code>{shortId(generation.provenance.source_sha256)}</code></span>
                <span><Hash size={15} /> OpenAPI <code>{shortId(generation.provenance.openapi_sha256)}</code></span>
                <span><Hash size={15} /> Request <code>{shortId(generation.provenance.request_sha256)}</code></span>
                <span><Hash size={15} /> Prompt <code>{shortId(generation.prompt_sha256)}</code></span>
                <span><Gauge size={15} /> {generation.output_tokens ?? "—"} output tokens</span>
              </div>
              <details className="asvs-ai-code asvs-ai-provenance">
                <summary>
                  <span><FileCheck2 size={16} /> Inspect source supplied to the model</span>
                  <ChevronRight size={16} />
                </summary>
                <div className="asvs-ai-source-files">
                  {generation.provenance.source_context.files.map((file) => (
                    <article key={`${file.repository}:${file.path}`}>
                      <div>
                        <code>{file.repository} · {file.path}</code>
                        <span>
                          {file.included_bytes} bytes
                          {file.truncated ? " · excerpted" : " · complete"}
                          {" · "}{shortId(file.sha256)}
                        </span>
                      </div>
                      <pre><code>{file.excerpt}</code></pre>
                    </article>
                  ))}
                </div>
              </details>
              <details className="asvs-ai-code">
                <summary>
                  <span><Braces size={16} /> Inspect live OpenAPI snapshot</span>
                  <ChevronRight size={16} />
                </summary>
                <pre><code>{JSON.stringify(generation.provenance.openapi_snapshot, null, 2)}</code></pre>
              </details>
              <details className="asvs-ai-code">
                <summary>
                  <span><Code2 size={16} /> Inspect redacted provider request</span>
                  <ChevronRight size={16} />
                </summary>
                <p className="asvs-ai-disclosure">{generation.provenance.disclosure}</p>
                <pre><code>{JSON.stringify(generation.provenance.model_request, null, 2)}</code></pre>
              </details>
              {generation.compiled_pytest && (
                <details className="asvs-ai-code">
                  <summary><span><Code2 size={16} /> Inspect compiled pytest</span><ChevronRight size={16} /></summary>
                  <pre><code>{generation.compiled_pytest}</code></pre>
                </details>
              )}
              <details className="asvs-ai-code">
                <summary>
                  <span><Braces size={16} /> Inspect model-authored Rego policy</span>
                  <ChevronRight size={16} />
                </summary>
                <p className="asvs-ai-disclosure">
                  The model returned these evidence rules. Bantam accepted only
                  package-local equality checks over reviewed scenario results,
                  then normalized the module. It is not executed by this demo.
                </p>
                <pre><code>{generation.plan.rego_module}</code></pre>
              </details>
              <div className="asvs-ai-approval">
                <div>
                  <ShieldCheck size={19} />
                  <p>
                    <strong>Human approval boundary</strong>
                    <span>
                      Approval interprets the source-grounded, validated scenario IDs through
                      the existing loopback runner. Neither the displayed Python nor Rego is
                      dynamically executed.
                    </span>
                  </p>
                </div>
                {planReady ? (
                  <Button
                    onClick={() => onExecute(generation.generation_id)}
                    disabled={generationPending || executionPending}
                  >
                    <Play size={16} />
                    {executionPending ? "Running reviewed scenarios…" : "Approve and run plan"}
                  </Button>
                ) : generation.status === "EXECUTED" ? (
                  <span className="asvs-ai-executed">
                    <CheckCircle2 size={16} />
                    Executed as run {shortId(generation.asvs_run_id ?? "")}
                  </span>
                ) : null}
              </div>
            </>
          ) : null}
        </section>
      )}
    </Panel>
  );
}

export function AsvsPage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["asvs-overview"],
    queryFn: api.asvsOverview,
    staleTime: 15_000,
  });
  const mutation = useMutation({
    mutationFn: api.runAsvs,
    onSuccess: async (run) => {
      toast.success(
        `ASVS verification ${run.status.toLowerCase()}`,
        `${run.controls_passed} of ${run.controls_total} controls passed and the evidence was sealed.`,
      );
      await queryClient.invalidateQueries({ queryKey: ["asvs-overview"] });
    },
    onError: (error) => toast.error("ASVS verification did not complete", error),
  });
  const generationMutation = useMutation({
    mutationFn: api.generateAsvsTestPlan,
    onSuccess: async (generation) => {
      toast.success(
        "AI tests and Rego validated",
        `${generation.plan?.tests.length ?? 0} source-grounded tests and candidate policy rules passed the safe boundary.`,
      );
      await queryClient.invalidateQueries({ queryKey: ["asvs-overview"] });
    },
    onError: (error) => toast.error("AI test plan was not generated", error),
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: ["asvs-overview"] });
    },
  });
  const executionMutation = useMutation({
    mutationFn: api.executeAsvsTestPlan,
    onSuccess: async ({ run }) => {
      toast.success(
        `Approved plan ${run.status.toLowerCase()}`,
        `${run.controls_passed} of ${run.controls_total} reviewed scenarios passed.`,
      );
      await queryClient.invalidateQueries({ queryKey: ["asvs-overview"] });
    },
    onError: (error) => toast.error("Approved test plan did not complete", error),
  });

  if (query.isLoading) return <LoadingState label="Loading ASVS assurance evidence" />;
  if (query.error || !query.data) {
    return <ErrorState error={query.error} onRetry={() => query.refetch()} />;
  }

  const overview: AsvsOverview = query.data;
  const latest = overview.latest_run;
  const evidenceByControl = new Map(
    (latest?.evidence ?? []).map((record) => [record.control_id, record]),
  );
  const runLabel = mutation.isPending
    ? "Executing protected probes…"
    : latest
      ? "Run verification again"
      : "Run live verification";

  return (
    <div className="page-stack asvs-page">
      <PageHeader
        eyebrow="Application assurance"
        title="ASVS control room"
        description="Run a reviewed Broken Access Control control set against Bantam’s real HTTP boundary, then inspect immutable, redacted evidence tied to the source revision."
        action={
          overview.runner_enabled ? (
            <Button
              onClick={() => mutation.mutate()}
              disabled={mutation.isPending || executionMutation.isPending}
            >
              <Play size={16} aria-hidden="true" />
              {runLabel}
            </Button>
          ) : (
            <span className="asvs-mode-pill"><LockKeyhole size={15} /> Evidence-only mode</span>
          )
        }
      />

      <Panel className="asvs-hero">
        <div className="asvs-hero-copy">
          <span className="asvs-shield"><ShieldCheck size={30} aria-hidden="true" /></span>
          <div>
            <p className="eyebrow eyebrow-light">Aspis assurance workflow</p>
            <h2>Security claims backed by reproducible evidence.</h2>
            <p>
              This is not a vulnerability toggle. The runner signs in with synthetic seeded
              identities, sends fixed same-origin probes, redacts all session material, and
              records the observed result without permitting an override.
            </p>
          </div>
        </div>
        <div className="asvs-flow" aria-label="ASVS evidence workflow">
          <div><span>01</span><strong>Select</strong><small>Reviewed ASVS subset</small></div>
          <ChevronRight aria-hidden="true" />
          <div><span>02</span><strong>Verify</strong><small>Live HTTP authorization</small></div>
          <ChevronRight aria-hidden="true" />
          <div><span>03</span><strong>Seal</strong><small>Hash + append-only audit</small></div>
        </div>
        <div className={`asvs-mode-banner ${overview.runner_enabled ? "enabled" : ""}`}>
          {overview.runner_enabled ? <Activity size={17} /> : <LockKeyhole size={17} />}
          <div>
            <strong>{overview.runner_enabled ? "Live verification enabled" : "Live verification disabled"}</strong>
            <span>
              {overview.runner_enabled
                ? `Development-only synthetic probes are available with a ${overview.cooldown_seconds}-second cooldown.`
                : "Production-safe mode: authorised administrators and Aspis auditors can inspect durable evidence, but the app cannot synthesize credentials or probes."}
            </span>
          </div>
        </div>
      </Panel>

      <AiPlanLab
        overview={overview}
        generationPending={generationMutation.isPending}
        executionPending={executionMutation.isPending || mutation.isPending}
        onGenerate={() => generationMutation.mutate()}
        onExecute={(generationId) => executionMutation.mutate(generationId)}
      />

      <div className="metric-grid asvs-metrics">
        <Panel className={`metric-card metric-${latest?.status === "PASS" ? "positive" : latest ? "warning" : ""}`}>
          <div className="metric-card-head"><span>Overall result</span><ShieldCheck /></div>
          <strong>{latest?.status ?? "—"}</strong>
          <small>{latest ? `Completed ${formatDate(latest.completed_at, true)}` : "No run recorded"}</small>
        </Panel>
        <Panel className="metric-card metric-positive">
          <div className="metric-card-head"><span>Controls passed</span><CheckCircle2 /></div>
          <strong>{latest ? `${latest.controls_passed}/${latest.controls_total}` : `0/${overview.catalog.controls.length}`}</strong>
          <small>Deterministically verified</small>
        </Panel>
        <Panel className={latest && (latest.controls_failed + latest.controls_error) > 0 ? "metric-card metric-warning" : "metric-card"}>
          <div className="metric-card-head"><span>Exceptions / errors</span><CircleAlert /></div>
          <strong>{overview.accepted_exceptions} / {latest?.controls_error ?? 0}</strong>
          <small>Accepted exceptions / execution errors</small>
        </Panel>
        <Panel className="metric-card">
          <div className="metric-card-head"><span>Evidence integrity</span><Fingerprint /></div>
          <strong className="asvs-hash-metric">{latest ? shortId(latest.evidence_sha256) : "Awaiting run"}</strong>
          <small>SHA-256 canonical bundle</small>
        </Panel>
      </div>

      <section className="asvs-section">
        <div className="asvs-section-heading">
          <div><p className="eyebrow">Reviewed scope</p><h2>Broken Access Control verification</h2></div>
          <span>{overview.catalog.controls.length} controls · ASVS {overview.catalog.version}</span>
        </div>
        <div className="asvs-control-grid">
          {overview.catalog.controls.map((control) => (
            <ControlCard
              key={control.control_id}
              control={control}
              evidence={evidenceByControl.get(control.control_id)}
            />
          ))}
        </div>
      </section>

      <div className="asvs-evidence-grid">
        <Panel>
          <div className="panel-heading">
            <div><p className="eyebrow">Chain of evidence</p><h2>Latest sealed artifact</h2></div>
            <FileCheck2 size={20} />
          </div>
          {latest ? (
            <dl className="asvs-integrity">
              <div><dt><Hash size={14} /> Evidence SHA-256</dt><dd><code>{latest.evidence_sha256}</code></dd></div>
              <div><dt><Fingerprint size={14} /> Target commit</dt><dd><code>{latest.target_commit}</code></dd></div>
              <div><dt><FileCheck2 size={14} /> Run ID</dt><dd><code>{latest.run_id}</code></dd></div>
              <div><dt><Clock3 size={14} /> Duration</dt><dd>{latest.duration_ms} ms</dd></div>
            </dl>
          ) : (
            <EmptyState title="No sealed artifact yet" description="Run the reviewed verification set in the development demo to create the first immutable evidence bundle." />
          )}
        </Panel>

        <Panel padded={false}>
          <div className="panel-heading panel-heading-padded">
            <div><p className="eyebrow">Run history</p><h2>Immutable verification ledger</h2></div>
            <span className="result-count">{overview.history.length} runs</span>
          </div>
          {overview.history.length === 0 ? (
            <EmptyState title="No verification history" description="Completed ASVS runs will appear here with their source revision and evidence hash." />
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Completed</th><th>Result</th><th>Controls</th><th>Commit</th><th>Evidence</th></tr></thead>
                <tbody>
                  {overview.history.map((run) => (
                    <tr key={run.run_id}>
                      <td>{formatDate(run.completed_at, true)}</td>
                      <td><StatusPill value={run.status} /></td>
                      <td>{run.controls_passed}/{run.controls_total} passed</td>
                      <td><code>{shortId(run.target_commit)}</code></td>
                      <td><code>{shortId(run.evidence_sha256)}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>

      <div className="asvs-limitations">
        <CircleAlert size={18} aria-hidden="true" />
        <div>
          <strong>Scope statement</strong>
          <p>
            This demo verifies five selected ASVS 5.0 authorization and session controls. It
            demonstrates the evidence pipeline; it is not certification and does not claim
            complete ASVS coverage. Status labels are {humanize("pass")}, {humanize("fail")},
            {" "}{humanize("inconclusive")}, or {humanize("error")} based only on observed evidence.
          </p>
        </div>
      </div>
    </div>
  );
}
