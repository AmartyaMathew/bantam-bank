import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Bot,
  ChevronRight,
  Coins,
  GitFork,
  ListChecks,
  Network,
  Play,
  RefreshCw,
  ShieldAlert,
  Target,
  TriangleAlert,
  Wrench,
} from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { api } from "../../api";
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
import { formatCompactGbp, formatDate, formatGbp, formatPercent, shortId } from "../../utils";
import type {
  AttackScenario,
  AttackScenarioSet,
  AttackSimulation,
  Remediation,
  ScenarioAttackNode,
  SimulationResult,
} from "../../types";

const STEPS = [
  {
    title: "Read the code",
    detail: "Bantam builds a knowledge graph of every route, guard, transaction, and database effect straight from the source. Nothing is hand-written.",
  },
  {
    title: "Ask for attack trees",
    detail: "That graph, the software it reveals, and the company's financial figures go to Mistral, which returns several MITRE ATT&CK attack trees with cost estimates.",
  },
  {
    title: "Simulate a chosen tree",
    detail: "Bantam runs the maths itself: ten thousand simulated years of attempts through the tree you pick, giving a range of annual losses rather than one number.",
  },
  {
    title: "Get costed remediations",
    detail: "The tree and its simulation go back to the model, which proposes fixes for the specific steps that mattered. Re-run to see what the fixes are worth.",
  },
];

export function AttackLabPage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const overviewQuery = useQuery({
    queryKey: ["attack-scenarios"],
    queryFn: api.attackScenarioOverview,
  });
  const [scenarioSetId, setScenarioSetId] = useState<string | null>(null);
  const [scenarioCount, setScenarioCount] = useState(3);
  const [snapshotId, setSnapshotId] = useState("");
  const [selectedScenarioId, setSelectedScenarioId] = useState<string | null>(null);
  const [iterations, setIterations] = useState(10000);
  const [seed, setSeed] = useState(20250101);
  const [appliedIds, setAppliedIds] = useState<string[]>([]);

  const setQuery = useQuery({
    queryKey: ["attack-scenario-set", scenarioSetId],
    queryFn: () => api.attackScenarioSet(scenarioSetId as string),
    enabled: Boolean(scenarioSetId),
  });

  const generate = useMutation({
    mutationFn: () =>
      api.generateAttackScenarios({
        graph_source: snapshotId ? "REPOSITORY_SNAPSHOT" : "BUILTIN",
        snapshot_id: snapshotId || null,
        scenario_count: scenarioCount,
        send_to_mistral: true,
      }),
    onSuccess: (created) => {
      queryClient.setQueryData(["attack-scenario-set", created.scenario_set_id], created);
      setScenarioSetId(created.scenario_set_id);
      setSelectedScenarioId(null);
      setAppliedIds([]);
      queryClient.invalidateQueries({ queryKey: ["attack-scenarios"] });
      const status = created.model_result.status;
      if (status === "READY") {
        toast.success(
          `${created.model_result.scenario_set?.scenarios.length ?? 0} attack trees generated`,
          "Every branch cites deterministic graph evidence.",
        );
      } else {
        toast.error("No attack trees were stored", new Error(created.model_result.error_code ?? status));
      }
    },
    onError: (error) => toast.error("Attack-tree generation failed", error),
  });

  const simulate = useMutation({
    mutationFn: (input: { scenarioId: string; planId?: string; remediationIds?: string[] }) =>
      api.runAttackSimulation(scenarioSetId as string, {
        scenario_id: input.scenarioId,
        iterations,
        seed,
        remediation_plan_id: input.planId ?? null,
        remediation_ids: input.remediationIds ?? [],
      }),
    onSuccess: (simulation) => {
      queryClient.invalidateQueries({ queryKey: ["attack-scenario-set", scenarioSetId] });
      toast.success(
        "Simulation complete",
        `Mean annual loss ${formatGbp(simulation.result.baseline.annual_loss.mean_gbp)} across ${simulation.iterations.toLocaleString("en-GB")} simulated years.`,
      );
    },
    onError: (error) => toast.error("The simulation did not run", error),
  });

  const remediate = useMutation({
    mutationFn: (simulationId: string) =>
      api.generateAttackRemediations(scenarioSetId as string, simulationId),
    onSuccess: (plan) => {
      queryClient.invalidateQueries({ queryKey: ["attack-scenario-set", scenarioSetId] });
      if (plan.model_result.status === "READY") {
        toast.success(
          `${plan.model_result.plan?.remediations.length ?? 0} remediations proposed`,
          "Select the ones to model, then re-run the simulation.",
        );
      } else {
        toast.error("No remediations were stored", new Error(plan.model_result.error_code ?? "provider error"));
      }
    },
    onError: (error) => toast.error("Remediation advice failed", error),
  });

  const scenarioSet = setQuery.data;
  const scenarios = scenarioSet?.model_result.scenario_set?.scenarios ?? [];
  const selected = scenarios.find((scenario) => scenario.scenario_id === selectedScenarioId) ?? null;

  const latestSimulation = useMemo(() => {
    if (!scenarioSet || !selected) return null;
    return (
      scenarioSet.simulations.find(
        (simulation) =>
          simulation.scenario_id === selected.scenario_id &&
          simulation.applied_remediation_ids.length === 0,
      ) ?? null
    );
  }, [scenarioSet, selected]);

  const remediatedSimulation = useMemo(() => {
    if (!scenarioSet || !selected) return null;
    return (
      scenarioSet.simulations.find(
        (simulation) =>
          simulation.scenario_id === selected.scenario_id &&
          simulation.applied_remediation_ids.length > 0,
      ) ?? null
    );
  }, [scenarioSet, selected]);

  const plan = useMemo(() => {
    if (!scenarioSet || !latestSimulation) return null;
    return (
      scenarioSet.remediation_plans.find(
        (entry) => entry.simulation_id === latestSimulation.simulation_id,
      ) ?? null
    );
  }, [scenarioSet, latestSimulation]);

  if (overviewQuery.isError) {
    return <ErrorState error={overviewQuery.error} onRetry={() => overviewQuery.refetch()} />;
  }
  const overview = overviewQuery.data;
  if (!overview) return <LoadingState label="Loading attack analysis workspace" />;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Threat and loss analysis"
        title="Attack simulation lab"
        description="Turn Bantam's own source code into MITRE ATT&CK attack trees, price them against the company's financials, simulate them, and get remediations for what actually drives the loss."
        action={
          <Button onClick={() => generate.mutate()} disabled={generate.isPending || !overview.mistral_configured}>
            <Bot size={16} /> {generate.isPending ? "Asking Mistral…" : "Generate attack trees"}
          </Button>
        }
      />

      <ol className="attack-steps">
        {STEPS.map((step, index) => (
          <li key={step.title}>
            <span className="attack-step-number">{String(index + 1).padStart(2, "0")}</span>
            <div>
              <h3>{step.title}</h3>
              <p>{step.detail}</p>
            </div>
          </li>
        ))}
      </ol>

      <Panel className="attack-caveat">
        <span><TriangleAlert size={22} /></span>
        <div>
          <strong>What these numbers are, and are not</strong>
          <p>
            Bantam is a synthetic bank. The attack trees are a model's proposals about
            how an attack could be structured, not confirmed vulnerabilities, and the
            money is arithmetic over the editable assumptions on the{" "}
            <strong>Company financials</strong> page. The graph is the only part of
            this page extracted from real code.
          </p>
        </div>
      </Panel>

      <Panel padded={false}>
        <div className="panel-heading panel-heading-padded">
          <div>
            <p className="eyebrow">Step 1</p>
            <h2>Choose the graph and generate</h2>
          </div>
          <span className="graph-digest"><Network size={14} /> {shortId(overview.builtin_graph.graph_digest)}</span>
        </div>
        <div className="attack-generate">
          <label>
            Graph source
            <select value={snapshotId} onChange={(event) => setSnapshotId(event.target.value)}>
              <option value="">
                This repository ({overview.builtin_graph.nodes} nodes, {overview.builtin_graph.flows} flows)
              </option>
              {overview.repository_snapshots.map((snapshot) => (
                <option key={snapshot.snapshot_id} value={snapshot.snapshot_id}>
                  {snapshot.repository} @ {snapshot.resolved_commit.slice(0, 8)}
                </option>
              ))}
            </select>
          </label>
          <label>
            Attack trees to request
            <input
              type="number"
              min={overview.limits.min_scenarios}
              max={overview.limits.max_scenarios}
              value={scenarioCount}
              onChange={(event) => setScenarioCount(Number(event.target.value))}
            />
          </label>
          <label>
            Financial assumptions
            <input readOnly value={`v${overview.financials.version} · ${formatGbp(overview.financials.profile.income.annual_revenue_gbp)} revenue`} />
          </label>
          <div className="attack-generate-action">
            <Button onClick={() => generate.mutate()} disabled={generate.isPending || !overview.mistral_configured}>
              <Bot size={16} /> {generate.isPending ? "Asking Mistral…" : "Generate attack trees"}
            </Button>
            {!overview.mistral_configured && (
              <small>Set ASPIS_MISTRAL_API_KEY to enable generation. Existing analyses stay readable.</small>
            )}
          </div>
        </div>
        <div className="attack-inventory">
          <p className="eyebrow">Software the graph shows</p>
          <div className="attack-chip-row">
            {overview.software_inventory.components.map((component) => (
              <span key={component.component_id} title={component.detection_rule}>
                {component.name} · {component.detail}
              </span>
            ))}
          </div>
        </div>
      </Panel>

      {overview.scenario_sets.length > 0 && (
        <Panel padded={false}>
          <div className="panel-heading panel-heading-padded">
            <div>
              <p className="eyebrow">Saved analyses</p>
              <h2>Previous runs</h2>
            </div>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Created</th><th>Graph</th><th>Financials</th><th>Model</th><th>Simulations</th><th /></tr>
              </thead>
              <tbody>
                {overview.scenario_sets.map((entry) => (
                  <tr key={entry.scenario_set_id}>
                    <td>{formatDate(entry.created_at, true)}</td>
                    <td><code>{shortId(entry.graph_digest)}</code></td>
                    <td>v{entry.financial_profile_version}</td>
                    <td><StatusPill value={String(entry.model_status)} /></td>
                    <td>{entry.simulation_count}</td>
                    <td>
                      <Button
                        variant="ghost"
                        onClick={() => {
                          setScenarioSetId(entry.scenario_set_id);
                          setSelectedScenarioId(null);
                          setAppliedIds([]);
                        }}
                      >
                        Open <ChevronRight size={15} />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {setQuery.isLoading && <LoadingState label="Loading analysis" />}
      {scenarioSet && scenarios.length === 0 && (
        <Panel>
          <EmptyState
            title="This analysis stored no attack trees"
            description={
              scenarioSet.model_result.error_code
                ? `Mistral output was rejected (${scenarioSet.model_result.error_code}). Nothing ungrounded is ever stored.`
                : "Generate a new analysis to produce attack trees."
            }
          />
        </Panel>
      )}

      {scenarioSet && scenarios.length > 0 && (
        <>
          <Panel padded={false}>
            <div className="panel-heading panel-heading-padded">
              <div>
                <p className="eyebrow">Step 2</p>
                <h2>Choose an attack scenario</h2>
              </div>
              <span className="graph-digest">financials v{scenarioSet.financial_profile_version}</span>
            </div>
            <p className="attack-summary">{scenarioSet.model_result.scenario_set?.summary}</p>
            <div className="attack-scenario-grid">
              {scenarios.map((scenario) => (
                <ScenarioCard
                  key={scenario.scenario_id}
                  scenario={scenario}
                  selected={scenario.scenario_id === selectedScenarioId}
                  onSelect={() => {
                    setSelectedScenarioId(scenario.scenario_id);
                    setAppliedIds([]);
                  }}
                />
              ))}
            </div>
          </Panel>

          {selected && (
            <>
              <Panel padded={false}>
                <div className="panel-heading panel-heading-padded">
                  <div>
                    <p className="eyebrow">Selected scenario</p>
                    <h2>{selected.attack_tree.title}</h2>
                  </div>
                  <span className="graph-digest"><Target size={14} /> {selected.business_service}</span>
                </div>
                <div className="attack-narrative">
                  <p>{selected.narrative}</p>
                  <div className="attack-chip-row">
                    {selected.mitre_techniques.map((technique) => (
                      <a key={technique.technique_id} href={technique.url} target="_blank" rel="noopener noreferrer">
                        {technique.technique_id} · {technique.name} <small>{technique.tactic}</small>
                      </a>
                    ))}
                  </div>
                </div>
                <AttackTreeView scenario={selected} />
                <div className="attack-estimate">
                  <p className="eyebrow">How the model priced it</p>
                  <p>{selected.financials.rationale}</p>
                  <div className="attack-chip-row">
                    {selected.financials.financial_inputs_used.map((input) => (
                      <span key={input}><Coins size={13} /> {input}</span>
                    ))}
                  </div>
                </div>
              </Panel>

              <Panel padded={false}>
                <div className="panel-heading panel-heading-padded">
                  <div>
                    <p className="eyebrow">Step 3</p>
                    <h2>Simulate this attack tree</h2>
                  </div>
                  <span className="graph-digest">engine v{overview.limits.engine_version}</span>
                </div>
                <div className="attack-generate">
                  <label>
                    Simulated years
                    <input
                      type="number"
                      min={overview.limits.min_iterations}
                      max={overview.limits.max_iterations}
                      step={1000}
                      value={iterations}
                      onChange={(event) => setIterations(Number(event.target.value))}
                    />
                  </label>
                  <label>
                    Random seed
                    <input
                      type="number"
                      min={0}
                      max={4294967295}
                      value={seed}
                      onChange={(event) => setSeed(Number(event.target.value))}
                    />
                  </label>
                  <label>
                    Impact tolerance
                    <input readOnly value={formatGbp(scenarioSet.financial_profile.risk_appetite.impact_tolerance_gbp)} />
                  </label>
                  <div className="attack-generate-action">
                    <Button
                      onClick={() => simulate.mutate({ scenarioId: selected.scenario_id })}
                      disabled={simulate.isPending}
                    >
                      <Play size={16} />{" "}
                      {simulate.isPending ? "Simulating…" : `Run ${iterations.toLocaleString("en-GB")} years`}
                    </Button>
                    <small>The same seed and the same assumptions always produce the same distribution.</small>
                  </div>
                </div>
              </Panel>

              {latestSimulation && (
                <SimulationView
                  simulation={latestSimulation}
                  scenario={selected}
                  scenarioSet={scenarioSet}
                />
              )}

              {latestSimulation && (
                <Panel padded={false}>
                  <div className="panel-heading panel-heading-padded">
                    <div>
                      <p className="eyebrow">Step 4</p>
                      <h2>Remediations for this tree</h2>
                    </div>
                    <Button
                      variant="secondary"
                      onClick={() => remediate.mutate(latestSimulation.simulation_id)}
                      disabled={remediate.isPending || !overview.mistral_configured}
                    >
                      <Wrench size={16} /> {remediate.isPending ? "Asking Mistral…" : plan ? "Ask again" : "Suggest remediations"}
                    </Button>
                  </div>
                  {!plan ? (
                    <div className="panel-padded">
                      <EmptyState
                        title="No remediation advice yet"
                        description="Send this tree and its simulated results back to the model to get fixes aimed at the steps that produced the loss."
                      />
                    </div>
                  ) : plan.model_result.status !== "READY" || !plan.model_result.plan ? (
                    <div className="panel-padded">
                      <EmptyState
                        title="Remediation advice was rejected"
                        description={`The model cited something Bantam never sent (${plan.model_result.error_code ?? "provider error"}), so nothing was stored.`}
                      />
                    </div>
                  ) : (
                    <RemediationView
                      remediations={plan.model_result.plan.remediations}
                      summary={plan.model_result.plan.summary}
                      monitoring={plan.model_result.plan.monitoring}
                      appliedIds={appliedIds}
                      onToggle={(id) =>
                        setAppliedIds((current) =>
                          current.includes(id)
                            ? current.filter((entry) => entry !== id)
                            : [...current, id],
                        )
                      }
                      onSimulate={() =>
                        simulate.mutate({
                          scenarioId: selected.scenario_id,
                          planId: plan.remediation_plan_id,
                          remediationIds: appliedIds,
                        })
                      }
                      pending={simulate.isPending}
                    />
                  )}
                </Panel>
              )}

              {remediatedSimulation?.result.residual && remediatedSimulation.result.economics && (
                <ResidualView simulation={remediatedSimulation} />
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

function ScenarioCard({
  scenario,
  selected,
  onSelect,
}: {
  scenario: AttackScenario;
  selected: boolean;
  onSelect: () => void;
}) {
  const worstCase =
    scenario.financials.primary_loss.maximum_gbp + scenario.financials.secondary_loss.maximum_gbp;
  const likely =
    scenario.financials.primary_loss.most_likely_gbp + scenario.financials.secondary_loss.most_likely_gbp;
  const leaves = scenario.attack_tree.nodes.filter((node) => node.operator === "LEAF").length;
  return (
    <button
      type="button"
      className={`attack-scenario-card${selected ? " selected" : ""}`}
      onClick={onSelect}
      aria-pressed={selected}
    >
      <p className="eyebrow">{scenario.business_service}</p>
      <h3>{scenario.name}</h3>
      <div className="attack-chip-row">
        {scenario.mitre_techniques.slice(0, 3).map((technique) => (
          <span key={technique.technique_id}>{technique.technique_id}</span>
        ))}
      </div>
      <dl>
        <div>
          <dt>Typical event</dt>
          <dd>{formatCompactGbp(likely)}</dd>
        </div>
        <div>
          <dt>Worst case</dt>
          <dd>{formatCompactGbp(worstCase)}</dd>
        </div>
        <div>
          <dt>Attempts a year</dt>
          <dd>{scenario.financials.annual_attempt_frequency}</dd>
        </div>
        <div>
          <dt>Attack steps</dt>
          <dd>{leaves}</dd>
        </div>
      </dl>
    </button>
  );
}

function AttackTreeView({ scenario }: { scenario: AttackScenario }) {
  const nodes = new Map(scenario.attack_tree.nodes.map((node) => [node.attack_node_id, node]));
  const children = new Map<string, string[]>();
  scenario.attack_tree.edges.forEach((edge) => {
    const current = children.get(edge.parent_attack_node_id) ?? [];
    current.push(edge.child_attack_node_id);
    children.set(edge.parent_attack_node_id, current);
  });

  const renderBranch = (attackNodeId: string): ReactNode => {
    const node = nodes.get(attackNodeId);
    if (!node) return null;
    const childIds = children.get(attackNodeId) ?? [];
    return (
      <div className="workflow-attack-branch" key={attackNodeId}>
        <article className={`workflow-attack-node workflow-attack-node-${node.kind.toLowerCase()}`}>
          <div className="workflow-attack-node-heading">
            <span>{node.kind}</span>
            <strong>{node.operator}</strong>
          </div>
          <h3>{node.title}</h3>
          <p>{node.description}</p>
          <NodeEvidence node={node} />
        </article>
        {childIds.length > 0 && (
          <div className="workflow-attack-children">
            <div className="workflow-attack-operator">
              <GitFork size={15} />
              <span>{node.operator === "AND" ? "All branches required" : "Any branch may satisfy the parent"}</span>
            </div>
            {childIds.map(renderBranch)}
          </div>
        )}
      </div>
    );
  };

  return (
    <section className="workflow-attack-tree" aria-label={scenario.attack_tree.title}>
      {renderBranch(scenario.attack_tree.root_attack_node_id)}
      {(scenario.attack_tree.assumptions.length > 0 || scenario.attack_tree.limitations.length > 0) && (
        <div className="workflow-attack-notes">
          {scenario.attack_tree.assumptions.length > 0 && (
            <section><strong>Assumptions</strong><ul>{scenario.attack_tree.assumptions.map((item) => <li key={item}>{item}</li>)}</ul></section>
          )}
          {scenario.attack_tree.limitations.length > 0 && (
            <section><strong>Tree limitations</strong><ul>{scenario.attack_tree.limitations.map((item) => <li key={item}>{item}</li>)}</ul></section>
          )}
        </div>
      )}
    </section>
  );
}

function NodeEvidence({ node }: { node: ScenarioAttackNode }) {
  return (
    <div className="attack-node-evidence">
      {node.operator === "LEAF" && (
        <span title="Chance this single step works on one attempt">
          succeeds {formatPercent(node.success_probability)}
        </span>
      )}
      {node.operator === "LEAF" && (
        <span title="Chance Bantam notices this step while it happens">
          detected {formatPercent(node.detection_probability)}
        </span>
      )}
      {node.mitre_technique_ids.map((id) => <span key={id}>{id}</span>)}
      {node.graph_node_ids.slice(0, 2).map((id) => <code key={id}>{id}</code>)}
    </div>
  );
}

function SimulationView({
  simulation,
  scenario,
  scenarioSet,
}: {
  simulation: AttackSimulation;
  scenario: AttackScenario;
  scenarioSet: AttackScenarioSet;
}) {
  const result = simulation.result.baseline;
  const overTolerance = result.exceedance_probability > 0;
  return (
    <>
      <div className="metric-grid">
        <Panel className="metric-card">
          <div className="metric-card-head"><span>Mean annual loss</span><Coins /></div>
          <strong>{formatGbp(result.annual_loss.mean_gbp)}</strong>
          <small>
            {result.mean_as_pct_of_revenue !== null
              ? `${result.mean_as_pct_of_revenue.toFixed(2)}% of annual revenue`
              : "after insurance recovery"}
          </small>
        </Panel>
        <Panel className="metric-card">
          <div className="metric-card-head"><span>Bad year (95th percentile)</span><Activity /></div>
          <strong>{formatGbp(result.annual_loss.p95_gbp)}</strong>
          <small>Losses stay below this in 95 years out of 100</small>
        </Panel>
        <Panel className={`metric-card metric-${overTolerance ? "warning" : "positive"}`}>
          <div className="metric-card-head"><span>Above impact tolerance</span><ShieldAlert /></div>
          <strong>{formatPercent(result.exceedance_probability)}</strong>
          <small>of years exceed {formatGbp(result.impact_tolerance_gbp)}</small>
        </Panel>
        <Panel className="metric-card">
          <div className="metric-card-head"><span>Years with any loss</span><Target /></div>
          <strong>{formatPercent(result.probability_of_loss_year)}</strong>
          <small>{result.expected_events_per_year.toFixed(2)} successful events a year</small>
        </Panel>
      </div>

      <Panel padded={false}>
        <div className="panel-heading panel-heading-padded">
          <div>
            <p className="eyebrow">Simulation result</p>
            <h2>{scenario.name}</h2>
          </div>
          <span className="graph-digest">
            seed {result.seed} · {result.iterations.toLocaleString("en-GB")} years
          </span>
        </div>
        <div className="attack-charts">
          <figure>
            <figcaption>How often each size of yearly loss happened</figcaption>
            <LossHistogram result={result} />
          </figure>
          <figure>
            <figcaption>Chance of losing more than a given amount in a year</figcaption>
            <ExceedanceCurve result={result} />
          </figure>
        </div>
        <div className="table-wrap">
          <table>
            <caption>
              Which attack step carried the successful events. Bantam counts the branch the
              attacker actually used, so a fallback branch only appears when the preferred one failed.
            </caption>
            <thead>
              <tr>
                <th>Attack step</th>
                <th>Share of successful events</th>
                <th>Success chance</th>
                <th>Detection chance</th>
                <th>Graph evidence</th>
              </tr>
            </thead>
            <tbody>
              {result.attack_path_contributions.map((contribution) => (
                <tr key={contribution.attack_node_id}>
                  <td>{contribution.title}</td>
                  <td>{formatPercent(contribution.share_of_successful_events)}</td>
                  <td>{formatPercent(contribution.effective_success_probability)}</td>
                  <td>{formatPercent(contribution.effective_detection_probability)}</td>
                  <td><code>{contribution.graph_node_ids[0]}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="attack-footnote">
          <p>{result.interpretation}</p>
          <p>
            Gross loss before insurance averaged {formatGbp(result.gross_mean_annual_loss_gbp)} a year, of which{" "}
            {formatGbp(result.insurance_recovery_mean_gbp)} was recovered under the{" "}
            {formatGbp(scenarioSet.financial_profile.insurance.cyber_cover_gbp)} cyber cover with a{" "}
            {formatGbp(scenarioSet.financial_profile.insurance.retention_gbp)} retention.
          </p>
        </div>
      </Panel>
    </>
  );
}

function LossHistogram({ result }: { result: SimulationResult }) {
  const width = 560;
  const height = 240;
  const margin = { left: 46, right: 16, top: 16, bottom: 34 };
  const chartWidth = width - margin.left - margin.right;
  const chartHeight = height - margin.top - margin.bottom;
  const bins = result.histogram.bins;
  const maxCount = Math.max(...bins.map((bin) => bin.count), 1);
  const barWidth = chartWidth / bins.length;
  const toleranceX =
    margin.left +
    Math.min(1, result.impact_tolerance_gbp / Math.max(result.histogram.ceiling_gbp, 1)) * chartWidth;
  return (
    <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Distribution of simulated annual losses">
      {bins.map((bin, index) => (
        <rect
          key={bin.lower_gbp}
          className="histogram-bar"
          x={margin.left + index * barWidth + 1}
          y={margin.top + chartHeight - (bin.count / maxCount) * chartHeight}
          width={Math.max(1, barWidth - 2)}
          height={(bin.count / maxCount) * chartHeight}
        />
      ))}
      <line
        className="histogram-marker tolerance"
        x1={toleranceX}
        y1={margin.top}
        x2={toleranceX}
        y2={margin.top + chartHeight}
      />
      <line
        className="histogram-axis"
        x1={margin.left}
        y1={margin.top + chartHeight}
        x2={margin.left + chartWidth}
        y2={margin.top + chartHeight}
      />
      {[0, 0.5, 1].map((fraction) => (
        <text
          key={fraction}
          className="histogram-label"
          x={margin.left + fraction * chartWidth}
          y={height - 12}
          textAnchor={fraction === 0 ? "start" : fraction === 1 ? "end" : "middle"}
        >
          {formatCompactGbp(fraction * result.histogram.ceiling_gbp)}
        </text>
      ))}
      <text className="histogram-label" x={4} y={margin.top + 10}>years</text>
    </svg>
  );
}

function ExceedanceCurve({ result }: { result: SimulationResult }) {
  const width = 560;
  const height = 240;
  const margin = { left: 46, right: 16, top: 16, bottom: 34 };
  const chartWidth = width - margin.left - margin.right;
  const chartHeight = height - margin.top - margin.bottom;
  const curve = result.loss_exceedance_curve;
  const ceiling = Math.max(curve[curve.length - 1]?.loss_gbp ?? 1, 1);
  const points = curve
    .map((point) => {
      const x = margin.left + (point.loss_gbp / ceiling) * chartWidth;
      const y = margin.top + chartHeight - point.annual_probability * chartHeight;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Loss exceedance curve">
      {[0, 0.25, 0.5, 0.75, 1].map((fraction) => (
        <line
          key={fraction}
          className="histogram-grid"
          x1={margin.left}
          y1={margin.top + fraction * chartHeight}
          x2={margin.left + chartWidth}
          y2={margin.top + fraction * chartHeight}
        />
      ))}
      <polyline className="exceedance-line" points={points} />
      <line
        className="histogram-axis"
        x1={margin.left}
        y1={margin.top + chartHeight}
        x2={margin.left + chartWidth}
        y2={margin.top + chartHeight}
      />
      {[0, 0.5, 1].map((fraction) => (
        <text
          key={fraction}
          className="histogram-label"
          x={margin.left + fraction * chartWidth}
          y={height - 12}
          textAnchor={fraction === 0 ? "start" : fraction === 1 ? "end" : "middle"}
        >
          {formatCompactGbp(fraction * ceiling)}
        </text>
      ))}
      {[0, 0.5, 1].map((fraction) => (
        <text
          key={`y${fraction}`}
          className="histogram-label"
          x={margin.left - 6}
          y={margin.top + (1 - fraction) * chartHeight + 4}
          textAnchor="end"
        >
          {formatPercent(fraction, 0)}
        </text>
      ))}
    </svg>
  );
}

function RemediationView({
  remediations,
  summary,
  monitoring,
  appliedIds,
  onToggle,
  onSimulate,
  pending,
}: {
  remediations: Remediation[];
  summary: string;
  monitoring: string[];
  appliedIds: string[];
  onToggle: (id: string) => void;
  onSimulate: () => void;
  pending: boolean;
}) {
  const totalCost = remediations
    .filter((item) => appliedIds.includes(item.remediation_id))
    .reduce((total, item) => total + item.estimated_cost_gbp + item.annual_run_cost_gbp, 0);
  return (
    <>
      <p className="attack-summary">{summary}</p>
      <div className="remediation-list">
        {remediations.map((remediation) => (
          <label
            key={remediation.remediation_id}
            className={`remediation-card priority-${remediation.priority.toLowerCase()}`}
          >
            <input
              type="checkbox"
              checked={appliedIds.includes(remediation.remediation_id)}
              onChange={() => onToggle(remediation.remediation_id)}
            />
            <div>
              <div className="remediation-head">
                <strong>{remediation.title}</strong>
                <StatusPill value={remediation.priority} />
              </div>
              <p>{remediation.description}</p>
              <p className="remediation-rationale">{remediation.evidence_rationale}</p>
              <div className="attack-chip-row">
                <span>{formatGbp(remediation.estimated_cost_gbp)} to build</span>
                <span>{formatGbp(remediation.annual_run_cost_gbp)} a year to run</span>
                <span>{remediation.implementation_effort.toLowerCase()} of effort</span>
                <span>cuts success {formatPercent(remediation.success_probability_reduction)}</span>
                <span>raises detection {formatPercent(remediation.detection_probability_uplift)}</span>
                {remediation.mitre_mitigation_ids.map((id, index) => (
                  <a key={id} href={remediation.mitre_mitigation_urls[index]} target="_blank" rel="noopener noreferrer">{id}</a>
                ))}
                {remediation.software_component_ids.map((id) => <span key={id}>{id}</span>)}
              </div>
              <p className="remediation-residual">Still remaining: {remediation.residual_risk_note}</p>
            </div>
          </label>
        ))}
      </div>
      {monitoring.length > 0 && (
        <div className="panel-padded">
          <p className="eyebrow">Monitoring the model suggests</p>
          <ul className="financial-notes">{monitoring.map((item) => <li key={item}>{item}</li>)}</ul>
        </div>
      )}
      <div className="remediation-actions">
        <div>
          <strong>{appliedIds.length} selected</strong>
          <small>{formatGbp(totalCost)} in first-year cost</small>
        </div>
        <Button onClick={onSimulate} disabled={appliedIds.length === 0 || pending}>
          <RefreshCw size={16} /> {pending ? "Re-running…" : "Re-run with these fixes"}
        </Button>
      </div>
    </>
  );
}

function ResidualView({ simulation }: { simulation: AttackSimulation }) {
  const { baseline, residual, economics } = simulation.result;
  if (!residual || !economics) return null;
  return (
    <Panel padded={false}>
      <div className="panel-heading panel-heading-padded">
        <div>
          <p className="eyebrow">What the fixes are worth</p>
          <h2>Residual risk after {simulation.applied_remediation_ids.length} remediations</h2>
        </div>
        <span className="graph-digest"><ListChecks size={14} /> same seed {residual.seed}</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>Measure</th><th>Before</th><th>After</th><th>Change</th></tr>
          </thead>
          <tbody>
            <tr>
              <td>Mean annual loss</td>
              <td>{formatGbp(baseline.annual_loss.mean_gbp)}</td>
              <td>{formatGbp(residual.annual_loss.mean_gbp)}</td>
              <td>{formatGbp(-economics.annual_loss_reduction_gbp)}</td>
            </tr>
            <tr>
              <td>Bad year (95th percentile)</td>
              <td>{formatGbp(baseline.annual_loss.p95_gbp)}</td>
              <td>{formatGbp(residual.annual_loss.p95_gbp)}</td>
              <td>{formatGbp(residual.annual_loss.p95_gbp - baseline.annual_loss.p95_gbp)}</td>
            </tr>
            <tr>
              <td>Years above impact tolerance</td>
              <td>{formatPercent(baseline.exceedance_probability)}</td>
              <td>{formatPercent(residual.exceedance_probability)}</td>
              <td>{formatPercent(economics.exceedance_change)}</td>
            </tr>
            <tr>
              <td>Successful events a year</td>
              <td>{baseline.expected_events_per_year.toFixed(2)}</td>
              <td>{residual.expected_events_per_year.toFixed(2)}</td>
              <td>{(residual.expected_events_per_year - baseline.expected_events_per_year).toFixed(2)}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div className="metric-grid">
        <Panel className="metric-card">
          <div className="metric-card-head"><span>First-year cost</span><Coins /></div>
          <strong>{formatGbp(economics.first_year_cost_gbp)}</strong>
          <small>{formatGbp(economics.annual_run_cost_gbp)} a year to run</small>
        </Panel>
        <Panel className="metric-card">
          <div className="metric-card-head"><span>Annual loss avoided</span><Activity /></div>
          <strong>{formatGbp(economics.annual_loss_reduction_gbp)}</strong>
          <small>difference between two identically seeded runs</small>
        </Panel>
        <Panel className="metric-card">
          <div className="metric-card-head"><span>Payback</span><Target /></div>
          <strong>
            {economics.payback_years === null
              ? "No payback"
              : economics.payback_years < 2
                ? `${(economics.payback_years * 12).toFixed(1)} months`
                : `${economics.payback_years.toFixed(1)} years`}
          </strong>
          <small>build cost ÷ net annual benefit</small>
        </Panel>
      </div>
      <div className="attack-footnote"><p>{economics.basis}</p></div>
    </Panel>
  );
}
