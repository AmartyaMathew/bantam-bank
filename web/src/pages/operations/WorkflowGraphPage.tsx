import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowDown,
  Braces,
  Bot,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  FileCode2,
  GitBranch,
  GitFork,
  Network,
  Plus,
  RefreshCw,
  Save,
  ShieldCheck,
  Target,
  Trash2,
} from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { api } from "../../api";
import {
  Button,
  ErrorState,
  LoadingState,
  PageHeader,
  Panel,
  StatusPill,
  useToast,
} from "../../components/ui";
import type {
  CustomWorkflow,
  DefaultWorkflow,
  RepositoryAttackTree,
  RepositoryGraphSourceRequest,
  WorkflowDraft,
  WorkflowGraphNode,
  WorkflowGraphOverview,
  WorkflowValidation,
} from "../../types";

const ACTORS = [
  "PUBLIC",
  "CUSTOMER",
  "BANK_ADMIN",
  "RISK_ANALYST",
  "COMPLIANCE_AUDITOR",
  "ASPIS_AUDITOR",
  "ASPIS_ADMIN",
  "SYSTEM",
];

interface DisplayFlow {
  id: string;
  name: string;
  description: string;
  actorRoles: string[];
  nodeIds: string[];
  documentationPath: string | null;
  documentation: string | null;
  source: "generated" | "custom";
  valid: boolean;
  stale: boolean;
}

const emptyDraft = (): WorkflowDraft => ({
  name: "",
  description: "",
  actor_role: "BANK_ADMIN",
  node_ids: [],
});

const defaultRepositorySource = (): RepositoryGraphSourceRequest => ({
  repository: "aam57689/bank",
  ref: "main",
  root_path: "",
  language: "python",
  send_to_mistral: true,
});

function displayFlows(graph: WorkflowGraphOverview): DisplayFlow[] {
  const defaults = graph.default_flows.map((flow: DefaultWorkflow) => ({
    id: flow.flow_id,
    name: flow.name,
    description: flow.description,
    actorRoles: flow.actor_roles,
    nodeIds: flow.node_ids,
    documentationPath: flow.documentation_path,
    documentation: flow.documentation,
    source: "generated" as const,
    valid: true,
    stale: false,
  }));
  const custom = graph.custom_flows.map((flow: CustomWorkflow) => ({
    id: `custom:${flow.workflow_id}`,
    name: flow.name,
    description: flow.description,
    actorRoles: [flow.actor_role],
    nodeIds: flow.node_ids,
    documentationPath: flow.documentation_path,
    documentation: flow.documentation,
    source: "custom" as const,
    valid: flow.valid,
    stale: flow.stale,
  }));
  return [...defaults, ...custom];
}

export function WorkflowGraphPage() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ["workflow-graph"], queryFn: api.workflowGraph });
  const sourcesQuery = useQuery({
    queryKey: ["repository-graph-sources"],
    queryFn: api.repositoryGraphSources,
  });
  const [repositoryGraph, setRepositoryGraph] = useState<WorkflowGraphOverview | null>(null);
  const [sourceDraft, setSourceDraft] = useState<RepositoryGraphSourceRequest>(defaultRepositorySource);
  const [recentSnapshotId, setRecentSnapshotId] = useState("");
  const [mode, setMode] = useState<"explore" | "build">("explore");
  const [selectedFlowId, setSelectedFlowId] = useState("");
  const [selectedNodeId, setSelectedNodeId] = useState("");
  const [density, setDensity] = useState<"all" | "overview">("all");
  const [draft, setDraft] = useState<WorkflowDraft>(emptyDraft);
  const [nextNodeId, setNextNodeId] = useState("");
  const [validation, setValidation] = useState<WorkflowValidation | null>(null);

  const graph = repositoryGraph ?? query.data;
  const nodesById = useMemo(
    () => new Map((graph?.nodes ?? []).map((node) => [node.id, node])),
    [graph],
  );
  const flows = useMemo(() => graph ? displayFlows(graph) : [], [graph]);
  const preferredFlow = flows.find((flow) => flow.name === "Register a customer") ?? flows[0];
  const selectedFlow = flows.find((flow) => flow.id === selectedFlowId) ?? preferredFlow;
  const selectedNode = selectedFlow?.nodeIds.includes(selectedNodeId)
    ? (nodesById.get(selectedNodeId) ?? nodesById.get(selectedFlow.nodeIds[0]))
    : (selectedFlow ? nodesById.get(selectedFlow.nodeIds[0]) : undefined);
  const flowNodeIds = useMemo(() => {
    const ids = selectedFlow?.nodeIds ?? [];
    if (density === "all") return ids;
    return ids.filter((id) => {
      const kind = nodesById.get(id)?.kind;
      return kind === "route" || kind === "function" || kind === "transaction"
        || kind === "lock" || kind === "effect" || kind === "terraform_resource"
        || kind === "terraform_module" || kind === "terraform_output";
    });
  }, [density, nodesById, selectedFlow]);

  const allowedSuccessors = useMemo(() => {
    if (!graph || draft.node_ids.length === 0) return [];
    const last = draft.node_ids[draft.node_ids.length - 1];
    const ids = graph.edges
      .filter((edge) => edge.source === last && (
        graph.snapshot_id
          ? true
          : ["next", "calls", "handled_by"].includes(edge.type)
      ))
      .map((edge) => edge.target)
      .filter((id, index, values) => values.indexOf(id) === index && !draft.node_ids.includes(id));
    return ids.map((id) => nodesById.get(id)).filter((node): node is WorkflowGraphNode => Boolean(node));
  }, [draft.node_ids, graph, nodesById]);

  const startNodes = useMemo(() => {
    if (!graph) return [];
    if (graph.snapshot_id) {
      const ids = new Set(
        graph.default_flows
          .filter((flow) => flow.actor_roles.includes(draft.actor_role))
          .map((flow) => flow.node_ids[0])
          .filter(Boolean),
      );
      return graph.nodes.filter((node) => ids.has(node.id));
    }
    return graph.nodes.filter((node) => {
      if (draft.actor_role === "SYSTEM") return node.kind === "function";
      return node.kind === "route" && (node.roles ?? []).includes(draft.actor_role);
    });
  }, [draft.actor_role, graph]);

  const availableActors = useMemo(() => {
    if (!graph?.snapshot_id) return ACTORS;
    const actors = graph.default_flows.flatMap((flow) => flow.actor_roles);
    return actors.filter((actor, index) => actors.indexOf(actor) === index);
  }, [graph]);

  const validateMutation = useMutation({
    mutationFn: (input: WorkflowDraft) => graph?.snapshot_id
      ? api.validateRepositoryWorkflow(graph.snapshot_id, input)
      : api.validateWorkflow(input),
    onSuccess: (result) => {
      setValidation(result);
      if (result.valid) toast.success("Workflow passes", "Every node and transition exists in the extracted graph.");
    },
    onError: (error) => toast.error("Validation failed", error),
  });
  const saveMutation = useMutation({
    mutationFn: (input: WorkflowDraft) => graph?.snapshot_id
      ? api.createRepositoryWorkflow(graph.snapshot_id, input)
      : api.createWorkflow(input),
    onSuccess: async (created) => {
      if (graph?.snapshot_id) {
        const refreshed = await api.repositoryGraph(graph.snapshot_id);
        setRepositoryGraph(refreshed);
        await queryClient.invalidateQueries({ queryKey: ["repository-graph-sources"] });
      } else {
        await queryClient.invalidateQueries({ queryKey: ["workflow-graph"] });
      }
      setSelectedFlowId(`custom:${created.workflow_id}`);
      setMode("explore");
      toast.success("Workflow saved", "The validated composition is now available in the explorer.");
    },
    onError: (error) => toast.error("Workflow was not saved", error),
  });

  const activateRepositoryGraph = (generated: WorkflowGraphOverview) => {
    setRepositoryGraph(generated);
    setSelectedFlowId("");
    setSelectedNodeId("");
    setValidation(null);
    setDraft({ ...emptyDraft(), actor_role: generated.default_flows[0]?.actor_roles[0] ?? "SYSTEM" });
    setMode("explore");
  };

  const generateMutation = useMutation({
    mutationFn: api.generateRepositoryGraph,
    onSuccess: async (generated) => {
      activateRepositoryGraph(generated);
      await queryClient.invalidateQueries({ queryKey: ["repository-graph-sources"] });
      toast.success(
        "Repository graph generated",
        `${generated.repository}@${generated.resolved_commit?.slice(0, 12)} was parsed deterministically.`,
      );
    },
    onError: (error) => toast.error("Repository graph failed", error),
  });

  const generateDefaultsMutation = useMutation({
    mutationFn: async () => {
      const sources = sourcesQuery.data?.default_sources ?? [];
      if (sources.length === 0) throw new Error("No default repository sources are configured.");
      const generated: WorkflowGraphOverview[] = [];
      const failures: string[] = [];
      for (const source of sources) {
        try {
          generated.push(await api.generateRepositoryGraph({
            repository: source.repository,
            ref: source.ref,
            root_path: source.root_path,
            language: source.language,
            send_to_mistral: source.send_to_mistral,
          }));
        } catch (error) {
          failures.push(`${source.name}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      if (generated.length === 0) throw new Error(failures.join(" "));
      return { generated, failures };
    },
    onSuccess: async ({ generated, failures }) => {
      const application = generated.find((item) => item.repository === "aam57689/bank") ?? generated[0];
      activateRepositoryGraph(application);
      await queryClient.invalidateQueries({ queryKey: ["repository-graph-sources"] });
      if (failures.length > 0) {
        toast.error("Some default graphs failed", failures.join(" "));
      } else {
        toast.success(
          "Default repository graphs generated",
          "Bantam and its Terraform infrastructure are now available as pinned snapshots.",
        );
      }
    },
    onError: (error) => toast.error("Default repository graphs failed", error),
  });

  const loadSnapshotMutation = useMutation({
    mutationFn: api.repositoryGraph,
    onSuccess: (snapshot) => {
      setRepositoryGraph(snapshot);
      setSelectedFlowId("");
      setSelectedNodeId("");
      setValidation(null);
      setDraft({ ...emptyDraft(), actor_role: snapshot.default_flows[0]?.actor_roles[0] ?? "SYSTEM" });
      setMode("explore");
    },
    onError: (error) => toast.error("Snapshot could not be loaded", error),
  });

  if (query.isLoading) return <LoadingState label="Building workflow explorer" />;
  if (query.error || !graph) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;

  const useSelectedAsDraft = () => {
    if (!selectedFlow) return;
    setDraft({
      name: `${selectedFlow.name} — custom path`,
      description: `Custom composition based on ${selectedFlow.name}.`,
      actor_role: selectedFlow.actorRoles[0] ?? "BANK_ADMIN",
      node_ids: selectedFlow.nodeIds.slice(0, 160),
    });
    setValidation(null);
    setNextNodeId("");
    setMode("build");
  };

  const updateDraft = (patch: Partial<WorkflowDraft>) => {
    setDraft((current) => ({ ...current, ...patch }));
    setValidation(null);
  };

  return (
    <div className="page-stack workflow-page">
      <PageHeader
        eyebrow="Deterministic architecture map"
        title="Workflow knowledge graph"
        description="Explore code-backed Bantam actions or compose a custom path that can only use extracted nodes and valid transitions."
        action={(
          <div className="workflow-mode-switch" role="group" aria-label="Workflow mode">
            <button type="button" aria-pressed={mode === "explore"} className={mode === "explore" ? "active" : ""} onClick={() => setMode("explore")}><Network size={16} /> Explore</button>
            <button type="button" aria-pressed={mode === "build"} className={mode === "build" ? "active" : ""} onClick={() => setMode("build")}><GitBranch size={16} /> Build</button>
          </div>
        )}
      />

      <Panel className="workflow-source-panel">
        <div className="workflow-source-heading">
          <div>
            <p className="eyebrow">Repository source</p>
            <h2>Generate from a pinned GitHub snapshot</h2>
            <p>Python and Terraform are parsed without checkout or execution. Private repositories use the server-side read token.</p>
          </div>
          <div className="workflow-source-status">
            <StatusPill value={sourcesQuery.data?.github_token_configured ? "GITHUB READY" : "PUBLIC ONLY"} />
            <StatusPill value={sourcesQuery.data?.mistral_configured ? "MISTRAL READY" : "MISTRAL OFF"} />
          </div>
        </div>

        <div className="workflow-default-sources">
          <button
            type="button"
            className={!repositoryGraph ? "active" : ""}
            onClick={() => {
              setRepositoryGraph(null);
              setSelectedFlowId("");
              setSelectedNodeId("");
              setValidation(null);
            }}
          >
            <ShieldCheck size={18} />
            <span><strong>Committed Bantam catalog</strong><small>Build-time verified baseline</small></span>
          </button>
          {(sourcesQuery.data?.default_sources ?? []).map((source) => (
            <button
              type="button"
              key={source.source_id}
              onClick={() => setSourceDraft({
                repository: source.repository,
                ref: source.ref,
                root_path: source.root_path,
                language: source.language,
                send_to_mistral: true,
              })}
            >
              <GitBranch size={18} />
              <span><strong>{source.name}</strong><small>{source.repository}{source.root_path ? `/${source.root_path}` : ""}{source.private ? " · private" : ""}</small></span>
            </button>
          ))}
        </div>

        <div className="workflow-default-action">
          <Button
            variant="secondary"
            disabled={generateDefaultsMutation.isPending || sourcesQuery.isLoading}
            onClick={() => generateDefaultsMutation.mutate()}
          >
            <RefreshCw size={16} className={generateDefaultsMutation.isPending ? "spin" : ""} />
            {generateDefaultsMutation.isPending ? "Generating default set…" : "Generate Bantam + Terraform defaults"}
          </Button>
          <small>Creates one immutable snapshot per repository so each graph keeps its own commit and provenance.</small>
        </div>

        <div className="workflow-source-form">
          <label>
            GitHub repository
            <input
              value={sourceDraft.repository}
              maxLength={220}
              onChange={(event) => setSourceDraft((current) => ({ ...current, repository: event.target.value }))}
              placeholder="owner/repository or https://github.com/owner/repository"
            />
          </label>
          <label>
            Ref
            <input value={sourceDraft.ref} maxLength={180} onChange={(event) => setSourceDraft((current) => ({ ...current, ref: event.target.value }))} placeholder="main" />
          </label>
          <label>
            Repository path
            <input value={sourceDraft.root_path} maxLength={500} onChange={(event) => setSourceDraft((current) => ({ ...current, root_path: event.target.value }))} placeholder="Optional subdirectory, e.g. bank" />
          </label>
          <label>
            Parser
            <select value={sourceDraft.language} onChange={(event) => setSourceDraft((current) => ({ ...current, language: event.target.value as RepositoryGraphSourceRequest["language"] }))}>
              <option value="auto">Detect Python / Terraform</option>
              <option value="python">Python AST</option>
              <option value="terraform">Terraform HCL</option>
            </select>
          </label>
          <label className="workflow-model-toggle">
            <input type="checkbox" checked={sourceDraft.send_to_mistral} onChange={(event) => setSourceDraft((current) => ({ ...current, send_to_mistral: event.target.checked }))} />
            <span><strong>Send redacted graph projection to Mistral</strong><small>Raw source and GitHub credentials never cross the model boundary.</small></span>
          </label>
          <Button disabled={generateMutation.isPending} onClick={() => generateMutation.mutate(sourceDraft)}>
            <RefreshCw size={16} className={generateMutation.isPending ? "spin" : ""} />
            {generateMutation.isPending ? "Fetching and generating…" : "Generate repository graph"}
          </Button>
        </div>

        {(sourcesQuery.data?.recent_snapshots.length ?? 0) > 0 && (
          <div className="workflow-recent-snapshots">
            <label>
              Recent pinned snapshot
              <select value={recentSnapshotId} onChange={(event) => setRecentSnapshotId(event.target.value)}>
                <option value="">Select a previous graph</option>
                {sourcesQuery.data?.recent_snapshots.map((snapshot) => (
                  <option key={snapshot.snapshot_id} value={snapshot.snapshot_id}>
                    {snapshot.repository}{snapshot.root_path ? `/${snapshot.root_path}` : ""} · {snapshot.resolved_commit.slice(0, 12)}
                  </option>
                ))}
              </select>
            </label>
            <Button variant="secondary" disabled={!recentSnapshotId || loadSnapshotMutation.isPending} onClick={() => loadSnapshotMutation.mutate(recentSnapshotId)}>Load snapshot</Button>
          </div>
        )}
      </Panel>

      <div className="workflow-integrity-bar">
        <ShieldCheck size={20} />
        <div>
          <strong>{graph.snapshot_id ? "Deterministic graph; optional AI attack analysis" : "Generated without an LLM"}</strong>
          <span>{graph.snapshot_id
            ? `${graph.repository}@${graph.resolved_commit?.slice(0, 12)} · ${graph.language} · Mistral cannot alter graph facts`
            : "Python AST + route decorators + parameterised SQL + version-controlled flow documentation"}</span>
        </div>
        <code>{graph.graph_digest.slice(0, 12)}</code>
      </div>

      {graph.model && <RepositoryNarrative model={graph.model} />}

      {mode === "explore" ? (
        <>
          <Panel className="workflow-toolbar">
            <label>
              Action workflow
              <select
                value={selectedFlow?.id ?? ""}
                onChange={(event) => {
                  setSelectedFlowId(event.target.value);
                  const flow = flows.find((item) => item.id === event.target.value);
                  setSelectedNodeId(flow?.nodeIds[0] ?? "");
                }}
              >
                <optgroup label="Generated defaults">
                  {flows.filter((flow) => flow.source === "generated").map((flow) => <option key={flow.id} value={flow.id}>{flow.name} · {flow.actorRoles.join(" / ")}</option>)}
                </optgroup>
                {flows.some((flow) => flow.source === "custom") && (
                  <optgroup label="Custom workflows">
                    {flows.filter((flow) => flow.source === "custom").map((flow) => <option key={flow.id} value={flow.id}>{flow.name}{flow.stale ? " · stale" : ""}</option>)}
                  </optgroup>
                )}
              </select>
            </label>
            <label>
              Detail
              <select value={density} onChange={(event) => setDensity(event.target.value as "all" | "overview")}>
                <option value="all">All checks and data effects</option>
                <option value="overview">Functions and durable effects</option>
              </select>
            </label>
            <div className="workflow-toolbar-summary">
              <span><strong>{flowNodeIds.length}</strong> visible nodes</span>
              <span><strong>{selectedFlow?.actorRoles.join(" / ")}</strong> actor</span>
              {selectedFlow?.source === "custom" && <StatusPill value={selectedFlow.valid ? "PASS" : "FAIL"} />}
            </div>
            <Button variant="secondary" onClick={useSelectedAsDraft}><GitBranch size={16} /> Use as custom flow</Button>
          </Panel>

          {selectedFlow && (
            <div className="workflow-layout">
              <Panel className="workflow-canvas-panel" padded={false}>
                <div className="workflow-canvas-heading">
                  <div><p className="eyebrow">{selectedFlow.source}</p><h2>{selectedFlow.name}</h2><p>{selectedFlow.description}</p></div>
                  <StatusPill value={selectedFlow.stale ? "STALE" : "CURRENT"} />
                </div>
                <div className="workflow-dual-canvas">
                  <FlowLane
                    title="Process flow"
                    nodeIds={flowNodeIds}
                    nodes={nodesById}
                    selectedId={selectedNode?.id ?? ""}
                    mode="process"
                    onSelect={setSelectedNodeId}
                  />
                  <FlowLane
                    title="Code flow"
                    nodeIds={flowNodeIds}
                    nodes={nodesById}
                    selectedId={selectedNode?.id ?? ""}
                    mode="code"
                    onSelect={setSelectedNodeId}
                  />
                </div>
              </Panel>
              <NodeInspector node={selectedNode} />
            </div>
          )}

          {selectedFlow?.documentation && (
            <Panel className="workflow-documentation">
              <div className="section-heading">
                <div><p className="eyebrow">Flow documentation</p><h2>{selectedFlow.documentationPath ?? "Generated from extracted source"}</h2></div>
                <FileCode2 size={22} />
              </div>
              <pre>{selectedFlow.documentation}</pre>
            </Panel>
          )}
        </>
      ) : (
        <Panel className="workflow-builder">
          <div className="workflow-builder-heading">
            <div><p className="eyebrow">Custom composition</p><h2>Build a path through extracted code</h2><p>The builder offers only transitions present in the deterministic catalogue. Server validation remains authoritative.</p></div>
            <Button variant="ghost" onClick={() => { setDraft({ ...emptyDraft(), actor_role: availableActors[0] ?? "SYSTEM" }); setValidation(null); setNextNodeId(""); }}><Trash2 size={16} /> Clear</Button>
          </div>
          <div className="workflow-builder-form">
            <label>Name<input value={draft.name} maxLength={100} onChange={(event) => updateDraft({ name: event.target.value })} placeholder="Example: Customer onboarding review" /></label>
            <label>Actor<select value={draft.actor_role} onChange={(event) => { updateDraft({ actor_role: event.target.value, node_ids: [] }); setNextNodeId(""); }}>{availableActors.map((actor) => <option value={actor} key={actor}>{actor}</option>)}</select></label>
            <label className="workflow-description-field">Description<textarea value={draft.description} maxLength={500} rows={2} onChange={(event) => updateDraft({ description: event.target.value })} placeholder="Why this code path matters" /></label>
          </div>

          <div className="workflow-builder-controls">
            {draft.node_ids.length === 0 ? (
              <label>
                Start at an extracted entry point
                <select value="" onChange={(event) => event.target.value && updateDraft({ node_ids: [event.target.value] })}>
                  <option value="">Select an extracted route, function, or Terraform target</option>
                  {startNodes.map((node) => <option key={node.id} value={node.id}>{node.label} · {node.signature ?? node.symbol}</option>)}
                </select>
              </label>
            ) : (
              <>
                <label>
                  Valid next node
                  <select value={nextNodeId} onChange={(event) => setNextNodeId(event.target.value)}>
                    <option value="">{allowedSuccessors.length ? "Select the next extracted transition" : "No unused outgoing transitions"}</option>
                    {allowedSuccessors.map((node) => <option key={node.id} value={node.id}>{node.label} · {node.kind}</option>)}
                  </select>
                </label>
                <Button variant="secondary" disabled={!nextNodeId} onClick={() => { updateDraft({ node_ids: [...draft.node_ids, nextNodeId] }); setNextNodeId(""); }}><Plus size={16} /> Add step</Button>
                <Button variant="ghost" onClick={() => { updateDraft({ node_ids: draft.node_ids.slice(0, -1) }); setNextNodeId(""); }}><Trash2 size={16} /> Remove last</Button>
              </>
            )}
          </div>

          <div className="workflow-builder-path">
            {draft.node_ids.length === 0 ? <p>Select an entry point to begin.</p> : draft.node_ids.map((nodeId, index) => {
              const node = nodesById.get(nodeId);
              return <div key={`${nodeId}:${index}`}><span>{index + 1}</span><div><strong>{node?.label ?? nodeId}</strong><code>{node?.signature ?? node?.symbol ?? nodeId}</code></div>{index < draft.node_ids.length - 1 && <ArrowDown size={16} />}</div>;
            })}
          </div>

          {validation && (
            <div className={`workflow-validation ${validation.valid ? "pass" : "fail"}`} role="status">
              {validation.valid ? <CheckCircle2 size={21} /> : <CircleAlert size={21} />}
              <div><strong>{validation.valid ? "PASS — valid code path" : "FAIL — workflow rejected"}</strong>{validation.errors.length === 0 ? <span>All nodes exist, the actor is allowed, and every adjacent edge was extracted.</span> : <ul>{validation.errors.map((error) => <li key={`${error.code}:${error.message}`}>{error.code}: {error.message}</li>)}</ul>}</div>
            </div>
          )}

          <div className="workflow-builder-actions">
            <Button variant="secondary" disabled={draft.node_ids.length < (graph.snapshot_id ? 1 : 2) || validateMutation.isPending} onClick={() => validateMutation.mutate(draft)}><ShieldCheck size={16} /> Validate deterministically</Button>
            <Button disabled={!validation?.valid || saveMutation.isPending} onClick={() => saveMutation.mutate(draft)}><Save size={16} /> Save valid workflow</Button>
          </div>
        </Panel>
      )}
    </div>
  );
}

function RepositoryNarrative({
  model,
}: {
  model: NonNullable<WorkflowGraphOverview["model"]>;
}) {
  const explanation = model.explanation;
  return (
    <Panel className="workflow-model-panel">
      <div className="workflow-model-heading">
        <div>
          <p className="eyebrow">Mistral security analysis</p>
          <h2>Graph-grounded attack tree</h2>
          <p>The model proposes potential attack paths, not confirmed vulnerabilities. Every tree node cites deterministic graph evidence.</p>
        </div>
        <div><Bot size={21} /><StatusPill value={model.status} /></div>
      </div>
      {explanation ? (
        <>
          <p className="workflow-model-summary">{explanation.summary}</p>
          {explanation.attack_tree
            ? <AttackTree tree={explanation.attack_tree} />
            : <p className="workflow-model-unavailable">This legacy snapshot predates attack-tree generation. Generate a fresh snapshot to add one.</p>}
          <div className="workflow-model-grid">
            {explanation.architecture.map((layer) => (
              <section key={`${layer.name}:${layer.node_ids.join(":")}`}>
                <strong>{layer.name}</strong>
                <p>{layer.explanation}</p>
                {layer.node_ids.length > 0 && <code>{layer.node_ids.join(" · ")}</code>}
              </section>
            ))}
          </div>
          <div className="workflow-model-details">
            <section><strong>Suggested reading order</strong><ol>{explanation.reading_order.map((item) => <li key={item}>{item}</li>)}</ol></section>
            {explanation.limitations.length > 0 && <section><strong>Model-stated limitations</strong><ul>{explanation.limitations.map((item) => <li key={item}>{item}</li>)}</ul></section>}
          </div>
        </>
      ) : (
        <p className="workflow-model-unavailable">
          {model.status === "DISABLED"
            ? "Configure ASPIS_MISTRAL_API_KEY to add the optional attack tree. The deterministic graph remains fully available."
            : model.status === "SKIPPED"
              ? "This snapshot was generated without sending a graph projection to Mistral."
              : `Mistral attack analysis was unavailable (${model.error_code ?? "provider error"}). The deterministic graph was still saved.`}
        </p>
      )}
      {model.provenance && (
        <div className="workflow-model-provenance">
          <span>{model.provenance.projection.complete ? "Complete graph projection" : "Bounded graph projection"}</span>
          <code>{model.provenance.projection.included_nodes} nodes · {model.provenance.projection.included_edges} edges · {model.provenance.request_sha256.slice(0, 12)}</code>
        </div>
      )}
    </Panel>
  );
}

function AttackTree({ tree }: { tree: RepositoryAttackTree }) {
  const nodes = new Map(tree.nodes.map((node) => [node.attack_node_id, node]));
  const children = new Map<string, string[]>();
  tree.edges.forEach((edge) => {
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
          <code>{node.graph_node_ids.join(" · ")}</code>
        </article>
        {childIds.length > 0 && (
          <div className="workflow-attack-children">
            <div className="workflow-attack-operator"><GitFork size={15} /><span>{node.operator === "AND" ? "All branches required" : "Any branch may satisfy the parent"}</span></div>
            {childIds.map(renderBranch)}
          </div>
        )}
      </div>
    );
  };

  return (
    <section className="workflow-attack-tree" aria-label={tree.title}>
      <div className="workflow-attack-tree-heading">
        <div><Target size={18} /><strong>{tree.title}</strong></div>
        <span>{tree.nodes.length} nodes · {tree.edges.length} branches</span>
      </div>
      {renderBranch(tree.root_attack_node_id)}
      {(tree.assumptions.length > 0 || tree.limitations.length > 0) && (
        <div className="workflow-attack-notes">
          {tree.assumptions.length > 0 && <section><strong>Assumptions</strong><ul>{tree.assumptions.map((item) => <li key={item}>{item}</li>)}</ul></section>}
          {tree.limitations.length > 0 && <section><strong>Tree limitations</strong><ul>{tree.limitations.map((item) => <li key={item}>{item}</li>)}</ul></section>}
        </div>
      )}
    </section>
  );
}

function FlowLane({
  title,
  nodeIds,
  nodes,
  selectedId,
  mode,
  onSelect,
}: {
  title: string;
  nodeIds: string[];
  nodes: Map<string, WorkflowGraphNode>;
  selectedId: string;
  mode: "process" | "code";
  onSelect: (id: string) => void;
}) {
  return (
    <section className={`workflow-lane workflow-lane-${mode}`} aria-label={title}>
      <div className="workflow-lane-heading"><span>{title}</span><small>{mode === "process" ? "Human intent" : "Extracted implementation"}</small></div>
      <div className="workflow-lane-track">
        {nodeIds.map((id, index) => {
          const node = nodes.get(id);
          if (!node) return null;
          const codeLabel = node.signature
            ?? (node.method && node.path ? `${node.method} ${node.path}` : undefined)
            ?? (node.operation ? `${node.operation} ${(node.tables ?? []).join(", ")}` : undefined)
            ?? node.address
            ?? node.function_symbol
            ?? node.label;
          return (
            <div className="workflow-lane-step" key={`${id}:${index}`}>
              <button
                type="button"
                className={`workflow-node workflow-node-${node.kind} ${selectedId === id ? "selected" : ""}`}
                onClick={() => onSelect(id)}
                aria-pressed={selectedId === id}
              >
                <span>{node.kind}</span>
                {mode === "process" ? <strong>{node.label}</strong> : <code>{codeLabel}</code>}
              </button>
              {index < nodeIds.length - 1 && <ChevronRight className="workflow-node-arrow" size={17} aria-hidden="true" />}
            </div>
          );
        })}
      </div>
    </section>
  );
}

function NodeInspector({ node }: { node?: WorkflowGraphNode }) {
  if (!node) return <Panel className="workflow-inspector"><p>Select a graph node to inspect its implementation evidence.</p></Panel>;
  return (
    <Panel className="workflow-inspector">
      <div className="workflow-inspector-title"><span className={`workflow-kind workflow-kind-${node.kind}`}><Braces size={15} /> {node.kind}</span><h2>{node.label}</h2></div>
      {node.signature && <InspectorBlock label={node.kind.startsWith("terraform_") ? "Terraform block signature" : "Function signature"}><code>{node.signature}</code></InspectorBlock>}
      {(node.symbol || node.function_symbol) && <InspectorBlock label="Symbol"><code>{node.symbol ?? node.function_symbol}</code></InspectorBlock>}
      {node.address && <InspectorBlock label="Terraform address"><code>{node.address}</code></InspectorBlock>}
      {node.block_type && <InspectorBlock label="Terraform block"><code>{node.block_type}{node.resource_type ? ` · ${node.resource_type}` : ""}</code></InspectorBlock>}
      {node.source && <InspectorBlock label="Module or provider source"><code>{node.source}</code></InspectorBlock>}
      {node.description && <InspectorBlock label="Description"><p>{node.description}</p></InspectorBlock>}
      {node.condition && <InspectorBlock label="Check"><code>{node.condition}</code></InspectorBlock>}
      {node.failure_outcomes && node.failure_outcomes.length > 0 && <InspectorBlock label="Failure outcome"><ul>{node.failure_outcomes.map((outcome) => <li key={outcome}><code>{outcome}</code></li>)}</ul></InspectorBlock>}
      {node.sql && <InspectorBlock label={node.durable ? "Durable database effect" : node.kind === "lock" ? "Locking query" : "Database query"}><pre>{node.sql}</pre></InspectorBlock>}
      {node.durability && <InspectorBlock label="Transaction guarantee"><p>{node.durability}</p></InspectorBlock>}
      {node.constraints && node.constraints.length > 0 && <InspectorBlock label="PostgreSQL checks"><ul>{node.constraints.map((constraint) => <li key={constraint.node_id}><code>{constraint.name} → {constraint.database_function}()</code></li>)}</ul></InspectorBlock>}
      {node.constraint && <InspectorBlock label="PostgreSQL enforcement"><code>{node.constraint} → {node.database_function}()</code></InspectorBlock>}
      {(node.file || node.line) && <InspectorBlock label="Source"><code>{node.file}{node.line ? ` · line ${node.line}` : ""}</code></InspectorBlock>}
      {node.tables && node.tables.length > 0 && <InspectorBlock label="Tables"><div className="workflow-table-tags">{node.tables.map((table) => <span key={table}>{table}</span>)}</div></InspectorBlock>}
      {node.excerpt && <InspectorBlock label="Documentation excerpt"><pre>{node.excerpt}</pre></InspectorBlock>}
    </Panel>
  );
}

function InspectorBlock({ label, children }: { label: string; children: ReactNode }) {
  return <section className="workflow-inspector-block"><span>{label}</span>{children}</section>;
}
