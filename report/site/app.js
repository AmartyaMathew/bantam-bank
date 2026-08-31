(function () {
  "use strict";

  const SVG_NS = "http://www.w3.org/2000/svg";
  const STAGES = [
    { id: "route", label: "Entry route", kinds: ["route"] },
    { id: "function", label: "Services", kinds: ["function"] },
    { id: "check", label: "Guards", kinds: ["check"] },
    { id: "transaction", label: "Transactions", kinds: ["transaction"] },
    { id: "data", label: "Reads & locks", kinds: ["query", "lock"] },
    { id: "effect", label: "Durable effects", kinds: ["effect"] },
    { id: "constraint", label: "DB constraints", kinds: ["constraint"] }
  ];

  const state = {
    graph: null,
    model: null,
    manifest: null,
    nodesById: new Map(),
    flowsById: new Map(),
    activeStage: "route",
    activeAttackTree: null,
    latestResult: null,
    trees: [],
    activeTree: null,
    treeFormat: "plain",
    treeView: {
      treeId: null,
      positions: new Map(),
      selected: null,
      scale: 1,
      translateX: 0,
      translateY: 0,
      drag: null
    }
  };

  const currency = new Intl.NumberFormat("en-GB", {
    style: "currency",
    currency: "GBP",
    maximumFractionDigits: 0
  });
  const integer = new Intl.NumberFormat("en-GB", { maximumFractionDigits: 0 });
  const percent = new Intl.NumberFormat("en-GB", {
    style: "percent",
    minimumFractionDigits: 1,
    maximumFractionDigits: 1
  });

  function byId(id) {
    const element = document.getElementById(id);
    if (!element) {
      throw new Error("Missing report element: " + id);
    }
    return element;
  }

  function option(value, label) {
    const element = document.createElement("option");
    element.value = value;
    element.textContent = label;
    return element;
  }

  function setText(id, value) {
    byId(id).textContent = value;
  }

  function clamp(value, minimum, maximum) {
    return Math.min(maximum, Math.max(minimum, value));
  }

  function shortDigest(value) {
    return value ? value.slice(0, 12) : "—";
  }

  async function loadJson(path) {
    const response = await fetch(path, {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    });
    if (!response.ok) {
      throw new Error("Could not load " + path + " (HTTP " + response.status + ")");
    }
    return response.json();
  }

  function initializeSnapshot() {
    const counts = state.graph.catalogue_counts;
    setText("metric-nodes", integer.format(counts.nodes));
    setText("metric-edges", integer.format(counts.edges));
    setText("metric-flows", integer.format(counts.flows));
    setText("metric-digest", shortDigest(state.graph.catalogue_digest));
    setText("build-commit", state.manifest.source_commit);
    setText("projection-digest", state.manifest.projection_digest);
    setText("model-digest", state.manifest.risk_model_digest);
    setText(
      "footer-build",
      "Source " + shortDigest(state.manifest.source_commit) +
        " · graph " + shortDigest(state.manifest.catalogue_digest)
    );

  }

  function initializeGraphControls() {
    state.nodesById = new Map(state.graph.nodes.map((node) => [node.id, node]));
    state.flowsById = new Map(state.graph.flows.map((flow) => [flow.id, flow]));

    const scenarioSelect = byId("graph-scenario");
    scenarioSelect.append(option("all", "All catalogue flows"));
    state.model.scenarios.forEach((scenario) => {
      scenarioSelect.append(option(scenario.id, scenario.name));
    });
    scenarioSelect.value = "payment-integrity";

    const stageSelect = byId("graph-stage");
    STAGES.forEach((stage) => stageSelect.append(option(stage.id, stage.label)));

    scenarioSelect.addEventListener("change", refreshFlowOptions);
    byId("graph-flow").addEventListener("change", renderSelectedFlow);
    stageSelect.addEventListener("change", () => {
      state.activeStage = stageSelect.value;
      renderSelectedFlow();
    });
    refreshFlowOptions();
  }

  function scenarioById(scenarioId) {
    return state.model.scenarios.find((scenario) => scenario.id === scenarioId);
  }

  function relevantFlows() {
    const scenarioId = byId("graph-scenario").value;
    if (scenarioId === "all") {
      return state.graph.flows;
    }
    const scenario = scenarioById(scenarioId);
    return scenario.flow_ids.map((flowId) => state.flowsById.get(flowId)).filter(Boolean);
  }

  function refreshFlowOptions() {
    const select = byId("graph-flow");
    const previous = select.value;
    select.replaceChildren();
    relevantFlows().forEach((flow) => {
      const route = flow.route ? flow.route.method + " " + flow.route.path : "SYSTEM";
      select.append(option(flow.id, flow.name + " · " + route));
    });
    if ([...select.options].some((entry) => entry.value === previous)) {
      select.value = previous;
    }
    renderSelectedFlow();
  }

  function flowNodes(flow) {
    return flow.node_ids.map((nodeId) => state.nodesById.get(nodeId)).filter(Boolean);
  }

  function stageForNode(node) {
    return STAGES.find((stage) => stage.kinds.includes(node.kind));
  }

  function groupedFlowNodes(flow) {
    const grouped = new Map(STAGES.map((stage) => [stage.id, []]));
    flowNodes(flow).forEach((node) => {
      const stage = stageForNode(node);
      if (stage) {
        grouped.get(stage.id).push(node);
      }
    });
    return grouped;
  }

  function renderSelectedFlow() {
    const flow = state.flowsById.get(byId("graph-flow").value);
    if (!flow) {
      return;
    }
    const nodes = flowNodes(flow);
    const route = flow.route ? flow.route.method + " " + flow.route.path : "System entry";
    setText("graph-actor", flow.actor_roles.join(", "));
    setText("graph-entry", route);
    setText("graph-node-count", integer.format(nodes.length));
    setText("graph-doc", flow.documentation_path || "Generated from source");
    renderPipeline(flow);
    renderEvidence(flow);
  }

  function svgElement(name, attributes) {
    const element = document.createElementNS(SVG_NS, name);
    Object.entries(attributes || {}).forEach(([key, value]) => {
      element.setAttribute(key, String(value));
    });
    return element;
  }

  function activateStage(stageId) {
    state.activeStage = stageId;
    byId("graph-stage").value = stageId;
    renderSelectedFlow();
  }

  function renderPipeline(flow) {
    const svg = byId("graph-pipeline");
    const title = svg.querySelector("title").cloneNode(true);
    const description = svg.querySelector("desc").cloneNode(true);
    svg.replaceChildren(title, description);
    const grouped = groupedFlowNodes(flow);
    const populated = STAGES.filter((stage) => grouped.get(stage.id).length > 0);
    if (!populated.some((stage) => stage.id === state.activeStage)) {
      state.activeStage = populated[0] ? populated[0].id : "route";
      byId("graph-stage").value = state.activeStage;
    }
    const left = 82;
    const right = 1038;
    const gap = populated.length > 1 ? (right - left) / (populated.length - 1) : 0;
    const y = 118;

    for (let index = 0; index < populated.length - 1; index += 1) {
      svg.append(
        svgElement("line", {
          x1: left + index * gap,
          y1: y,
          x2: left + (index + 1) * gap,
          y2: y,
          class: "pipeline-line"
        })
      );
    }

    populated.forEach((stage, index) => {
      const count = grouped.get(stage.id).length;
      const radius = 30 + Math.min(18, Math.sqrt(count) * 3.2);
      const group = svgElement("g", {
        class: "pipeline-node" + (stage.id === state.activeStage ? " is-active" : ""),
        role: "button",
        tabindex: "0",
        "aria-label": stage.label + ", " + count + " evidence nodes"
      });
      group.append(
        svgElement("circle", {
          cx: left + index * gap,
          cy: y,
          r: radius
        })
      );
      const countText = svgElement("text", {
        x: left + index * gap,
        y: y + 8,
        "text-anchor": "middle",
        class: "pipeline-count"
      });
      countText.textContent = String(count);
      group.append(countText);
      const labelText = svgElement("text", {
        x: left + index * gap,
        y: 210,
        "text-anchor": "middle",
        class: "pipeline-label"
      });
      labelText.textContent = stage.label;
      group.append(labelText);
      group.addEventListener("click", () => activateStage(stage.id));
      group.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          activateStage(stage.id);
        }
      });
      svg.append(group);
    });
  }

  function nodeOperation(node) {
    if (node.signature) {
      return node.signature;
    }
    if (node.condition) {
      return node.condition;
    }
    if (node.operation) {
      const tables = Array.isArray(node.tables) && node.tables.length
        ? " · " + node.tables.join(", ")
        : "";
      return node.operation + tables + (node.durable ? " · durable" : "");
    }
    if (node.durability) {
      return node.durability;
    }
    if (node.database_function) {
      return node.database_function;
    }
    return node.function_symbol || "—";
  }

  function sourceUrl(node) {
    if (!node.file) {
      return null;
    }
    const ref = state.graph.source_commit === "local" ? "main" : state.graph.source_commit;
    const suffix = node.line ? "#L" + node.line : "";
    return "https://github.com/aam57689/bank/blob/" + ref + "/" + node.file + suffix;
  }

  function renderEvidence(flow) {
    const grouped = groupedFlowNodes(flow);
    const selected = grouped.get(state.activeStage) || [];
    const stage = STAGES.find((candidate) => candidate.id === state.activeStage);
    setText(
      "evidence-caption",
      (stage ? stage.label : "Evidence") + " · " + selected.length + " node(s)"
    );
    const body = byId("graph-evidence-body");
    body.replaceChildren();
    selected.forEach((node) => {
      const row = document.createElement("tr");
      const kindCell = document.createElement("td");
      const kind = document.createElement("span");
      kind.className = "kind-pill";
      kind.textContent = node.kind;
      kindCell.append(kind);

      const labelCell = document.createElement("td");
      labelCell.textContent = node.label;
      const operationCell = document.createElement("td");
      const operation = document.createElement("code");
      operation.textContent = nodeOperation(node);
      operationCell.append(operation);

      const sourceCell = document.createElement("td");
      const url = sourceUrl(node);
      if (url) {
        const link = document.createElement("a");
        link.className = "source-link";
        link.href = url;
        link.rel = "noopener noreferrer";
        link.textContent = node.file + (node.line ? ":" + node.line : "");
        sourceCell.append(link);
      } else {
        sourceCell.textContent = "Generated catalogue evidence";
      }
      row.append(kindCell, labelCell, operationCell, sourceCell);
      body.append(row);
    });
  }

  function renderBusinessProfile() {
    const profile = state.model.business_profile;
    if (!profile) {
      return;
    }
    setText("business-revenue", currency.format(profile.annual_revenue_gbp));
    setText("business-customers", integer.format(profile.customer_accounts));
    setText("business-volume", currency.format(profile.annual_payment_volume_gbp));
    setText("business-transfers", integer.format(profile.annual_transfer_count));
  }

  function attackTreeProbability(scenario) {
    const assumptions = scenario.attack_tree &&
      scenario.attack_tree.probability_assumptions;
    if (!Array.isArray(assumptions) || !assumptions.length) {
      return scenario.assumptions.annual_event_probability;
    }
    return assumptions.reduce((total, assumption) => {
      return total * Number(assumption.probability || 0);
    }, 1);
  }

  function costBasisRows(costBasis) {
    if (!costBasis) {
      return [];
    }
    if (Array.isArray(costBasis.line_items) && costBasis.line_items.length) {
      return costBasis.line_items;
    }
    return [
      {
        label: "RTO",
        amount_gbp: costBasis.rto_hours * costBasis.outage_cost_per_hour_gbp,
        source: costBasis.rto_hours + "h x " +
          compactCurrency(costBasis.outage_cost_per_hour_gbp) + "/h = " +
          currency.format(costBasis.rto_hours * costBasis.outage_cost_per_hour_gbp),
        rationale: "Service is unavailable or untrusted until containment."
      },
      {
        label: "RPO",
        amount_gbp: costBasis.rpo_minutes / 60 *
          costBasis.data_reconstruction_cost_per_hour_gbp,
        source: costBasis.rpo_minutes + "m x " +
          compactCurrency(costBasis.data_reconstruction_cost_per_hour_gbp) + "/h = " +
          currency.format(
            costBasis.rpo_minutes / 60 *
            costBasis.data_reconstruction_cost_per_hour_gbp
          ),
        rationale: "Lost, replayed, or uncertain state needs reconstruction."
      },
      {
        label: "Response/remediation",
        amount_gbp: costBasis.response_and_remediation_cost_gbp,
        source: "Synthetic response package",
        rationale: "Incident command, engineering, investigation, and remediation."
      },
      {
        label: "Customer/regulatory",
        amount_gbp: costBasis.customer_or_regulatory_cost_gbp,
        source: "Synthetic trust-repair package",
        rationale: "Customer support, complaints, legal, and regulatory review."
      }
    ];
  }

  function appendText(parent, tag, className, value) {
    const element = document.createElement(tag);
    if (className) {
      element.className = className;
    }
    element.textContent = value;
    parent.append(element);
    return element;
  }

  function initializeAttackTreeControls() {
    const select = byId("attack-tree-select");
    state.model.scenarios.forEach((scenario) => {
      select.append(option(scenario.id, scenario.name));
    });
    select.value = state.model.scenarios[0].id;
    state.activeAttackTree = select.value;
    select.addEventListener("change", () => {
      state.activeAttackTree = select.value;
      renderAttackTreeDetail();
    });
    byId("use-attack-tree").addEventListener("click", () => {
      byId("simulation-scope").value = byId("attack-tree-select").value;
      updateRunButton();
      runSimulation();
      byId("simulation").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    renderAttackTreeDetail();
  }

  function renderAttackTreeDetail() {
    const scenario = scenarioById(byId("attack-tree-select").value);
    if (!scenario || !scenario.attack_tree) {
      return;
    }
    const tree = scenario.attack_tree;
    const container = byId("attack-tree-detail");
    container.replaceChildren();

    const storyCard = document.createElement("article");
    storyCard.className = "attack-tree-card attack-story-card";
    appendText(storyCard, "p", "eyebrow", scenario.name);
    appendText(storyCard, "h3", "", tree.root);
    appendText(storyCard, "p", "plain-summary", scenario.plain_english_summary || "");
    appendText(storyCard, "p", "", tree.story || scenario.narrative);
    appendText(storyCard, "p", "flow-evidence", "Incident causing loss: " + scenario.incident);
    appendText(storyCard, "p", "flow-evidence", scenario.why_these_numbers);

    const probabilityCard = document.createElement("article");
    probabilityCard.className = "attack-tree-card";
    appendText(probabilityCard, "p", "eyebrow", "Traversal probability");
    appendText(probabilityCard, "h3", "", "Why the default trigger is " +
      percent.format(scenario.assumptions.annual_event_probability));
    const chain = document.createElement("ol");
    chain.className = "tree-chain probability-chain";
    tree.probability_assumptions.forEach((assumption) => {
      const item = document.createElement("li");
      appendText(item, "strong", "", assumption.title + " · " +
        percent.format(assumption.probability));
      appendText(item, "small", "", assumption.rationale);
      chain.append(item);
    });
    probabilityCard.append(chain);
    appendText(
      probabilityCard,
      "p",
      "tree-total",
      "Path product: " + percent.format(attackTreeProbability(scenario)) +
        " annual traversal probability"
    );
    appendText(probabilityCard, "p", "flow-evidence", tree.probability_note || "");

    const costCard = document.createElement("article");
    costCard.className = "attack-tree-card";
    appendText(costCard, "p", "eyebrow", "RTO/RPO loss story");
    appendText(costCard, "h3", "", "Full traversal costs " +
      currency.format(tree.traversal_cost_gbp));
    const costs = document.createElement("dl");
    costs.className = "cost-breakdown";
    costBasisRows(scenario.cost_basis).forEach((item) => {
      const row = document.createElement("div");
      appendText(row, "dt", "", item.label);
      const detail = document.createElement("dd");
      appendText(detail, "strong", "", currency.format(item.amount_gbp));
      appendText(detail, "small", "", item.source + ". " + item.rationale);
      row.append(detail);
      costs.append(row);
    });
    costCard.append(costs);
    appendText(costCard, "p", "flow-evidence", scenario.cost_basis.source_note || "");

    container.append(storyCard, probabilityCard, costCard);
  }

  function initializeModelControls() {
    const scope = byId("simulation-scope");
    scope.append(option("portfolio", "Full portfolio"));
    state.model.scenarios.forEach((scenario) => {
      scope.append(option(scenario.id, scenario.name + " tree"));
    });
    scope.value = "portfolio";
    scope.addEventListener("change", updateRunButton);

    byId("iterations-input").value = state.model.iterations;
    byId("seed-input").value = state.model.seed;
    byId("tolerance-input").value = state.model.impact_tolerance_gbp;
    ["iterations-input", "seed-input", "tolerance-input"].forEach((id) => {
      byId(id).addEventListener("input", updateRunButton);
    });

    const scenariosBody = byId("scenario-inputs");
    state.model.scenarios.forEach((scenario) => {
      const row = document.createElement("tr");
      const nameCell = document.createElement("td");
      nameCell.className = "scenario-name";
      const strong = document.createElement("strong");
      strong.textContent = scenario.name;
      const small = document.createElement("small");
      small.textContent = scenario.business_service;
      nameCell.append(strong, small);

      const compromiseCell = document.createElement("td");
      compromiseCell.append(numberInput(
        scenario.id,
        "annual_event_probability",
        scenario.assumptions.annual_event_probability * 100,
        0,
        100,
        0.1,
        "Annual scenario trigger probability, percent"
      ));
      appendText(compromiseCell, "small", "", "Whole attack tree per year");
      const conditionalCell = document.createElement("td");
      conditionalCell.append(numberInput(
        scenario.id,
        "conditional_loss_probability",
        scenario.assumptions.conditional_loss_probability * 100,
        0,
        100,
        0.1,
        "Conditional loss probability, percent"
      ));
      appendText(conditionalCell, "small", "", "Material loss after containment");
      const lossCell = document.createElement("td");
      lossCell.append(numberInput(
        scenario.id,
        "base_loss_gbp",
        scenario.assumptions.base_loss_gbp,
        1000,
        100000000,
        1000,
        "Base loss in pounds"
      ));
      appendText(lossCell, "small", "", "RTO + RPO + response + customer/regulatory");
      const countermeasureCell = document.createElement("td");
      countermeasureCell.append(scenarioCountermeasureToggle(scenario));

      const graphCell = document.createElement("td");
      graphCell.textContent = scenario.flow_ids.length + " flows";
      if (scenario.attack_tree) {
        const small = document.createElement("small");
        small.textContent = "Tree path " + percent.format(attackTreeProbability(scenario));
        graphCell.append(small);
      }
      row.append(
        nameCell,
        compromiseCell,
        conditionalCell,
        lossCell,
        countermeasureCell,
        graphCell
      );
      scenariosBody.append(row);
    });

    byId("run-simulation").addEventListener("click", runSimulation);
    updateRunButton();
    renderInvestmentTable();
  }

  function numberInput(scenarioId, field, value, minimum, maximum, step, label) {
    const input = document.createElement("input");
    input.type = "number";
    input.min = String(minimum);
    input.max = String(maximum);
    input.step = String(step);
    input.value = String(value);
    input.dataset.scenarioId = scenarioId;
    input.dataset.field = field;
    input.setAttribute("aria-label", label);
    input.addEventListener("input", updateRunButton);
    return input;
  }

  function scenarioCountermeasureToggle(scenario) {
    const details = countermeasureCase(scenario);
    const controlIds = countermeasureControlIds(scenario);
    const controls = controlIds.map((controlId) => controlById(controlId)).filter(Boolean);
    const total = controls.reduce((sum, control) => sum + control.cost_y1_gbp, 0);
    const label = document.createElement("label");
    label.className = "scenario-countermeasure";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.dataset.scenarioCountermeasure = scenario.id;
    checkbox.disabled = controlIds.length === 0;
    checkbox.addEventListener("change", () => {
      updateRunButton();
      if (state.latestResult) {
        runSimulation();
      }
    });

    const track = document.createElement("span");
    track.className = "mini-toggle-track";
    track.setAttribute("aria-hidden", "true");

    const copy = document.createElement("span");
    copy.className = "scenario-countermeasure-copy";
    appendText(copy, "strong", "", "Add countermeasure");
    appendText(copy, "small", "",
      controls.length
        ? (details.title || controls.map((control) => control.short_name || control.name).join(" + ")) +
          " · " + currency.format(total)
        : "No mapped countermeasure");

    label.append(checkbox, track, copy);
    return label;
  }

  function selectedControlIds() {
    const selected = new Map();
    document.querySelectorAll("[data-scenario-countermeasure]").forEach((checkbox) => {
      const scenario = scenarioById(checkbox.dataset.scenarioCountermeasure);
      if (!scenario || !checkbox.checked) {
        return;
      }
      selected.set(scenario.id, countermeasureControlIds(scenario));
    });
    return selected;
  }

  function selectedControlIdSet(selectedIds) {
    const ids = new Set();
    if (selectedIds instanceof Map) {
      selectedIds.forEach((scenarioIds) => {
        scenarioIds.forEach((controlId) => ids.add(controlId));
      });
      return ids;
    }
    (selectedIds || []).forEach((controlId) => ids.add(controlId));
    return ids;
  }

  function selectedControlIdsForScenarios(scenarios) {
    const selected = selectedControlIds();
    const scopeIds = new Set(scenarios.map((scenario) => scenario.id));
    const scoped = new Map();
    selected.forEach((controlIds, scenarioId) => {
      if (scopeIds.has(scenarioId)) {
        scoped.set(scenarioId, controlIds);
      }
    });
    return scoped;
  }

  function controlIdsForScenario(scenarioId, selectedIds) {
    if (selectedIds instanceof Map) {
      return selectedIds.get(scenarioId) || [];
    }
    return selectedIds || [];
  }

  function updateRunButton() {
    const iterations = Number(byId("iterations-input").value) || 0;
    const scope = byId("simulation-scope").value;
    const scenario = scope === "portfolio" ? null : scenarioById(scope);
    const suffix = scenario ? " for " + scenario.name + " tree" : " for full portfolio";
    const selectedCount = selectedControlIdSet(selectedControlIds()).size;
    const controlText = selectedCount
      ? " with " + selectedCount + " countermeasure" + (selectedCount === 1 ? "" : "s")
      : "";
    setText(
      "run-simulation",
      "Run " + integer.format(iterations) + " simulated years" + suffix + controlText
    );
  }

  function editableAssumptions() {
    return state.model.scenarios.map((scenario) => {
      const assumptions = { ...scenario.assumptions };
      document.querySelectorAll('[data-scenario-id="' + scenario.id + '"]').forEach(
        (input) => {
          const value = Number(input.value);
          assumptions[input.dataset.field] = input.dataset.field.includes("probability")
            ? value / 100
            : value;
        }
      );
      return { ...scenario, assumptions };
    });
  }

  function validateSimulationInputs(scenarios, iterations, seed, tolerance) {
    if (!Number.isInteger(iterations) || iterations < 1000 || iterations > 100000) {
      throw new Error("Simulated years must be an integer from 1,000 to 100,000.");
    }
    if (!Number.isInteger(seed) || seed < 0 || seed >= 2 ** 32) {
      throw new Error("Random seed must be an integer from 0 to 4,294,967,295.");
    }
    if (!Number.isFinite(tolerance) || tolerance < 10000 || tolerance > 100000000) {
      throw new Error("Impact tolerance must be between £10,000 and £100,000,000.");
    }
    scenarios.forEach((scenario) => {
      const values = scenario.assumptions;
      [values.annual_event_probability, values.conditional_loss_probability].forEach(
        (value) => {
          if (!Number.isFinite(value) || value < 0 || value > 1) {
            throw new Error(scenario.name + " probabilities must be between 0% and 100%.");
          }
        }
      );
      if (!Number.isFinite(values.base_loss_gbp) || values.base_loss_gbp <= 0) {
        throw new Error(scenario.name + " base loss must be greater than zero.");
      }
    });
  }

  function mulberry32(seed) {
    let value = seed >>> 0;
    return function () {
      value += 0x6d2b79f5;
      let output = value;
      output = Math.imul(output ^ (output >>> 15), output | 1);
      output ^= output + Math.imul(output ^ (output >>> 7), output | 61);
      return ((output ^ (output >>> 14)) >>> 0) / 4294967296;
    };
  }

  function standardNormalSample(random) {
    const u = Math.max(Number.EPSILON, random());
    const v = Math.max(Number.EPSILON, random());
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
  }

  function normalSample(random, mean, standardDeviation) {
    return Math.max(0.25, mean + standardDeviation * standardNormalSample(random));
  }

  function weibullSample(random, shape, scale) {
    return scale * Math.pow(-Math.log(Math.max(Number.EPSILON, 1 - random())), 1 / shape);
  }

  function gammaFunction(value) {
    const coefficients = [
      676.5203681218851,
      -1259.1392167224028,
      771.3234287776531,
      -176.6150291621406,
      12.507343278686905,
      -0.13857109526572012,
      0.000009984369578019572,
      0.00000015056327351493116
    ];
    if (value < 0.5) {
      return Math.PI / (Math.sin(Math.PI * value) * gammaFunction(1 - value));
    }
    let shifted = value - 1;
    let series = 0.9999999999998099;
    coefficients.forEach((coefficient, index) => {
      series += coefficient / (shifted + index + 1);
    });
    const t = shifted + coefficients.length - 0.5;
    return Math.sqrt(2 * Math.PI) * Math.pow(t, shifted + 0.5) * Math.exp(-t) * series;
  }

  function gammaSample(random, shape) {
    if (shape < 1) {
      return gammaSample(random, shape + 1) * Math.pow(random(), 1 / shape);
    }
    const d = shape - 1 / 3;
    const c = 1 / Math.sqrt(9 * d);
    for (;;) {
      const x = standardNormalSample(random);
      const vBase = 1 + c * x;
      if (vBase <= 0) {
        continue;
      }
      const v = vBase ** 3;
      const u = random();
      if (u < 1 - 0.0331 * x ** 4) {
        return d * v;
      }
      if (Math.log(u) < 0.5 * x ** 2 + d * (1 - v + Math.log(v))) {
        return d * v;
      }
    }
  }

  function betaSample(random, alpha, beta) {
    const left = gammaSample(random, alpha);
    const right = gammaSample(random, beta);
    return left / (left + right);
  }

  function controlMultipliers(scenarioId, selectedIds) {
    const scenarioControlIds = controlIdsForScenario(scenarioId, selectedIds);
    let frequency = 1;
    let magnitude = 1;
    state.model.controls.forEach((control) => {
      if (!scenarioControlIds.includes(control.id)) {
        return;
      }
      const reduction = control.reductions[scenarioId];
      if (reduction) {
        frequency *= 1 - reduction.frequency;
        magnitude *= 1 - reduction.magnitude;
      }
    });
    return { frequency, magnitude };
  }

  function analyticEal(scenario, multipliers) {
    const assumptions = scenario.assumptions;
    return assumptions.annual_event_probability * multipliers.frequency *
      assumptions.conditional_loss_probability * assumptions.base_loss_gbp *
      multipliers.magnitude;
  }

  function simulatePortfolio(scenarios, iterations, seed, tolerance, selectedIds) {
    const random = mulberry32(seed);
    const multipliers = new Map(
      scenarios.map((scenario) => [
        scenario.id,
        controlMultipliers(scenario.id, selectedIds)
      ])
    );
    const losses = new Array(iterations);
    for (let run = 0; run < iterations; run += 1) {
      let annualLoss = 0;
      scenarios.forEach((scenario) => {
        const assumptions = scenario.assumptions;
        const reduction = multipliers.get(scenario.id);
        const eventProbability =
          assumptions.annual_event_probability * reduction.frequency;
        if (random() >= eventProbability ||
            random() >= assumptions.conditional_loss_probability) {
          return;
        }
        const detection = normalSample(
          random,
          assumptions.detection_mean_hours,
          assumptions.detection_sd_hours
        );
        const dwell = weibullSample(
          random,
          assumptions.dwell_shape,
          assumptions.dwell_scale_hours
        );
        const blast = betaSample(
          random,
          assumptions.blast_alpha,
          assumptions.blast_beta
        );
        const expectedDwell = assumptions.dwell_scale_hours *
          gammaFunction(1 + 1 / assumptions.dwell_shape);
        const expectedBlast = assumptions.blast_alpha /
          (assumptions.blast_alpha + assumptions.blast_beta);
        const severity = clamp(
          0.25 * detection / assumptions.detection_mean_hours +
            0.25 * dwell / expectedDwell +
            0.5 * blast / expectedBlast,
          0.2,
          3
        );
        annualLoss += assumptions.base_loss_gbp * reduction.magnitude * severity;
      });
      losses[run] = annualLoss;
    }
    losses.sort((left, right) => left - right);
    const sum = losses.reduce((total, value) => total + value, 0);
    const percentileValue = (quantile) => {
      const index = Math.min(losses.length - 1, Math.ceil(quantile * losses.length) - 1);
      return losses[Math.max(0, index)];
    };
    const baselineEal = scenarios.reduce(
      (total, scenario) => total + analyticEal(scenario, { frequency: 1, magnitude: 1 }),
      0
    );
    const adjustedEal = scenarios.reduce(
      (total, scenario) => total + analyticEal(scenario, multipliers.get(scenario.id)),
      0
    );
    const selectedSet = selectedControlIdSet(selectedIds);
    const programmeCost = state.model.controls
      .filter((control) => selectedSet.has(control.id))
      .reduce((total, control) => total + control.cost_y1_gbp, 0);
    return {
      losses,
      mean: sum / losses.length,
      median: percentileValue(0.5),
      p90: percentileValue(0.9),
      p95: percentileValue(0.95),
      p99: percentileValue(0.99),
      exceedance: losses.filter((loss) => loss > tolerance).length / losses.length,
      tolerance,
      baselineEal,
      adjustedEal,
      programmeCost,
      reduction: baselineEal - adjustedEal,
      multipliers,
      scenarios,
      iterations,
      seed
    };
  }

  function runSimulation() {
    const button = byId("run-simulation");
    const status = byId("simulation-status");
    try {
      button.disabled = true;
      status.textContent = "Calculating locally…";
      const scenarios = editableAssumptions();
      const iterations = Number(byId("iterations-input").value);
      const seed = Number(byId("seed-input").value);
      const tolerance = Number(byId("tolerance-input").value);
      const scope = byId("simulation-scope").value;
      const scopedScenarios = scope === "portfolio"
        ? scenarios
        : scenarios.filter((scenario) => scenario.id === scope);
      if (!scopedScenarios.length) {
        throw new Error("Choose a valid simulation scope.");
      }
      validateSimulationInputs(scopedScenarios, iterations, seed, tolerance);
      const selectedIds = selectedControlIdsForScenarios(scopedScenarios);
      const baselineResult = simulatePortfolio(
        scopedScenarios,
        iterations,
        seed,
        tolerance,
        new Map()
      );
      const result = simulatePortfolio(
        scopedScenarios,
        iterations,
        seed,
        tolerance,
        selectedIds
      );
      result.baselineMonteCarlo = baselineResult;
      result.monteCarloReduction = Math.max(0, baselineResult.mean - result.mean);
      result.selectedControlCount = selectedControlIdSet(selectedIds).size;
      result.scope = scope;
      result.scopeLabel = scope === "portfolio"
        ? "full portfolio"
        : scopedScenarios[0].name + " attack tree";
      state.latestResult = result;
      renderSimulationResult(result);
      status.textContent =
        "Complete · " + result.scopeLabel + " · seed " + result.seed + " · " +
        integer.format(result.iterations) + " simulated years";
    } catch (error) {
      status.textContent = error instanceof Error ? error.message : String(error);
    } finally {
      button.disabled = false;
    }
  }

  function renderSimulationResult(result) {
    setText("result-mean", currency.format(result.mean));
    setText("result-p95", currency.format(result.p95));
    setText("result-exceedance", percent.format(result.exceedance));
    setText("result-threshold", "above " + currency.format(result.tolerance));
    const annualReduction = result.monteCarloReduction ?? result.reduction;
    const paybackYears = annualReduction > 0
      ? result.programmeCost / annualReduction
      : Number.POSITIVE_INFINITY;
    setText(
      "result-payback",
      result.programmeCost === 0
        ? "No programme"
        : Number.isFinite(paybackYears)
          ? paybackYears < 2
            ? (paybackYears * 12).toFixed(1) + " months"
            : paybackYears.toFixed(1) + " years"
          : "No payback"
    );
    setText("headline-eal", currency.format(result.baselineEal));
    setText("headline-exceedance", percent.format(result.exceedance));
    setText("headline-tolerance", "above " + currency.format(result.tolerance));
    renderSimulationStory(result);
    renderScenarioResults(result);
  }

  function renderSimulationStory(result) {
    const baseline = result.baselineMonteCarlo || result;
    const reduction = Math.max(0, baseline.mean - result.mean);
    const ceiling = Math.max(baseline.mean, result.mean, 1);
    const baselineWidth = Math.max(2, baseline.mean / ceiling * 100);
    const adjustedWidth = Math.max(2, result.mean / ceiling * 100);

    byId("baseline-bar").style.width = baselineWidth + "%";
    byId("adjusted-bar").style.width = adjustedWidth + "%";
    setText("baseline-bar-value", currency.format(baseline.mean));
    setText("adjusted-bar-value", currency.format(result.mean));

    if (!result.programmeCost) {
      setText("simulation-story-title", "No row countermeasures selected yet");
      setText(
        "simulation-story-copy",
        "Use the switches in the scenario table to add a prevention package for a row. The lab will rerun the same seeded years before and after those controls."
      );
      return;
    }

    const paybackYears = reduction > 0
      ? result.programmeCost / reduction
      : Number.POSITIVE_INFINITY;
    const payback = Number.isFinite(paybackYears)
      ? paybackYears < 2
        ? (paybackYears * 12).toFixed(1) + " months"
        : paybackYears.toFixed(1) + " years"
      : "not reached";

    setText(
      "simulation-story-title",
      "Selected row countermeasures reduce simulated mean loss by " +
        currency.format(reduction)
    );
    setText(
      "simulation-story-copy",
      "The lab runs " + integer.format(result.iterations) +
        " seeded years once without row countermeasures and again with the selected " +
        "packages. First-year prevention spend is " + currency.format(result.programmeCost) +
        ", giving a modelled payback of " + payback +
        ". This is an assumption test, not a prediction."
    );
  }

  function compactCurrency(value) {
    if (value >= 1000000) {
      return "£" + (value / 1000000).toFixed(value >= 10000000 ? 0 : 1) + "m";
    }
    if (value >= 1000) {
      return "£" + Math.round(value / 1000) + "k";
    }
    return currency.format(value);
  }

  function renderScenarioResults(result) {
    const body = byId("scenario-results");
    body.replaceChildren();
    result.scenarios.forEach((scenario) => {
      const baseline = analyticEal(scenario, { frequency: 1, magnitude: 1 });
      const adjusted = analyticEal(scenario, result.multipliers.get(scenario.id));
      const row = document.createElement("tr");
      [
        scenario.name,
        String(scenario.flow_ids.length),
        currency.format(baseline),
        currency.format(adjusted),
        baseline > 0 ? percent.format((baseline - adjusted) / baseline) : "0%"
      ].forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.append(cell);
      });
      body.append(row);
    });
  }

  function renderInvestmentTable() {
    const body = byId("investment-body");
    body.replaceChildren();
    let total = 0;
    const includedControlIds = [];
    state.model.scenarios.forEach((scenario) => {
      countermeasureControlIds(scenario).forEach((controlId) => {
        if (!includedControlIds.includes(controlId)) {
          includedControlIds.push(controlId);
        }
      });
    });
    includedControlIds.map(controlById).filter(Boolean).forEach((control) => {
      total += control.cost_y1_gbp;
      const effects = Object.entries(control.reductions).map(([scenarioId, reduction]) => {
        const scenario = scenarioById(scenarioId);
        const parts = [];
        if (reduction.frequency) {
          parts.push(percent.format(reduction.frequency) + " frequency");
        }
        if (reduction.magnitude) {
          parts.push(percent.format(reduction.magnitude) + " magnitude");
        }
        return (scenario ? scenario.name : scenarioId) + ": " + parts.join(" + ");
      });
      const row = document.createElement("tr");
      const name = document.createElement("td");
      const strong = document.createElement("strong");
      strong.textContent = control.name;
      const detail = document.createElement("small");
      detail.className = "investment-detail";
      detail.textContent = control.description;
      name.append(strong, detail);
      if (Array.isArray(control.cost_breakdown) && control.cost_breakdown.length) {
        const breakdown = document.createElement("ul");
        breakdown.className = "investment-breakdown";
        control.cost_breakdown.forEach((item) => {
          const entry = document.createElement("li");
          entry.textContent = item.label + " " + currency.format(item.amount_gbp);
          breakdown.append(entry);
        });
        name.append(breakdown);
      }
      const phase = document.createElement("td");
      phase.textContent = control.phase;
      const cost = document.createElement("td");
      cost.textContent = currency.format(control.cost_y1_gbp);
      if (control.cost_source) {
        const source = document.createElement("small");
        source.className = "investment-detail";
        source.textContent = control.cost_source;
        cost.append(source);
      }
      const effect = document.createElement("td");
      effect.textContent = effects.join("; ");
      row.append(name, phase, cost, effect);
      body.append(row);
    });
    setText("investment-total", currency.format(total));
  }

  function renderSources() {
    const list = byId("source-list");
    state.model.sources.forEach((source) => {
      const item = document.createElement("li");
      const link = document.createElement("a");
      link.href = source.url;
      link.rel = "noopener noreferrer";
      link.textContent = source.name;
      const detail = document.createElement("small");
      detail.textContent = source.purpose;
      item.append(link, detail);
      list.append(item);
    });
  }


  // ----------------------------------------------------------------------
  // Attack tree explorer: curated trees verified during the report build
  // ----------------------------------------------------------------------

  function treeById(treeId) {
    return state.trees.find((tree) => tree.tree_id === treeId) || null;
  }

  function initializeTreeExplorer() {
    const select = byId("tree-select");
    select.addEventListener("change", () => {
      state.activeTree = select.value;
      renderTree();
    });
    document.querySelectorAll('input[name="tree-format"]').forEach((radio) => {
      radio.addEventListener("change", () => {
        state.treeFormat = radio.value;
        refreshTreeOptions();
      });
    });
    initializeGraphInteractions();
    initializeMiniLab();
    refreshTreeOptions();
  }

  function refreshTreeOptions() {
    const select = byId("tree-select");
    select.replaceChildren();
    state.trees.forEach((tree) => {
      const name = state.treeFormat === "plain" ? tree.plain_name : tree.name;
      select.append(option(tree.tree_id, name));
    });
    if (!state.activeTree || !treeById(state.activeTree)) {
      state.activeTree = state.trees.length ? state.trees[0].tree_id : null;
    }
    select.value = state.activeTree || "";
    renderTree();
  }

  function treeChildren(tree) {
    const children = new Map(tree.nodes.map((node) => [node.node_id, []]));
    tree.edges.forEach((edge) => {
      const current = children.get(edge[0]);
      if (current) {
        current.push(edge[1]);
      }
    });
    return children;
  }

  const GRAPH = {
    viewWidth: 1120,
    viewHeight: 560,
    nodeWidth: 210,
    lineHeight: 15,
    padding: 13,
    gapX: 28,
    gapY: 76,
    minScale: 0.35,
    maxScale: 2.4
  };

  function wrapLabel(text, maxChars, maxLines) {
    const words = String(text).split(/\s+/);
    const lines = [];
    let current = "";
    words.forEach((word) => {
      const candidate = current ? current + " " + word : word;
      if (candidate.length <= maxChars || !current) {
        current = candidate;
      } else {
        lines.push(current);
        current = word;
      }
    });
    if (current) {
      lines.push(current);
    }
    if (lines.length <= maxLines) {
      return lines;
    }
    const kept = lines.slice(0, maxLines);
    kept[maxLines - 1] = kept[maxLines - 1].replace(/\s*\S*$/, "") + "…";
    return kept;
  }

  function layoutTree(tree, plain) {
    const nodes = new Map(tree.nodes.map((node) => [node.node_id, node]));
    const children = treeChildren(tree);
    const positions = new Map();
    let cursor = 0;

    // Leaves take the next free column and every parent centres over its own
    // children, which keeps a hand-authored tree readable without a physics
    // simulation the reader would have to wait for.
    const place = (nodeId, depth) => {
      const node = nodes.get(nodeId);
      const lines = wrapLabel(plain ? node.plain_title : node.title, 27, 3);
      const height = GRAPH.padding * 2 + 13 + lines.length * GRAPH.lineHeight;
      const childIds = children.get(nodeId) || [];
      let x;
      if (!childIds.length) {
        x = cursor;
        cursor += GRAPH.nodeWidth + GRAPH.gapX;
      } else {
        const spans = childIds.map((childId) => place(childId, depth + 1));
        x = (spans[0] + spans[spans.length - 1]) / 2;
      }
      positions.set(nodeId, {
        x: x,
        y: 0,
        width: GRAPH.nodeWidth,
        height: height,
        lines: lines,
        depth: depth
      });
      return x;
    };
    place(tree.root_node_id, 0);

    const rowHeights = [];
    positions.forEach((position) => {
      rowHeights[position.depth] = Math.max(
        rowHeights[position.depth] || 0,
        position.height
      );
    });
    const rowTops = [];
    rowHeights.reduce((top, height, index) => {
      rowTops[index] = top;
      return top + height + GRAPH.gapY;
    }, 0);
    positions.forEach((position) => {
      position.y = rowTops[position.depth];
    });
    return positions;
  }

  function graphBounds() {
    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    state.treeView.positions.forEach((position) => {
      minX = Math.min(minX, position.x);
      minY = Math.min(minY, position.y);
      maxX = Math.max(maxX, position.x + position.width);
      maxY = Math.max(maxY, position.y + position.height);
    });
    return { minX: minX, minY: minY, maxX: maxX, maxY: maxY };
  }

  function fitGraph() {
    if (!state.treeView.positions.size) {
      return;
    }
    const bounds = graphBounds();
    const width = Math.max(bounds.maxX - bounds.minX, 1);
    const height = Math.max(bounds.maxY - bounds.minY, 1);
    const scale = clamp(
      Math.min((GRAPH.viewWidth - 60) / width, (GRAPH.viewHeight - 60) / height),
      GRAPH.minScale,
      1.1
    );
    state.treeView.scale = scale;
    state.treeView.translateX =
      (GRAPH.viewWidth - width * scale) / 2 - bounds.minX * scale;
    state.treeView.translateY =
      (GRAPH.viewHeight - height * scale) / 2 - bounds.minY * scale;
    applyViewTransform();
  }

  function applyViewTransform() {
    const view = state.treeView;
    byId("tree-viewport").setAttribute(
      "transform",
      "translate(" + view.translateX.toFixed(2) + "," + view.translateY.toFixed(2) +
        ") scale(" + view.scale.toFixed(3) + ")"
    );
  }

  function edgePath(parent, child) {
    const x1 = parent.x + parent.width / 2;
    const y1 = parent.y + parent.height;
    const x2 = child.x + child.width / 2;
    const y2 = child.y;
    const bend = Math.max(20, (y2 - y1) / 2);
    return "M " + x1 + " " + y1 + " C " + x1 + " " + (y1 + bend) + " " +
      x2 + " " + (y2 - bend) + " " + x2 + " " + y2;
  }

  function renderEdges(tree) {
    const layer = byId("tree-edges");
    layer.replaceChildren();
    tree.edges.forEach((edge) => {
      const parent = state.treeView.positions.get(edge[0]);
      const child = state.treeView.positions.get(edge[1]);
      if (!parent || !child) {
        return;
      }
      const path = document.createElementNS(SVG_NS, "path");
      path.setAttribute("d", edgePath(parent, child));
      path.setAttribute("class", "graph-edge");
      path.dataset.parent = edge[0];
      path.dataset.child = edge[1];
      layer.append(path);
    });
  }

  function renderNodes(tree, plain) {
    const nodes = new Map(tree.nodes.map((node) => [node.node_id, node]));
    const children = treeChildren(tree);
    const layer = byId("tree-nodes");
    layer.replaceChildren();
    state.treeView.positions.forEach((position, nodeId) => {
      const node = nodes.get(nodeId);
      const group = document.createElementNS(SVG_NS, "g");
      group.setAttribute(
        "class",
        "graph-node graph-node-" + node.kind.toLowerCase() +
          (nodeId === state.treeView.selected ? " selected" : "")
      );
      group.setAttribute("transform", "translate(" + position.x + "," + position.y + ")");
      group.setAttribute("tabindex", "0");
      group.setAttribute("role", "button");
      group.setAttribute(
        "aria-label",
        (plain ? plainKind(node) : node.kind) + ": " +
          (plain ? node.plain_title : node.title)
      );
      group.dataset.nodeId = nodeId;

      const box = document.createElementNS(SVG_NS, "rect");
      box.setAttribute("width", position.width);
      box.setAttribute("height", position.height);
      box.setAttribute("rx", "12");
      box.setAttribute("class", "graph-node-box");
      group.append(box);

      const kind = document.createElementNS(SVG_NS, "text");
      kind.setAttribute("x", GRAPH.padding);
      kind.setAttribute("y", GRAPH.padding + 8);
      kind.setAttribute("class", "graph-node-kind");
      const childCount = (children.get(nodeId) || []).length;
      kind.textContent = plain
        ? plainKind(node)
        : node.kind + (childCount ? " · " + node.operator : " · LEAF");
      group.append(kind);

      position.lines.forEach((line, index) => {
        const text = document.createElementNS(SVG_NS, "text");
        text.setAttribute("x", GRAPH.padding);
        text.setAttribute(
          "y",
          GRAPH.padding + 24 + index * GRAPH.lineHeight
        );
        text.setAttribute("class", "graph-node-label");
        text.textContent = line;
        group.append(text);
      });
      layer.append(group);
    });
  }

  function renderNodeDetail(tree, plain) {
    const detail = byId("tree-detail");
    detail.replaceChildren();
    const nodes = new Map(tree.nodes.map((node) => [node.node_id, node]));
    const node = nodes.get(state.treeView.selected);
    if (!node) {
      appendText(detail, "p", "eyebrow", "Select a step");
      appendText(detail, "p", "graph-detail-hint",
        "Choose any box in the graph to read the full description, the evidence " +
        "behind it, and what already stands in its way.");
      return;
    }
    const children = treeChildren(tree).get(node.node_id) || [];
    appendText(detail, "p", "eyebrow", plain ? plainKind(node) : node.kind + " · " +
      (children.length ? node.operator : "LEAF"));
    appendText(detail, "h4", "", plain ? node.plain_title : node.title);
    appendText(detail, "p", "", plain ? node.plain_description : node.description);

    if (children.length) {
      appendText(detail, "p", "graph-detail-operator", node.operator === "AND"
        ? (plain ? "All " + children.length + " steps below have to happen."
                 : "AND — every one of the " + children.length + " children is required.")
        : (plain ? "Any one of the " + children.length + " steps below is enough."
                 : "OR — any of the " + children.length + " children satisfies this."));
    }

    if (!plain && node.mitre_techniques.length) {
      const techniques = document.createElement("p");
      techniques.className = "tree-techniques";
      node.mitre_techniques.forEach((technique) => {
        const link = document.createElement("a");
        link.href = technique.url;
        link.rel = "noopener noreferrer";
        link.target = "_blank";
        link.textContent = technique.technique_id + " " + technique.name;
        const tactic = document.createElement("small");
        tactic.textContent = technique.tactic;
        link.append(tactic);
        techniques.append(link);
      });
      detail.append(techniques);
    }

    if (node.existing_obstacles.length) {
      appendText(detail, "p", "tree-obstacle", (plain
        ? "What already stands in the way: "
        : "Extracted obstacle: ") + node.existing_obstacles.join(" "));
    }

    const evidence = node.flow_ids.concat(node.graph_node_ids);
    if (evidence.length) {
      appendText(detail, "p", "tree-evidence", (plain
        ? "Where this lives in the code: "
        : "Cites: ") + evidence.map(plain ? humanEvidence : (value) => value).join("; "));
    }
  }

  function selectGraphNode(nodeId) {
    state.treeView.selected = nodeId;
    const tree = treeById(state.activeTree);
    if (!tree) {
      return;
    }
    byId("tree-nodes").querySelectorAll(".graph-node").forEach((element) => {
      element.classList.toggle("selected", element.dataset.nodeId === nodeId);
    });
    renderNodeDetail(tree, state.treeFormat === "plain");
  }

  function pointerToView(event) {
    const svg = byId("tree-graph");
    const rect = svg.getBoundingClientRect();
    const ratio = GRAPH.viewWidth / Math.max(rect.width, 1);
    return {
      x: (event.clientX - rect.left) * ratio,
      y: (event.clientY - rect.top) * ratio,
      ratio: ratio
    };
  }

  function zoomBy(factor, focus) {
    const view = state.treeView;
    const next = clamp(view.scale * factor, GRAPH.minScale, GRAPH.maxScale);
    const point = focus || { x: GRAPH.viewWidth / 2, y: GRAPH.viewHeight / 2 };
    const worldX = (point.x - view.translateX) / view.scale;
    const worldY = (point.y - view.translateY) / view.scale;
    view.scale = next;
    view.translateX = point.x - worldX * next;
    view.translateY = point.y - worldY * next;
    applyViewTransform();
  }

  function moveNode(nodeId, deltaX, deltaY) {
    const position = state.treeView.positions.get(nodeId);
    if (!position) {
      return;
    }
    position.x += deltaX;
    position.y += deltaY;
    const group = byId("tree-nodes")
      .querySelector('[data-node-id="' + cssEscape(nodeId) + '"]');
    if (group) {
      group.setAttribute("transform", "translate(" + position.x + "," + position.y + ")");
    }
    byId("tree-edges").querySelectorAll(".graph-edge").forEach((path) => {
      if (path.dataset.parent !== nodeId && path.dataset.child !== nodeId) {
        return;
      }
      const parent = state.treeView.positions.get(path.dataset.parent);
      const child = state.treeView.positions.get(path.dataset.child);
      if (parent && child) {
        path.setAttribute("d", edgePath(parent, child));
      }
    });
  }

  function cssEscape(value) {
    return window.CSS && window.CSS.escape
      ? window.CSS.escape(value)
      : value.replace(/[^a-zA-Z0-9_-]/g, "\\$&");
  }

  function initializeGraphInteractions() {
    const svg = byId("tree-graph");
    svg.setAttribute("viewBox", "0 0 " + GRAPH.viewWidth + " " + GRAPH.viewHeight);

    svg.addEventListener("pointerdown", (event) => {
      const group = event.target.closest(".graph-node");
      const point = pointerToView(event);
      state.treeView.drag = {
        nodeId: group ? group.dataset.nodeId : null,
        lastX: point.x,
        lastY: point.y,
        moved: false
      };
      svg.setPointerCapture(event.pointerId);
    });

    svg.addEventListener("pointermove", (event) => {
      const drag = state.treeView.drag;
      if (!drag) {
        return;
      }
      const point = pointerToView(event);
      const deltaX = point.x - drag.lastX;
      const deltaY = point.y - drag.lastY;
      if (Math.abs(deltaX) + Math.abs(deltaY) > 1.5) {
        drag.moved = true;
      }
      drag.lastX = point.x;
      drag.lastY = point.y;
      if (drag.nodeId) {
        moveNode(drag.nodeId, deltaX / state.treeView.scale, deltaY / state.treeView.scale);
      } else {
        state.treeView.translateX += deltaX;
        state.treeView.translateY += deltaY;
        applyViewTransform();
      }
    });

    const endDrag = (event) => {
      const drag = state.treeView.drag;
      state.treeView.drag = null;
      if (svg.hasPointerCapture(event.pointerId)) {
        svg.releasePointerCapture(event.pointerId);
      }
      if (drag && drag.nodeId && !drag.moved) {
        selectGraphNode(drag.nodeId);
      }
    };
    svg.addEventListener("pointerup", endDrag);
    svg.addEventListener("pointercancel", endDrag);

    svg.addEventListener("wheel", (event) => {
      event.preventDefault();
      zoomBy(event.deltaY < 0 ? 1.12 : 1 / 1.12, pointerToView(event));
    }, { passive: false });

    svg.addEventListener("keydown", (event) => {
      const group = event.target.closest(".graph-node");
      if (!group) {
        return;
      }
      const nodeId = group.dataset.nodeId;
      const step = event.shiftKey ? 30 : 10;
      const moves = {
        ArrowLeft: [-step, 0],
        ArrowRight: [step, 0],
        ArrowUp: [0, -step],
        ArrowDown: [0, step]
      };
      if (moves[event.key]) {
        event.preventDefault();
        moveNode(nodeId, moves[event.key][0], moves[event.key][1]);
      } else if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectGraphNode(nodeId);
      }
    });

    byId("graph-zoom-in").addEventListener("click", () => zoomBy(1.2));
    byId("graph-zoom-out").addEventListener("click", () => zoomBy(1 / 1.2));
    byId("graph-fit").addEventListener("click", fitGraph);
    byId("graph-reset").addEventListener("click", () => renderTree(true));
  }

  function renderTree(resetLayout) {
    const tree = treeById(state.activeTree);
    const summary = byId("tree-summary");
    const notes = byId("tree-notes");
    summary.replaceChildren();
    notes.replaceChildren();
    if (!tree) {
      appendText(summary, "p", "", "No attack tree is available for this build.");
      return;
    }
    const plain = state.treeFormat === "plain";
    const scenario = tree.scenario_id ? scenarioById(tree.scenario_id) : null;

    setText("tree-origin", "Curated in the repository · citations verified at build time");

    appendText(summary, "p", "eyebrow",
      scenario ? scenario.name : tree.business_service);
    appendText(summary, "h3", "", plain ? tree.plain_name : tree.name);
    appendText(summary, "p", "", plain ? tree.plain_summary : tree.summary);
    const leaves = tree.nodes.filter((node) => node.operator === "LEAF").length;
    appendText(summary, "p", "tree-counts",
      tree.nodes.length + " steps · " + leaves + " individual actions" +
      (scenario ? " · priced as " + currency.format(scenario.assumptions.base_loss_gbp) +
        " per full traversal" : ""));

    const keepLayout = !resetLayout &&
      state.treeView.treeId === tree.tree_id &&
      state.treeView.positions.size === tree.nodes.length;
    if (!keepLayout) {
      state.treeView.positions = layoutTree(tree, plain);
      state.treeView.treeId = tree.tree_id;
      state.treeView.selected = tree.root_node_id;
    } else {
      // Re-wrap labels in place so switching register never loses a layout the
      // reader has arranged by hand.
      const nodes = new Map(tree.nodes.map((node) => [node.node_id, node]));
      state.treeView.positions.forEach((position, nodeId) => {
        const node = nodes.get(nodeId);
        position.lines = wrapLabel(plain ? node.plain_title : node.title, 27, 3);
        position.height = GRAPH.padding * 2 + 13 + position.lines.length * GRAPH.lineHeight;
      });
    }

    renderEdges(tree);
    renderNodes(tree, plain);
    renderNodeDetail(tree, plain);
    if (!keepLayout) {
      fitGraph();
    } else {
      applyViewTransform();
    }

    [
      ["Assumptions", tree.assumptions],
      [plain ? "What this does not prove" : "Limitations", tree.limitations]
    ].forEach(([label, values]) => {
      if (!values || !values.length) {
        return;
      }
      const block = document.createElement("div");
      appendText(block, "p", "eyebrow", label);
      const list = document.createElement("ul");
      values.forEach((value) => appendText(list, "li", "", value));
      block.append(list);
      notes.append(block);
    });

    syncMiniLab(scenario);
  }

  // ----------------------------------------------------------------------
  // A three-assumption view of the risk lab for the selected tree
  // ----------------------------------------------------------------------

  function initializeMiniLab() {
    ["mini-probability", "mini-loss", "mini-tolerance", "mini-countermeasure"].forEach((id) => {
      byId(id).addEventListener("input", () => {
        updateMiniOutputs();
        runMiniSimulation();
      });
    });
    byId("mini-open-full").addEventListener("click", () => {
      const scope = byId("simulation-scope");
      const tree = treeById(state.activeTree);
      if (tree && tree.scenario_id) {
        const scenario = scenarioById(tree.scenario_id);
        const enabled = Boolean(scenario && byId("mini-countermeasure").checked);
        scope.value = tree.scenario_id;
        document.querySelectorAll("[data-scenario-countermeasure]").forEach((checkbox) => {
          checkbox.checked = enabled &&
            checkbox.dataset.scenarioCountermeasure === scenario.id;
        });
        updateRunButton();
        runSimulation();
      }
      byId("simulation").scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  function syncMiniLab(scenario) {
    const lab = byId("mini-lab");
    if (!scenario) {
      lab.hidden = true;
      return;
    }
    lab.hidden = false;
    const assumptions = scenario.assumptions;
    byId("mini-probability").value = (
      assumptions.annual_event_probability *
      assumptions.conditional_loss_probability * 100
    ).toFixed(1);
    byId("mini-loss").value = assumptions.base_loss_gbp;
    byId("mini-tolerance").value = state.model.impact_tolerance_gbp;
    byId("mini-countermeasure").checked = false;
    renderMiniCost(scenario);
    updateMiniOutputs();
    runMiniSimulation();
  }

  function updateMiniOutputs() {
    setText("mini-probability-value",
      Number(byId("mini-probability").value).toFixed(1) + "% of years");
    setText("mini-loss-value", currency.format(Number(byId("mini-loss").value)));
    setText("mini-tolerance-value",
      currency.format(Number(byId("mini-tolerance").value)));
  }

  function renderMiniCost(scenario) {
    const rows = byId("mini-cost-rows");
    rows.replaceChildren();
    costBasisRows(scenario.cost_basis).forEach((item) => {
      const row = document.createElement("div");
      appendText(row, "dt", "", item.label);
      const value = document.createElement("dd");
      appendText(value, "strong", "", currency.format(item.amount_gbp));
      appendText(value, "small", "", item.source);
      row.append(value);
      rows.append(row);
    });
  }

  function controlById(controlId) {
    return state.model.controls.find((control) => control.id === controlId) || null;
  }

  function countermeasureCase(scenario) {
    const fallbackIds = state.model.controls
      .filter((control) => control.reductions && control.reductions[scenario.id])
      .map((control) => control.id);
    return scenario.countermeasure_case || {
      title: "Robust countermeasure",
      toggle_label: "Turn on robust countermeasure",
      summary: "Applies the selected tree's relevant countermeasures.",
      control_ids: fallbackIds,
      probability_rationale: []
    };
  }

  function countermeasureControlIds(scenario) {
    const details = countermeasureCase(scenario);
    const ids = Array.isArray(details.control_ids) ? details.control_ids : [];
    const known = ids.filter((controlId) => controlById(controlId));
    if (known.length) {
      return known;
    }
    return state.model.controls
      .filter((control) => control.reductions && control.reductions[scenario.id])
      .map((control) => control.id);
  }

  function countermeasureProbabilityText(probability, adjustedProbability, multipliers) {
    const frequencyReduction = probability > 0
      ? 1 - adjustedProbability / probability
      : 0;
    const magnitudeReduction = 1 - multipliers.magnitude;
    const parts = [];
    if (frequencyReduction > 0) {
      parts.push(percent.format(frequencyReduction) + " lower annual traversal chance");
    } else {
      parts.push("Traversal chance unchanged");
    }
    if (magnitudeReduction > 0) {
      parts.push(percent.format(magnitudeReduction) + " lower loss severity when it lands");
    }
    return parts.join("; ");
  }

  function costCategory(item) {
    return item.cost_type === "recurring" ? "recurring" : "one_time";
  }

  function renderBillGroup(container, title, items) {
    const group = document.createElement("div");
    group.className = "mini-bill-group";
    appendText(group, "h5", "", title);
    const subtotal = items.reduce((total, item) => total + item.amount, 0);
    if (items.length) {
      const rows = document.createElement("dl");
      items.forEach((item) => {
        const row = document.createElement("div");
        appendText(row, "dt", "", item.label);
        const value = document.createElement("dd");
        appendText(value, "strong", "", currency.format(item.amount));
        appendText(value, "small", "",
          item.controlName + ". " + (item.rationale || "First-year programme estimate."));
        row.append(value);
        rows.append(row);
      });
      group.append(rows);
    } else {
      appendText(group, "p", "mini-bill-empty", "No line items in this category.");
    }
    const subtotalRow = document.createElement("div");
    subtotalRow.className = "mini-bill-subtotal";
    appendText(subtotalRow, "span", "", "Subtotal");
    appendText(subtotalRow, "strong", "", currency.format(subtotal));
    group.append(subtotalRow);
    container.append(group);
  }

  function renderMiniPreventionBill(controlIds) {
    const bill = byId("mini-prevention-bill");
    bill.replaceChildren();
    const controls = controlIds.map((controlId) => controlById(controlId)).filter(Boolean);
    const items = [];
    controls.forEach((control) => {
      (control.cost_breakdown || []).forEach((item) => {
        items.push({
          type: costCategory(item),
          label: item.label,
          amount: Number(item.amount_gbp || 0),
          rationale: item.rationale || control.cost_source || "",
          controlName: control.short_name || control.name
        });
      });
    });
    const total = items.reduce((sum, item) => sum + item.amount, 0);
    const recurring = items.filter((item) => item.type === "recurring");
    const oneTime = items.filter((item) => item.type !== "recurring");
    setText("mini-prevention-title",
      controls.map((control) => control.short_name || control.name).join(" + "));
    setText("mini-prevention-total", currency.format(total));
    renderBillGroup(bill, "Recurring tooling and monitoring", recurring);
    renderBillGroup(bill, "One-time engineering and rollout", oneTime);
  }

  function renderMiniCountermeasure(scenario) {
    const details = countermeasureCase(scenario);
    const controlIds = countermeasureControlIds(scenario);
    const enabled = byId("mini-countermeasure").checked && controlIds.length > 0;
    setText("mini-countermeasure-title",
      details.toggle_label || "Turn on robust countermeasure");
    setText("mini-countermeasure-summary",
      details.summary || "Applies this tree's recommended prevention package.");
    const panel = byId("mini-countermeasure-panel");
    panel.hidden = !enabled;
    if (!enabled) {
      return;
    }

    const probability = clamp(Number(byId("mini-probability").value) / 100, 0, 1);
    const multipliers = controlMultipliers(scenario.id, controlIds);
    const adjustedProbability = probability * multipliers.frequency;
    setText("mini-probability-before", percent.format(probability));
    setText("mini-probability-after", percent.format(adjustedProbability));
    setText("mini-probability-change",
      countermeasureProbabilityText(probability, adjustedProbability, multipliers));

    const reasons = byId("mini-countermeasure-reasons");
    reasons.replaceChildren();
    const explicitReasons = Array.isArray(details.probability_rationale)
      ? details.probability_rationale
      : [];
    explicitReasons.forEach((reason) => appendText(reasons, "li", "", reason));
    if (!reasons.children.length) {
      controlIds.forEach((controlId) => {
        const control = controlById(controlId);
        const reduction = control && control.reductions
          ? control.reductions[scenario.id]
          : null;
        if (!control || !reduction) {
          return;
        }
        const parts = [];
        if (reduction.frequency) {
          parts.push(percent.format(reduction.frequency) + " frequency reduction");
        }
        if (reduction.magnitude) {
          parts.push(percent.format(reduction.magnitude) + " loss-severity reduction");
        }
        appendText(reasons, "li", "",
          control.short_name + " contributes " + parts.join(" and ") + ".");
      });
    }
    renderMiniPreventionBill(controlIds);
  }

  function runMiniSimulation() {
    const tree = treeById(state.activeTree);
    const scenario = tree && tree.scenario_id ? scenarioById(tree.scenario_id) : null;
    if (!scenario) {
      return;
    }
    const probability = clamp(Number(byId("mini-probability").value) / 100, 0, 1);
    const loss = Number(byId("mini-loss").value);
    const tolerance = Number(byId("mini-tolerance").value);
    const controlIds = byId("mini-countermeasure").checked
      ? countermeasureControlIds(scenario)
      : [];
    // One slider stands in for the two probabilities the full lab exposes:
    // their product is the chance of a full traversal, which is the only thing
    // this view claims to model.
    const simple = {
      ...scenario,
      assumptions: {
        ...scenario.assumptions,
        annual_event_probability: probability,
        conditional_loss_probability: 1,
        base_loss_gbp: loss
      }
    };
    const result = simulatePortfolio(
      [simple],
      state.model.iterations,
      state.model.seed,
      tolerance,
      controlIds
    );
    const quietYears = result.losses.filter((loss) => loss <= 0).length;
    const quietShare = quietYears / result.losses.length;
    setText("mini-mean", currency.format(result.mean));
    setText("mini-p99", currency.format(result.p99));
    setText("mini-exceed", percent.format(result.exceedance));
    setText("mini-exceed-note", "years above " + currency.format(tolerance));
    byId("mini-exceed-card").className =
      result.exceedance > 0.05 ? "mini-over" : "mini-within";
    const mode = controlIds.length
      ? "with the robust countermeasure on"
      : "with the robust countermeasure off";
    setText("mini-sentence",
      "Running " + mode + ", " + percent.format(quietShare) + " of the " +
      integer.format(result.iterations) + " simulated years cost nothing at all, and " +
      percent.format(result.exceedance) + " of them went past the " +
      currency.format(tolerance) + " the bank says it can absorb. The worst year in " +
      "a hundred cost " + currency.format(result.p99) + ", and averaged over every " +
      "year the cost is " + currency.format(result.mean) + ".");
    renderMiniCountermeasure(scenario);
    renderMiniStrip(result, quietShare);
  }

  function renderMiniStrip(result, quietShare) {
    // Most simulated years cost nothing, and a bar for those swamps everything
    // else. The strip therefore shows only the years where the tree succeeded,
    // and the caption carries the quiet years as a number instead.
    const strip = byId("mini-strip");
    strip.replaceChildren();
    const losses = result.losses.filter((loss) => loss > 0);
    const ceiling = Math.max(result.p99, result.tolerance, 1);
    const bins = 24;
    const counts = new Array(bins).fill(0);
    losses.forEach((loss) => {
      counts[Math.min(bins - 1, Math.floor(loss / ceiling * bins))] += 1;
    });
    const peak = Math.max(...counts, 1);
    const toleranceBin = Math.min(bins - 1, Math.floor(result.tolerance / ceiling * bins));
    counts.forEach((count, index) => {
      const bar = document.createElement("span");
      bar.className = index >= toleranceBin ? "mini-bar over" : "mini-bar";
      bar.style.height = Math.max(2, count / peak * 100) + "%";
      strip.append(bar);
    });
    setText("mini-strip-caption",
      "Years in which the tree succeeded, from nothing on the left to " +
      compactCurrency(ceiling) + " on the right. Amber bars are above the " +
      "tolerance. The other " + percent.format(quietShare) + " of years cost nothing " +
      "and are not shown.");
  }

  function plainKind(node) {
    if (node.kind === "GOAL") {
      return "What the attacker wants";
    }
    return node.kind === "SUBGOAL" ? "Something that has to work" : "A single step";
  }

  function humanEvidence(identifier) {
    const flow = state.flowsById.get(identifier);
    if (flow) {
      return flow.route
        ? flow.name + " (" + flow.route.method + " " + flow.route.path + ")"
        : flow.name;
    }
    const node = state.nodesById.get(identifier);
    if (node) {
      return node.label || identifier;
    }
    return identifier;
  }

  async function initialize() {
    try {
      const [graph, model, manifest, trees] = await Promise.all([
        loadJson("data/bantam-graph.json"),
        loadJson("data/risk-model.json"),
        loadJson("build-manifest.json"),
        loadJson("data/attack-trees.json")
      ]);
      state.graph = graph;
      state.model = model;
      state.manifest = manifest;
      state.trees = trees.trees;
      initializeSnapshot();
      initializeGraphControls();
      initializeModelControls();
      renderBusinessProfile();
      initializeAttackTreeControls();
      initializeTreeExplorer();
      renderSources();
      setText("simulation-status", "Ready. Default assumptions have been loaded.");
      runSimulation();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const errorElement = byId("load-error");
      errorElement.hidden = false;
      errorElement.textContent =
        "The interactive evidence could not be loaded. Serve the generated site over " +
        "HTTP and verify its build artifact. " + message;
    }
  }

  initialize();
})();
