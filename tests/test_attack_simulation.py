"""Attack-tree grounding, Monte Carlo determinism, and remediation boundaries."""

from __future__ import annotations

import copy
import json

from bantam.attack_simulation import (
    build_remediation_request,
    build_scenario_request,
    build_software_inventory,
    generate_attack_scenarios,
    generate_remediations,
    programme_economics,
    simulate_scenario,
)
from bantam.financials import load_default_profile
from bantam.repository_graph import ModelOutput, redacted_graph_projection
from bantam.workflow_graph import load_catalog


class _StubModelsClient:
    """Return a fixed response and keep the request for boundary assertions."""

    def __init__(self, content: str) -> None:
        self.content = content
        self.requests: list[dict[str, object]] = []

    def generate(self, request_body: dict[str, object]) -> ModelOutput:
        self.requests.append(request_body)
        return ModelOutput(
            content=self.content,
            request_id="req_test",
            input_tokens=100,
            output_tokens=200,
        )


def _catalog() -> dict[str, object]:
    return load_catalog()


def _sample_ids(count: int = 3) -> list[str]:
    projection = redacted_graph_projection(_catalog())
    return [node["id"] for node in projection["nodes"][:count]]


def _tree(prefix: str, node_ids: list[str]) -> dict[str, object]:
    """A minimal structurally valid tree: one goal over two leaf actions."""

    return {
        "title": f"{prefix} attack tree over Bantam evidence",
        "root_attack_node_id": f"attack:{prefix}-root",
        "nodes": [
            {
                "attack_node_id": f"attack:{prefix}-root",
                "title": "Reach the attacker goal",
                "description": "Combine one of the available actions to reach the goal.",
                "kind": "GOAL",
                "operator": "OR",
                "graph_node_ids": node_ids[:1],
                "flow_ids": [],
                "mitre_technique_ids": ["T1078"],
                "success_probability": 0.5,
                "detection_probability": 0.1,
            },
            {
                "attack_node_id": f"attack:{prefix}-first",
                "title": "Abuse a valid account",
                "description": "Use credentials obtained outside Bantam to sign in.",
                "kind": "ACTION",
                "operator": "LEAF",
                "graph_node_ids": node_ids[:2],
                "flow_ids": [],
                "mitre_technique_ids": ["T1078"],
                "success_probability": 0.2,
                "detection_probability": 0.3,
            },
            {
                "attack_node_id": f"attack:{prefix}-second",
                "title": "Tamper with stored data",
                "description": "Alter durable state through an insufficiently guarded path.",
                "kind": "ACTION",
                "operator": "LEAF",
                "graph_node_ids": node_ids[:1],
                "flow_ids": [],
                "mitre_technique_ids": [],
                "success_probability": 0.05,
                "detection_probability": 0.5,
            },
        ],
        "edges": [
            {
                "parent_attack_node_id": f"attack:{prefix}-root",
                "child_attack_node_id": f"attack:{prefix}-first",
            },
            {
                "parent_attack_node_id": f"attack:{prefix}-root",
                "child_attack_node_id": f"attack:{prefix}-second",
            },
        ],
        "assumptions": ["Credential theft happens outside Bantam."],
        "limitations": ["The projection may be incomplete."],
    }


def _scenario(prefix: str, node_ids: list[str]) -> dict[str, object]:
    return {
        "scenario_id": f"scenario:{prefix}",
        "name": f"{prefix.title()} loss scenario",
        "business_service": "Move synthetic GBP and keep the ledger attributable",
        "narrative": "An adversary reaches a payment path and moves value before review contains it.",
        "mitre_techniques": [
            {
                "technique_id": "T1078",
                "name": "Valid Accounts",
                "tactic": "Initial Access",
            }
        ],
        "attack_tree": _tree(prefix, node_ids),
        "financials": {
            "annual_attempt_frequency": 6.0,
            "primary_loss": {
                "minimum_gbp": 50_000,
                "most_likely_gbp": 450_000,
                "maximum_gbp": 3_200_000,
            },
            "secondary_loss": {
                "minimum_gbp": 25_000,
                "most_likely_gbp": 180_000,
                "maximum_gbp": 1_400_000,
            },
            "detected_loss_multiplier": 0.35,
            "rationale": "Sized against daily payment volume and the regulatory penalty ceiling.",
            "financial_inputs_used": [
                "operations.daily_payment_volume_gbp",
                "regulatory.maximum_penalty_pct_of_revenue",
            ],
        },
    }


def _scenario_set(node_ids: list[str]) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "summary": "Two severe but plausible scenarios drawn from the current graph.",
        "scenarios": [_scenario("payments", node_ids), _scenario("identity", node_ids)],
        "assumptions": ["Frequencies are judgements, not measured incident data."],
        "limitations": ["No exploitability was demonstrated."],
    }


def _remediation_plan(scenario: dict[str, object]) -> dict[str, object]:
    leaf = next(
        node["attack_node_id"]
        for node in scenario["attack_tree"]["nodes"]
        if node["operator"] == "LEAF"
    )
    return {
        "schema_version": "1.0",
        "summary": "Reduce the two leaf actions that carried the simulated events.",
        "remediations": [
            {
                "remediation_id": "fix:step-up-auth",
                "title": "Require step-up authentication on value movement",
                "description": "Challenge every transfer above a threshold with a second factor bound to the device.",
                "mitre_mitigation_ids": ["M1032"],
                "target_attack_node_ids": [leaf],
                "graph_node_ids": [],
                "software_component_ids": [],
                "implementation_effort": "WEEKS",
                "priority": "HIGH",
                "estimated_cost_gbp": 60_000,
                "annual_run_cost_gbp": 12_000,
                "success_probability_reduction": 0.6,
                "detection_probability_uplift": 0.3,
                "residual_risk_note": "Session hijack after a successful challenge remains possible.",
                "evidence_rationale": "This step carried the largest share of successful simulated events.",
            },
            {
                "remediation_id": "fix:velocity-alerting",
                "title": "Alert on abnormal payment velocity",
                "description": "Detect unusual transfer sequences and hold them for review before settlement.",
                "mitre_mitigation_ids": [],
                "target_attack_node_ids": [leaf],
                "graph_node_ids": [],
                "software_component_ids": [],
                "implementation_effort": "MONTHS",
                "priority": "MEDIUM",
                "estimated_cost_gbp": 40_000,
                "annual_run_cost_gbp": 20_000,
                "success_probability_reduction": 0.0,
                "detection_probability_uplift": 0.5,
                "residual_risk_note": "Detection shortens dwell time but does not prevent the first event.",
                "evidence_rationale": "Detected events attract the reduced loss multiplier in the simulation.",
            },
        ],
        "monitoring": ["Track the share of held transfers that are genuine fraud."],
        "assumptions": ["Effect sizes are engineering judgements."],
        "limitations": ["No vendor quotes informed the costs."],
    }


def test_software_inventory_cites_only_real_graph_nodes() -> None:
    catalog = _catalog()
    inventory = build_software_inventory(catalog)
    known = {node["id"] for node in catalog["nodes"]}
    component_ids = {item["component_id"] for item in inventory["components"]}
    assert {"software:http-api", "software:postgresql"} <= component_ids
    for component in inventory["components"]:
        assert set(component["evidence_node_ids"]) <= known
        assert component["detection_rule"]


def test_scenario_prompt_carries_graph_software_and_financial_context() -> None:
    catalog = _catalog()
    profile = load_default_profile()
    request, projection = build_scenario_request(
        catalog, profile, build_software_inventory(catalog), scenario_count=3
    )
    prompt = request["messages"][1]["content"]
    assert "GRAPH_JSON=" in prompt
    assert "SOFTWARE_JSON=" in prompt
    assert "FINANCIALS_JSON=" in prompt
    assert str(profile["income"]["annual_revenue_gbp"]) in prompt
    # The projection publishes table-level effects, never query bodies.
    assert all("sql" not in node for node in projection["nodes"])
    assert request["temperature"] == 0


def test_valid_model_output_is_stored_with_bantam_built_attack_urls() -> None:
    catalog = _catalog()
    client = _StubModelsClient(json.dumps(_scenario_set(_sample_ids())))
    result = generate_attack_scenarios(
        catalog,
        load_default_profile(),
        build_software_inventory(catalog),
        client,
    )
    assert result["status"] == "READY"
    scenarios = result["scenario_set"]["scenarios"]
    assert len(scenarios) == 2
    assert scenarios[0]["mitre_techniques"][0]["url"] == (
        "https://attack.mitre.org/techniques/T1078/"
    )
    assert result["provenance"]["graph_digest"] == catalog["graph_digest"]


def test_scenario_citing_an_unknown_graph_node_is_rejected() -> None:
    catalog = _catalog()
    payload = _scenario_set(_sample_ids())
    payload["scenarios"][0]["attack_tree"]["nodes"][1]["graph_node_ids"] = [
        "function:not.a.real.symbol"
    ]
    result = generate_attack_scenarios(
        catalog,
        load_default_profile(),
        build_software_inventory(catalog),
        _StubModelsClient(json.dumps(payload)),
    )
    assert result["status"] == "FAILED"
    assert result["error_code"] == "ATTACK_SCENARIO_REFERENCE_INVALID"
    assert result["scenario_set"] is None


def test_scenario_citing_an_invented_financial_input_is_rejected() -> None:
    catalog = _catalog()
    payload = _scenario_set(_sample_ids())
    payload["scenarios"][0]["financials"]["financial_inputs_used"] = [
        "income.imaginary_line"
    ]
    result = generate_attack_scenarios(
        catalog,
        load_default_profile(),
        build_software_inventory(catalog),
        _StubModelsClient(json.dumps(payload)),
    )
    assert result["error_code"] == "ATTACK_SCENARIO_FINANCIAL_INPUT_INVALID"


def test_scenario_using_a_technique_it_never_declared_is_rejected() -> None:
    catalog = _catalog()
    payload = _scenario_set(_sample_ids())
    payload["scenarios"][0]["attack_tree"]["nodes"][1]["mitre_technique_ids"] = [
        "T9999"
    ]
    result = generate_attack_scenarios(
        catalog,
        load_default_profile(),
        build_software_inventory(catalog),
        _StubModelsClient(json.dumps(payload)),
    )
    assert result["error_code"] == "ATTACK_SCENARIO_TECHNIQUE_INVALID"


def test_structurally_broken_tree_is_rejected() -> None:
    catalog = _catalog()
    payload = _scenario_set(_sample_ids())
    # A leaf that owns children contradicts the LEAF operator.
    payload["scenarios"][0]["attack_tree"]["edges"].append(
        {
            "parent_attack_node_id": "attack:payments-first",
            "child_attack_node_id": "attack:payments-second",
        }
    )
    result = generate_attack_scenarios(
        catalog,
        load_default_profile(),
        build_software_inventory(catalog),
        _StubModelsClient(json.dumps(payload)),
    )
    assert result["error_code"] == "ATTACK_SCENARIO_TREE_INVALID"


def test_generation_is_skipped_and_disabled_without_a_client() -> None:
    catalog = _catalog()
    profile = load_default_profile()
    inventory = build_software_inventory(catalog)
    skipped = generate_attack_scenarios(
        catalog, profile, inventory, None, requested=False
    )
    disabled = generate_attack_scenarios(catalog, profile, inventory, None)
    assert skipped["status"] == "SKIPPED"
    assert disabled["status"] == "DISABLED"
    assert disabled["error_code"] == "MISTRAL_NOT_CONFIGURED"


def test_simulation_is_reproducible_from_its_seed() -> None:
    scenario = _scenario("payments", _sample_ids())
    profile = load_default_profile()
    first = simulate_scenario(scenario, profile, iterations=2_000, seed=7)
    again = simulate_scenario(scenario, profile, iterations=2_000, seed=7)
    different = simulate_scenario(scenario, profile, iterations=2_000, seed=8)
    assert first["annual_loss"] == again["annual_loss"]
    assert first["annual_loss"]["mean_gbp"] != different["annual_loss"]["mean_gbp"]


def test_or_branches_are_tried_in_order_until_one_succeeds() -> None:
    scenario = _scenario("payments", _sample_ids())
    nodes = scenario["attack_tree"]["nodes"]
    nodes[1]["success_probability"] = 0.99
    nodes[2]["success_probability"] = 0.99
    result = simulate_scenario(
        scenario, load_default_profile(), iterations=2_000, seed=3
    )
    shares = {
        row["attack_node_id"]: row["share_of_successful_events"]
        for row in result["attack_path_contributions"]
    }
    # The preferred branch nearly always works, so the fallback rarely runs.
    assert shares["attack:payments-first"] > 0.9
    assert shares["attack:payments-second"] < 0.1


def test_an_and_branch_needs_every_child() -> None:
    scenario = _scenario("payments", _sample_ids())
    tree = scenario["attack_tree"]
    tree["nodes"][0]["operator"] = "AND"
    tree["nodes"][1]["success_probability"] = 0.99
    tree["nodes"][2]["success_probability"] = 0.001
    result = simulate_scenario(
        scenario, load_default_profile(), iterations=2_000, seed=5
    )
    assert result["expected_events_per_year"] < 0.05


def test_insurance_retention_caps_the_loss_kept_from_one_event() -> None:
    scenario = _scenario("payments", _sample_ids())
    scenario["attack_tree"]["nodes"][1]["success_probability"] = 0.99
    scenario["financials"]["annual_attempt_frequency"] = 1.0
    profile = load_default_profile()
    profile["insurance"] = {"cyber_cover_gbp": 25_000_000, "retention_gbp": 100_000}
    result = simulate_scenario(scenario, profile, iterations=2_000, seed=11)
    # Every modelled event costs more than the retention gross, so the bank keeps
    # exactly the retention each time and an annual loss is always a multiple of it.
    assert result["annual_loss"]["maximum_gbp"] % 100_000 == 0
    assert result["annual_loss"]["p95_gbp"] % 100_000 == 0
    assert result["gross_mean_annual_loss_gbp"] > result["annual_loss"]["mean_gbp"]


def test_single_event_loss_is_capped_by_the_maximum_credible_loss() -> None:
    scenario = _scenario("payments", _sample_ids())
    scenario["attack_tree"]["nodes"][1]["success_probability"] = 0.99
    scenario["financials"]["primary_loss"] = {
        "minimum_gbp": 900_000_000,
        "most_likely_gbp": 950_000_000,
        "maximum_gbp": 999_000_000,
    }
    profile = load_default_profile()
    profile["insurance"] = {"cyber_cover_gbp": 0, "retention_gbp": 0}
    result = simulate_scenario(scenario, profile, iterations=1_000, seed=13)
    cap = profile["risk_appetite"]["maximum_credible_single_loss_gbp"]
    # Loss ranges far beyond the balance sheet are clamped event by event, so a
    # year's loss is a whole number of capped events rather than an unbounded tail.
    assert result["capped_event_share"] == 1.0
    assert result["annual_loss"]["maximum_gbp"] % cap == 0


def test_applying_remediations_lowers_the_modelled_loss() -> None:
    scenario = _scenario("payments", _sample_ids())
    profile = load_default_profile()
    plan = _remediation_plan(scenario)
    baseline = simulate_scenario(scenario, profile, iterations=4_000, seed=21)
    residual = simulate_scenario(
        scenario,
        profile,
        iterations=4_000,
        seed=21,
        remediations=plan["remediations"],
    )
    assert residual["annual_loss"]["mean_gbp"] < baseline["annual_loss"]["mean_gbp"]
    assert residual["applied_remediation_ids"] == [
        "fix:step-up-auth",
        "fix:velocity-alerting",
    ]
    economics = programme_economics(baseline, residual, plan["remediations"])
    assert economics["first_year_cost_gbp"] == 132_000
    assert economics["annual_loss_reduction_gbp"] > 0


def test_programme_economics_reports_no_payback_when_running_costs_dominate() -> None:
    scenario = _scenario("payments", _sample_ids())
    profile = load_default_profile()
    baseline = simulate_scenario(scenario, profile, iterations=1_000, seed=31)
    expensive = [
        {
            "remediation_id": "fix:gold-plating",
            "estimated_cost_gbp": 5_000_000,
            "annual_run_cost_gbp": 5_000_000,
        }
    ]
    economics = programme_economics(baseline, baseline, expensive)
    assert economics["annual_loss_reduction_gbp"] == 0
    assert economics["payback_years"] is None


def test_remediation_prompt_reports_the_simulated_contributions() -> None:
    catalog = _catalog()
    scenario = _scenario("payments", _sample_ids())
    profile = load_default_profile()
    simulation = simulate_scenario(scenario, profile, iterations=1_000, seed=41)
    request = build_remediation_request(
        scenario, simulation, profile, build_software_inventory(catalog), []
    )
    prompt = request["messages"][1]["content"]
    assert "SIMULATION_JSON=" in prompt
    assert "attack:payments-first" in prompt
    assert "share_of_successful_events" in prompt


def test_remediation_targeting_an_unknown_step_is_rejected() -> None:
    catalog = _catalog()
    scenario = _scenario("payments", _sample_ids())
    profile = load_default_profile()
    simulation = simulate_scenario(scenario, profile, iterations=1_000, seed=43)
    plan = copy.deepcopy(_remediation_plan(scenario))
    plan["remediations"][0]["target_attack_node_ids"] = ["attack:not-in-this-tree"]
    result = generate_remediations(
        scenario,
        simulation,
        profile,
        build_software_inventory(catalog),
        [],
        _StubModelsClient(json.dumps(plan)),
    )
    assert result["status"] == "FAILED"
    assert result["error_code"] == "REMEDIATION_REFERENCE_INVALID"
    assert result["plan"] is None


def test_remediation_that_touches_no_action_is_rejected() -> None:
    catalog = _catalog()
    scenario = _scenario("payments", _sample_ids())
    profile = load_default_profile()
    simulation = simulate_scenario(scenario, profile, iterations=1_000, seed=47)
    plan = copy.deepcopy(_remediation_plan(scenario))
    plan["remediations"][0]["target_attack_node_ids"] = ["attack:payments-root"]
    result = generate_remediations(
        scenario,
        simulation,
        profile,
        build_software_inventory(catalog),
        [],
        _StubModelsClient(json.dumps(plan)),
    )
    assert result["error_code"] == "REMEDIATION_TARGETS_NO_ACTION"


def test_remediation_naming_unknown_software_is_rejected() -> None:
    catalog = _catalog()
    scenario = _scenario("payments", _sample_ids())
    profile = load_default_profile()
    simulation = simulate_scenario(scenario, profile, iterations=1_000, seed=53)
    plan = copy.deepcopy(_remediation_plan(scenario))
    plan["remediations"][0]["software_component_ids"] = ["software:acme-waf"]
    result = generate_remediations(
        scenario,
        simulation,
        profile,
        build_software_inventory(catalog),
        [],
        _StubModelsClient(json.dumps(plan)),
    )
    assert result["error_code"] == "REMEDIATION_SOFTWARE_INVALID"


def test_valid_remediations_gain_bantam_built_mitigation_urls() -> None:
    catalog = _catalog()
    scenario = _scenario("payments", _sample_ids())
    profile = load_default_profile()
    simulation = simulate_scenario(scenario, profile, iterations=1_000, seed=59)
    result = generate_remediations(
        scenario,
        simulation,
        profile,
        build_software_inventory(catalog),
        [],
        _StubModelsClient(json.dumps(_remediation_plan(scenario))),
    )
    assert result["status"] == "READY"
    assert result["plan"]["remediations"][0]["mitre_mitigation_urls"] == [
        "https://attack.mitre.org/mitigations/M1032/"
    ]
