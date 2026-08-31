"""Published attack trees stay grounded in the graph the build ships."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts.attack_tree_library import (
    AttackTreeLibraryError,
    PROMPT_LIMITS,
    decorate,
    model_facing_schema,
    parse_tree_set,
    structural_error,
    request_descriptor,
    technique_url,
    validate_library,
)
from scripts.generate_attack_trees import reduce_projection
from scripts.resilience_report import (
    _read_mapping,
    build_public_projection,
    collect_repository_evidence,
)
from bantam.workflow_graph import load_catalog


ROOT = Path(__file__).resolve().parents[1]
LIBRARY_PATH = ROOT / "report" / "attack-trees.json"


def _projection() -> dict:
    return build_public_projection(
        load_catalog(),
        _read_mapping(ROOT / "report" / "risk-model.json", label="risk model"),
        source_commit="local",
        repository_evidence=collect_repository_evidence(ROOT),
    )


def _identifiers(projection: dict) -> tuple[set[str], set[str]]:
    return (
        {flow["id"] for flow in projection["flows"]},
        {node["id"] for node in projection["nodes"]},
    )


def _library() -> dict:
    return json.loads(LIBRARY_PATH.read_text(encoding="utf-8"))


def _validated() -> dict:
    projection = _projection()
    flow_ids, node_ids = _identifiers(projection)
    return validate_library(_library(), flow_ids=flow_ids, graph_node_ids=node_ids)


def test_curated_trees_cite_only_evidence_this_build_publishes() -> None:
    projection = _projection()
    flow_ids, node_ids = _identifiers(projection)
    library = validate_library(_library(), flow_ids=flow_ids, graph_node_ids=node_ids)
    assert len(library["trees"]) >= 2
    for tree in library["trees"]:
        for node in tree["nodes"]:
            cited = set(node["flow_ids"]) | set(node["graph_node_ids"])
            assert cited
            assert cited <= flow_ids | node_ids


def test_every_step_is_written_in_both_registers() -> None:
    for tree in _validated()["trees"]:
        assert tree["plain_name"] != tree["name"]
        assert tree["plain_summary"] != tree["summary"]
        for node in tree["nodes"]:
            assert node["plain_title"] and node["plain_description"]
            assert node["plain_title"] != node["title"]
            assert node["plain_description"] != node["description"]


def test_plain_english_avoids_technique_identifiers() -> None:
    for tree in _validated()["trees"]:
        plain = " ".join(
            [tree["plain_name"], tree["plain_summary"]]
            + [node["plain_title"] for node in tree["nodes"]]
            + [node["plain_description"] for node in tree["nodes"]]
        )
        for node in tree["nodes"]:
            for technique in node["mitre_techniques"]:
                assert technique["technique_id"] not in plain
                assert technique["name"] not in plain


def test_attack_links_are_rebuilt_and_never_taken_from_storage() -> None:
    poisoned = _library()
    technique = poisoned["trees"][0]["nodes"][0]["mitre_techniques"][0]
    technique["url"] = "https://example.invalid/not-mitre"
    decorated = decorate(poisoned)
    assert decorated["trees"][0]["nodes"][0]["mitre_techniques"][0]["url"] == (
        "https://attack.mitre.org/techniques/"
        + technique["technique_id"].split(".")[0]
        + "/"
    )


def test_technique_url_handles_sub_techniques_and_rejects_rubbish() -> None:
    assert technique_url("T1078.004").endswith("/techniques/T1078/004/")
    assert technique_url("T1078").endswith("/techniques/T1078/")
    with pytest.raises(AttackTreeLibraryError):
        technique_url("not-a-technique")


def test_a_decorated_library_still_validates() -> None:
    projection = _projection()
    flow_ids, node_ids = _identifiers(projection)
    once = validate_library(_library(), flow_ids=flow_ids, graph_node_ids=node_ids)
    twice = validate_library(once, flow_ids=flow_ids, graph_node_ids=node_ids)
    assert twice["trees"][0]["origin"] == "CURATED"


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda tree: tree["edges"].append(
                [tree["nodes"][-1]["node_id"], tree["nodes"][1]["node_id"]]
            ),
            id="leaf-with-children",
        ),
        pytest.param(
            lambda tree: tree.__setitem__("root_node_id", "attack:not-present"),
            id="missing-root",
        ),
        pytest.param(
            lambda tree: tree["nodes"][1].__setitem__("kind", "GOAL"),
            id="second-goal",
        ),
        pytest.param(lambda tree: tree["edges"].pop(), id="orphaned-node"),
    ],
)
def test_structurally_broken_trees_are_rejected(mutate) -> None:
    tree = copy.deepcopy(_library()["trees"][0])
    mutate(tree)
    parsed = parse_tree_set({"schema_version": "1.0", "trees": [tree]})
    assert structural_error(parsed.trees[0]) is not None


def test_a_tree_citing_an_unknown_flow_fails_the_build() -> None:
    library = _library()
    library["trees"][0]["nodes"][0]["flow_ids"] = ["default:post:/v1/does-not-exist"]
    with pytest.raises(AttackTreeLibraryError, match="unknown flows"):
        validate_library(
            library, flow_ids={"default:post:/v1/transfers"}, graph_node_ids=set()
        )


def test_a_tree_citing_an_unknown_graph_node_fails_the_build() -> None:
    projection = _projection()
    flow_ids, node_ids = _identifiers(projection)
    library = _library()
    library["trees"][0]["nodes"][0]["graph_node_ids"] = ["function:not.real"]
    with pytest.raises(AttackTreeLibraryError, match="unknown graph nodes"):
        validate_library(library, flow_ids=flow_ids, graph_node_ids=node_ids)


def test_a_step_with_no_evidence_fails_the_build() -> None:
    projection = _projection()
    flow_ids, node_ids = _identifiers(projection)
    library = _library()
    library["trees"][0]["nodes"][1]["flow_ids"] = []
    library["trees"][0]["nodes"][1]["graph_node_ids"] = []
    with pytest.raises(AttackTreeLibraryError, match="cites no code evidence"):
        validate_library(library, flow_ids=flow_ids, graph_node_ids=node_ids)


def test_the_model_is_never_asked_for_fields_bantam_derives() -> None:
    schema = model_facing_schema()
    assert "origin" not in schema["$defs"]["AttackTree"]["properties"]
    assert "url" not in schema["$defs"]["MitreTechnique"]["properties"]


def test_the_published_request_contract_is_bounded_and_declares_its_boundary() -> None:
    descriptor = request_descriptor()
    assert descriptor["endpoint"] == "https://api.mistral.ai/v1/chat/completions"
    assert descriptor["temperature"] == 0
    assert descriptor["limits"] == PROMPT_LIMITS
    assert "never stored" in descriptor["disclosure"]
    assert "untrusted data" in descriptor["system"]


def test_the_prompt_projection_is_reduced_and_carries_no_raw_sql() -> None:
    reduced = reduce_projection(_projection())
    encoded = json.dumps(reduced)
    assert len(encoded) <= PROMPT_LIMITS["max_bytes"]
    assert len(reduced["flows"]) <= PROMPT_LIMITS["max_flows"]
    assert len(reduced["nodes"]) <= PROMPT_LIMITS["max_nodes"]
    assert len(reduced["edges"]) <= PROMPT_LIMITS["max_edges"]
    assert '"sql"' not in encoded
    assert all("sql" not in node for node in reduced["nodes"])


def test_each_curated_tree_prices_a_real_risk_scenario() -> None:
    model = _read_mapping(ROOT / "report" / "risk-model.json", label="risk model")
    scenario_ids = {scenario["id"] for scenario in model["scenarios"]}
    linked = {tree["scenario_id"] for tree in _validated()["trees"]}
    # Selecting a tree runs the simple lab for its scenario, so every scenario
    # needs a tree and every tree needs a scenario that still exists.
    assert linked == scenario_ids


def test_a_tree_naming_an_unknown_scenario_fails_the_build() -> None:
    projection = _projection()
    flow_ids, node_ids = _identifiers(projection)
    library = _library()
    library["trees"][0]["scenario_id"] = "not-a-scenario"
    with pytest.raises(AttackTreeLibraryError, match="unknown risk scenario"):
        validate_library(
            library,
            flow_ids=flow_ids,
            graph_node_ids=node_ids,
            scenario_ids={"payment-integrity"},
        )


def test_a_generated_tree_may_leave_the_scenario_link_empty() -> None:
    projection = _projection()
    flow_ids, node_ids = _identifiers(projection)
    library = _library()
    library["trees"] = library["trees"][:1]
    library["trees"][0]["scenario_id"] = ""
    validated = validate_library(
        library, flow_ids=flow_ids, graph_node_ids=node_ids, scenario_ids=set()
    )
    assert validated["trees"][0]["scenario_id"] == ""


def test_every_tree_is_shallow_enough_to_lay_out_on_one_canvas() -> None:
    for tree in _validated()["trees"]:
        children: dict[str, list[str]] = {node["node_id"]: [] for node in tree["nodes"]}
        for parent, child in tree["edges"]:
            children[parent].append(child)
        depths = {tree["root_node_id"]: 1}
        queue = [tree["root_node_id"]]
        while queue:
            current = queue.pop()
            for child in children[current]:
                depths[child] = depths[current] + 1
                queue.append(child)
        assert max(depths.values()) <= 4, tree["tree_id"]
        assert len(depths) == len(tree["nodes"])
