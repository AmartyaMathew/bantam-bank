from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from scripts.resilience_report import (
    ResilienceReportError,
    build_public_projection,
    build_site,
    collect_repository_evidence,
)


ROOT = Path(__file__).resolve().parents[1]


def _catalogue() -> dict:
    route_id = "route:POST:/v1/example"
    function_id = "function:example.create"
    effect_id = "sql:example.create:abc:1"
    return {
        "version": 1,
        "generator": "test",
        "graph_digest": "a" * 64,
        "nodes": [
            {
                "id": route_id,
                "kind": "route",
                "label": "POST /v1/example",
                "file": "example.py",
                "line": 10,
                "function_symbol": "example.create",
                "signature": "def create()",
            },
            {
                "id": function_id,
                "kind": "function",
                "label": "Create",
                "file": "example.py",
                "line": 11,
                "function_symbol": "example.create",
                "signature": "def create()",
            },
            {
                "id": effect_id,
                "kind": "effect",
                "label": "Insert examples",
                "file": "example.py",
                "line": 13,
                "function_symbol": "example.create",
                "operation": "INSERT",
                "tables": ["examples"],
                "durable": True,
                "sql": "INSERT INTO examples(secret) VALUES ('do not publish')",
            },
        ],
        "edges": [
            {
                "source": route_id,
                "target": function_id,
                "type": "handled_by",
                "flow_ids": ["default:post:/v1/example"],
            },
            {
                "source": function_id,
                "target": effect_id,
                "type": "writes",
                "flow_ids": ["default:post:/v1/example"],
            },
        ],
        "default_flows": [
            {
                "flow_id": "default:post:/v1/example",
                "name": "Create an example",
                "description": "Test flow",
                "actor_roles": ["BANK_ADMIN"],
                "route": {"method": "POST", "path": "/v1/example"},
                "documentation": "private authored body",
                "documentation_path": "docs/example.md",
                "node_ids": [route_id, function_id, effect_id],
            }
        ],
    }


def _model(flow_id: str = "default:post:/v1/example") -> dict:
    return {
        "version": 1,
        "iterations": 10_000,
        "seed": 7,
        "impact_tolerance_gbp": 1_000_000,
        "scenarios": [
            {
                "id": "example-risk",
                "name": "Example risk",
                "flow_ids": [flow_id],
                "assumptions": {
                    "annual_event_probability": 0.1,
                    "conditional_loss_probability": 0.5,
                    "base_loss_gbp": 2_000_000,
                    "detection_mean_hours": 24,
                    "detection_sd_hours": 12,
                    "dwell_shape": 2,
                    "dwell_scale_hours": 48,
                    "blast_alpha": 2,
                    "blast_beta": 5,
                },
            }
        ],
        "controls": [
            {
                "id": "example-control",
                "cost_y1_gbp": 100_000,
                "reductions": {"example-risk": {"frequency": 0.25, "magnitude": 0.2}},
            }
        ],
        "presets": [
            {
                "id": "example-preset",
                "control_ids": ["example-control"],
            }
        ],
    }


def _model_with_attack_tree(flow_id: str = "default:post:/v1/example") -> dict:
    model = _model()
    model["scenarios"][0]["attack_tree"] = {
        "root": "Reach example state",
        "traversal_cost_gbp": 2_000_000,
        "nodes": [
            {
                "id": "example-root",
                "kind": "GOAL",
                "title": "Reach example state",
                "operator": "AND",
                "flow_ids": [flow_id],
            }
        ],
        "probability_assumptions": [
            {
                "id": "example-access",
                "title": "Example path is attempted",
                "probability": 0.25,
                "rationale": "Test assumption",
            }
        ],
    }
    return model


def test_public_projection_retains_evidence_but_removes_raw_sql() -> None:
    projection = build_public_projection(
        _catalogue(),
        _model(),
        source_commit="b" * 40,
        repository_evidence={"sbom_gap": True},
    )

    effect = next(node for node in projection["nodes"] if node["kind"] == "effect")
    assert effect["operation"] == "INSERT"
    assert effect["tables"] == ["examples"]
    assert effect["durable"] is True
    assert "sql" not in effect
    serialized = json.dumps(projection)
    assert "do not publish" not in serialized
    assert "private authored body" not in serialized
    assert projection["flows"][0]["risk_scenario_ids"] == ["example-risk"]
    assert len(projection["projection_digest"]) == 64


def test_risk_model_rejects_a_flow_not_in_the_catalogue() -> None:
    with pytest.raises(ResilienceReportError, match="unknown catalogue flows"):
        build_public_projection(
            _catalogue(),
            _model("default:post:/v1/missing"),
            source_commit="b" * 40,
            repository_evidence={},
        )


def test_risk_model_rejects_attack_tree_flow_not_in_the_catalogue() -> None:
    with pytest.raises(
        ResilienceReportError,
        match="attack_tree.*unknown catalogue flows",
    ):
        build_public_projection(
            _catalogue(),
            _model_with_attack_tree("default:post:/v1/missing"),
            source_commit="b" * 40,
            repository_evidence={},
        )


def test_current_repository_builds_a_self_contained_pages_artifact(
    tmp_path: Path,
) -> None:
    output = tmp_path / "site"
    manifest = build_site(
        root=ROOT,
        catalogue_path=ROOT / "bantam" / "workflow_catalog.json",
        model_path=ROOT / "report" / "risk-model.json",
        static_path=ROOT / "report" / "site",
        output=output,
        source_commit="c" * 40,
    )

    graph = json.loads((output / "data" / "bantam-graph.json").read_text())
    assert graph["source_commit"] == "c" * 40
    assert graph["catalogue_counts"]["flows"] >= 3
    assert all(
        node.get("file") != "scripts/resilience_report.py" for node in graph["nodes"]
    )
    assert graph["repository_evidence"]["lock_and_audit_evidence"] == {
        "npm_audit_ci": True,
        "pip_audit_ci": True,
        "python_exact_pins": True,
        "web_lockfile": True,
    }
    assert graph["repository_evidence"]["sbom_gap"] == (
        not graph["repository_evidence"]["sbom_artifacts"]
    )
    if graph["repository_evidence"]["sbom_artifacts"]:
        published = graph["repository_evidence"]["published_sbom_artifacts"]
        assert published
        assert all((output / path).is_file() for path in published)
        assert graph["repository_evidence"]["sbom_summary"]["component_count"] >= 1
    assert manifest["projection_digest"] == graph["projection_digest"]
    assert (output / "index.html").is_file()
    assert (output / "app.js").is_file()
    assert (output / "styles.css").is_file()
    assert (output / ".nojekyll").is_file()
    html = (output / "index.html").read_text()
    script = (output / "app.js").read_text()
    assert "Content-Security-Policy" in html
    assert "raw SQL" in html
    html_ids = set(re.findall(r'id="([^"]+)"', html))
    script_ids = set(re.findall(r'byId\("([^"]+)"\)', script))
    assert script_ids <= html_ids

    trees = json.loads((output / "data" / "attack-trees.json").read_text())
    assert manifest["attack_tree_digest"]
    assert len(trees["trees"]) >= 2
    assert all(tree["origin"] == "CURATED" for tree in trees["trees"])
    # Pages publishes curated trees only. It contains no browser-side model
    # endpoint, key form, or model request contract.
    assert "https://api.mistral.ai" not in html
    assert "generator-key" not in html
    assert "api.mistral.ai" not in script
    assert not (output / "data" / "attack-tree-request.json").exists()
    secret_pattern = re.compile(
        r"(?i)(api[_-]?key|authorization|bearer)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}"
    )
    for published in output.rglob("*"):
        if published.is_file() and published.suffix in {
            ".js",
            ".json",
            ".html",
            ".css",
        }:
            assert not secret_pattern.search(published.read_text(encoding="utf-8")), (
                published
            )


def test_repository_evidence_keeps_audits_separate_from_sbom_discovery() -> None:
    evidence = collect_repository_evidence(ROOT)

    assert evidence["declared_runtime_dependencies"]["python"] > 0
    assert evidence["declared_runtime_dependencies"]["web"] > 0
    assert evidence["lock_and_audit_evidence"]["pip_audit_ci"] is True
    assert evidence["lock_and_audit_evidence"]["npm_audit_ci"] is True
    assert evidence["sbom_gap"] == (not evidence["sbom_artifacts"])
