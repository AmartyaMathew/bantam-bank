"""Build the public Bantam operational-resilience report.

The report is a static GitHub Pages site.  It publishes a deliberately reduced
projection of Bantam's deterministic workflow catalogue: stable identifiers,
function/check evidence, table-level data effects, and graph edges are kept,
while raw SQL and authored documentation bodies stay inside the repository.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tomllib
from typing import Any

from bantam.workflow_graph import load_catalog
from scripts.attack_tree_library import (
    AttackTreeLibraryError,
    validate_library,
)


STATIC_FILES = ("index.html", "styles.css", "app.js")
EXCLUDED_DISCOVERY_PARTS = {
    ".git",
    ".venv",
    "_site",
    "dist",
    "node_modules",
    "runtime",
    "site-packages",
}
SBOM_SUFFIXES = (".cdx.json", ".cdx.xml", ".spdx", ".spdx.json", ".spdx.yml")
COMMIT_RE = re.compile(r"(?:[0-9a-f]{7,64}|local)\Z")


class ResilienceReportError(ValueError):
    """Raised when report inputs do not satisfy the publication contract."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _read_mapping(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ResilienceReportError(f"could not read {label}: {path}") from error
    if not isinstance(value, dict):
        raise ResilienceReportError(f"{label} must be a JSON object")
    return value


def _probability(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ResilienceReportError(f"{field} must be numeric")
    result = float(value)
    if not 0 <= result <= 1:
        raise ResilienceReportError(f"{field} must be between zero and one")
    return result


def _positive_number(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ResilienceReportError(f"{field} must be numeric")
    result = float(value)
    if result <= 0:
        raise ResilienceReportError(f"{field} must be greater than zero")
    return result


def _non_empty_string(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ResilienceReportError(f"{field} must be a non-empty string")
    return value


def _validate_cost_line_items(
    line_items: Any,
    *,
    field: str,
    expected_total: float,
) -> None:
    if not isinstance(line_items, list) or not line_items:
        raise ResilienceReportError(f"{field} must be a non-empty list")
    total = 0.0
    for index, item in enumerate(line_items, start=1):
        if not isinstance(item, dict):
            raise ResilienceReportError(f"{field}[{index}] must be an object")
        _non_empty_string(item.get("label"), field=f"{field}[{index}].label")
        total += _positive_number(
            item.get("amount_gbp"), field=f"{field}[{index}].amount_gbp"
        )
    if round(total) != round(expected_total):
        raise ResilienceReportError(
            f"{field} must sum to {expected_total:.0f}, got {total:.0f}"
        )


def validate_risk_model(
    model: dict[str, Any], catalogue: dict[str, Any]
) -> dict[str, Any]:
    """Validate editable financial assumptions against real catalogue flows."""

    if model.get("version") != 1:
        raise ResilienceReportError("risk model version must be 1")
    iterations = model.get("iterations")
    if isinstance(iterations, bool) or not isinstance(iterations, int):
        raise ResilienceReportError("iterations must be an integer")
    if not 1_000 <= iterations <= 100_000:
        raise ResilienceReportError("iterations must be between 1,000 and 100,000")
    seed = model.get("seed")
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**32:
        raise ResilienceReportError("seed must be a 32-bit unsigned integer")
    _positive_number(model.get("impact_tolerance_gbp"), field="impact_tolerance_gbp")
    business_profile = model.get("business_profile")
    if business_profile is not None and not isinstance(business_profile, dict):
        raise ResilienceReportError("business_profile must be an object")

    flow_ids = {flow["flow_id"] for flow in catalogue.get("default_flows", [])}
    scenarios = model.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ResilienceReportError("risk model requires at least one scenario")
    scenario_ids: set[str] = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise ResilienceReportError("each scenario must be an object")
        scenario_id = scenario.get("id")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ResilienceReportError("each scenario requires an id")
        if scenario_id in scenario_ids:
            raise ResilienceReportError(f"duplicate scenario id: {scenario_id}")
        scenario_ids.add(scenario_id)
        assumptions = scenario.get("assumptions")
        if not isinstance(assumptions, dict):
            raise ResilienceReportError(f"{scenario_id}.assumptions must be an object")
        _probability(
            assumptions.get("annual_event_probability"),
            field=f"{scenario_id}.annual_event_probability",
        )
        _probability(
            assumptions.get("conditional_loss_probability"),
            field=f"{scenario_id}.conditional_loss_probability",
        )
        _positive_number(
            assumptions.get("base_loss_gbp"), field=f"{scenario_id}.base_loss_gbp"
        )
        base_loss = float(assumptions["base_loss_gbp"])
        for field in (
            "detection_mean_hours",
            "detection_sd_hours",
            "dwell_shape",
            "dwell_scale_hours",
            "blast_alpha",
            "blast_beta",
        ):
            _positive_number(assumptions.get(field), field=f"{scenario_id}.{field}")
        linked_flows = scenario.get("flow_ids")
        if not isinstance(linked_flows, list) or not linked_flows:
            raise ResilienceReportError(f"{scenario_id} requires flow_ids")
        unknown = sorted(set(linked_flows) - flow_ids)
        if unknown:
            raise ResilienceReportError(
                f"{scenario_id} references unknown catalogue flows: "
                f"{', '.join(unknown)}"
            )
        cost_basis = scenario.get("cost_basis")
        if cost_basis is not None:
            if not isinstance(cost_basis, dict):
                raise ResilienceReportError(
                    f"{scenario_id}.cost_basis must be an object"
                )
            if "line_items" in cost_basis:
                _validate_cost_line_items(
                    cost_basis["line_items"],
                    field=f"{scenario_id}.cost_basis.line_items",
                    expected_total=base_loss,
                )
        attack_tree = scenario.get("attack_tree")
        if attack_tree is not None:
            if not isinstance(attack_tree, dict):
                raise ResilienceReportError(
                    f"{scenario_id}.attack_tree must be an object"
                )
            _non_empty_string(
                attack_tree.get("root"), field=f"{scenario_id}.attack_tree.root"
            )
            _positive_number(
                attack_tree.get("traversal_cost_gbp"),
                field=f"{scenario_id}.attack_tree.traversal_cost_gbp",
            )
            tree_nodes = attack_tree.get("nodes", [])
            if not isinstance(tree_nodes, list) or not tree_nodes:
                raise ResilienceReportError(
                    f"{scenario_id}.attack_tree.nodes must be a list"
                )
            tree_node_ids: set[str] = set()
            for node in tree_nodes:
                if not isinstance(node, dict):
                    raise ResilienceReportError(
                        f"{scenario_id}.attack_tree.nodes entries must be objects"
                    )
                node_id = _non_empty_string(
                    node.get("id"), field=f"{scenario_id}.attack_tree.nodes.id"
                )
                if node_id in tree_node_ids:
                    raise ResilienceReportError(
                        f"{scenario_id}.attack_tree has duplicate node id: {node_id}"
                    )
                tree_node_ids.add(node_id)
                _non_empty_string(
                    node.get("title"),
                    field=f"{scenario_id}.attack_tree.nodes.{node_id}.title",
                )
                node_flow_ids = node.get("flow_ids", [])
                if not isinstance(node_flow_ids, list):
                    raise ResilienceReportError(
                        f"{scenario_id}.attack_tree.nodes.{node_id}.flow_ids "
                        "must be a list"
                    )
                unknown_tree_flows = sorted(set(node_flow_ids) - flow_ids)
                if unknown_tree_flows:
                    raise ResilienceReportError(
                        f"{scenario_id}.attack_tree.nodes.{node_id} references unknown "
                        f"catalogue flows: {', '.join(unknown_tree_flows)}"
                    )
            probability_assumptions = attack_tree.get("probability_assumptions", [])
            if (
                not isinstance(probability_assumptions, list)
                or not probability_assumptions
            ):
                raise ResilienceReportError(
                    f"{scenario_id}.attack_tree.probability_assumptions must be a list"
                )
            for assumption in probability_assumptions:
                if not isinstance(assumption, dict):
                    raise ResilienceReportError(
                        f"{scenario_id}.attack_tree.probability_assumptions entries "
                        "must be objects"
                    )
                assumption_id = _non_empty_string(
                    assumption.get("id"),
                    field=f"{scenario_id}.attack_tree.probability_assumptions.id",
                )
                _non_empty_string(
                    assumption.get("title"),
                    field=(
                        f"{scenario_id}.attack_tree.probability_assumptions."
                        f"{assumption_id}.title"
                    ),
                )
                _probability(
                    assumption.get("probability"),
                    field=(
                        f"{scenario_id}.attack_tree.probability_assumptions."
                        f"{assumption_id}.probability"
                    ),
                )

    controls = model.get("controls")
    if not isinstance(controls, list):
        raise ResilienceReportError("controls must be a list")
    control_ids: set[str] = set()
    for control in controls:
        if not isinstance(control, dict):
            raise ResilienceReportError("each control must be an object")
        control_id = control.get("id")
        if not isinstance(control_id, str) or not control_id:
            raise ResilienceReportError("each control requires an id")
        if control_id in control_ids:
            raise ResilienceReportError(f"duplicate control id: {control_id}")
        control_ids.add(control_id)
        cost_y1 = _positive_number(
            control.get("cost_y1_gbp"), field=f"{control_id}.cost_y1_gbp"
        )
        if "cost_breakdown" in control:
            _validate_cost_line_items(
                control["cost_breakdown"],
                field=f"{control_id}.cost_breakdown",
                expected_total=cost_y1,
            )
        reductions = control.get("reductions")
        if not isinstance(reductions, dict):
            raise ResilienceReportError(f"{control_id}.reductions must be an object")
        unknown_scenarios = sorted(set(reductions) - scenario_ids)
        if unknown_scenarios:
            raise ResilienceReportError(
                f"{control_id} references unknown scenarios: "
                f"{', '.join(unknown_scenarios)}"
            )
        for scenario_id, reduction in reductions.items():
            if not isinstance(reduction, dict):
                raise ResilienceReportError(
                    f"{control_id}.{scenario_id} reduction must be an object"
                )
            for factor in ("frequency", "magnitude"):
                _probability(
                    reduction.get(factor, 0),
                    field=f"{control_id}.{scenario_id}.{factor}",
                )

    presets = model.get("presets", [])
    if not isinstance(presets, list):
        raise ResilienceReportError("presets must be a list")
    for preset in presets:
        if not isinstance(preset, dict) or not isinstance(preset.get("id"), str):
            raise ResilienceReportError("each preset requires an id")
        selected = preset.get("control_ids")
        if not isinstance(selected, list):
            raise ResilienceReportError(f"{preset['id']}.control_ids must be a list")
        unknown_controls = sorted(set(selected) - control_ids)
        if unknown_controls:
            raise ResilienceReportError(
                f"{preset['id']} references unknown controls: "
                f"{', '.join(unknown_controls)}"
            )
    return model


def _public_node(node: dict[str, Any]) -> dict[str, Any]:
    public = {
        key: node[key]
        for key in (
            "id",
            "kind",
            "label",
            "file",
            "line",
            "function_symbol",
            "signature",
            "condition",
            "failure_outcomes",
            "operation",
            "tables",
            "durable",
            "durability",
            "constraints",
            "database_function",
        )
        if key in node
    }
    # Exact SQL is valuable inside Bantam's authenticated explorer, but the
    # Pages report is normally public.  Table, operation, and durability facts
    # preserve the human flow without publishing query bodies.
    return public


def build_public_projection(
    catalogue: dict[str, Any],
    model: dict[str, Any],
    *,
    source_commit: str,
    repository_evidence: dict[str, Any],
) -> dict[str, Any]:
    """Return the bounded graph published to GitHub Pages."""

    if not COMMIT_RE.fullmatch(source_commit):
        raise ResilienceReportError("source commit must be a Git SHA or 'local'")
    validate_risk_model(model, catalogue)
    nodes_by_id = {node["id"]: node for node in catalogue.get("nodes", [])}
    scenarios_by_flow: dict[str, list[str]] = {}
    for scenario in model["scenarios"]:
        for flow_id in scenario["flow_ids"]:
            scenarios_by_flow.setdefault(flow_id, []).append(scenario["id"])

    flows: list[dict[str, Any]] = []
    referenced_node_ids: set[str] = set()
    for flow in catalogue.get("default_flows", []):
        node_ids = list(flow.get("node_ids", []))
        missing = [node_id for node_id in node_ids if node_id not in nodes_by_id]
        if missing:
            raise ResilienceReportError(
                f"flow {flow['flow_id']} references missing graph nodes"
            )
        referenced_node_ids.update(node_ids)
        flows.append(
            {
                "id": flow["flow_id"],
                "name": flow["name"],
                "description": flow.get("description", ""),
                "actor_roles": flow.get("actor_roles", []),
                "route": flow.get("route"),
                "documentation_path": flow.get("documentation_path"),
                "node_ids": node_ids,
                "risk_scenario_ids": sorted(scenarios_by_flow.get(flow["flow_id"], [])),
            }
        )

    nodes = [
        _public_node(nodes_by_id[node_id]) for node_id in sorted(referenced_node_ids)
    ]
    edges = [
        {
            "source": edge["source"],
            "target": edge["target"],
            "type": edge["type"],
            "flow_ids": edge.get("flow_ids", []),
        }
        for edge in catalogue.get("edges", [])
        if edge.get("source") in referenced_node_ids
        and edge.get("target") in referenced_node_ids
    ]
    kind_counts = Counter(node["kind"] for node in catalogue.get("nodes", []))
    edge_counts = Counter(edge["type"] for edge in catalogue.get("edges", []))
    projection: dict[str, Any] = {
        "version": 1,
        "repository": "aam57689/bank",
        "source_commit": source_commit,
        "catalogue_digest": catalogue["graph_digest"],
        "catalogue_counts": {
            "nodes": len(catalogue.get("nodes", [])),
            "edges": len(catalogue.get("edges", [])),
            "flows": len(catalogue.get("default_flows", [])),
            "node_kinds": dict(sorted(kind_counts.items())),
            "edge_types": dict(sorted(edge_counts.items())),
        },
        "publication_boundary": {
            "includes": [
                "stable graph and flow identifiers",
                "function signatures and check conditions",
                "table-level reads, locks, durable effects, and constraints",
                "source file and line evidence",
            ],
            "excludes": [
                "raw SQL text",
                "authored documentation bodies",
                "credentials and runtime data",
                "Mistral requests and responses",
            ],
        },
        "repository_evidence": repository_evidence,
        "flows": flows,
        "nodes": nodes,
        "edges": edges,
    }
    projection["projection_digest"] = _digest(projection)
    return projection


def _published_sbom_path(relative_path: str) -> str:
    return f"data/sbom/{relative_path.replace('/', '__')}"


def _sbom_ecosystem(component: dict[str, Any]) -> str:
    for entry in component.get("properties", []):
        if entry.get("name") == "bantam:ecosystem" and isinstance(
            entry.get("value"), str
        ):
            return entry["value"]
    purl = component.get("purl")
    if isinstance(purl, str) and purl.startswith("pkg:"):
        return purl.split("/", 1)[0].removeprefix("pkg:")
    return "unknown"


def _sbom_summary(root: Path, sbom_paths: list[str]) -> dict[str, Any]:
    formats: Counter[str] = Counter()
    ecosystems: Counter[str] = Counter()
    component_count = 0
    runtime_component_count = 0
    for relative_path in sbom_paths:
        path = root / relative_path
        if not path.name.lower().endswith(".cdx.json"):
            formats[path.suffix.lstrip(".") or "unknown"] += 1
            continue
        document = _read_mapping(path, label="SBOM")
        if document.get("bomFormat") != "CycloneDX":
            raise ResilienceReportError(f"SBOM is not CycloneDX JSON: {relative_path}")
        formats[f"CycloneDX {document.get('specVersion', 'unknown')}"] += 1
        components = document.get("components", [])
        if not isinstance(components, list):
            raise ResilienceReportError(
                f"SBOM components must be a list: {relative_path}"
            )
        component_count += len(components)
        for component in components:
            if not isinstance(component, dict):
                raise ResilienceReportError(
                    f"SBOM component entries must be objects: {relative_path}"
                )
            ecosystems[_sbom_ecosystem(component)] += 1
            if component.get("scope", "required") == "required":
                runtime_component_count += 1
    return {
        "component_count": component_count,
        "runtime_component_count": runtime_component_count,
        "ecosystems": dict(sorted(ecosystems.items())),
        "formats": dict(sorted(formats.items())),
    }


def collect_repository_evidence(root: Path) -> dict[str, Any]:
    """Collect small manifest facts without claiming an SBOM vulnerability scan."""

    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    python_dependencies = pyproject.get("project", {}).get("dependencies", [])
    package = _read_mapping(root / "web" / "package.json", label="web package")
    web_dependencies = package.get("dependencies", {})
    if not isinstance(python_dependencies, list) or not isinstance(
        web_dependencies, dict
    ):
        raise ResilienceReportError("dependency manifests have an unexpected shape")

    sbom_paths: list[str] = []
    for candidate in root.rglob("*"):
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(root)
        if EXCLUDED_DISCOVERY_PARTS.intersection(relative.parts):
            continue
        lowered = candidate.name.lower()
        if lowered.endswith(SBOM_SUFFIXES):
            sbom_paths.append(relative.as_posix())

    workflow_text = (root / ".github" / "workflows" / "security.yml").read_text(
        encoding="utf-8"
    )
    audit_text = workflow_text + (root / "Makefile").read_text(encoding="utf-8")
    sbom_paths = sorted(sbom_paths)
    return {
        "declared_runtime_dependencies": {
            "python": len(python_dependencies),
            "web": len(web_dependencies),
        },
        "lock_and_audit_evidence": {
            "web_lockfile": (root / "web" / "package-lock.json").is_file(),
            "python_exact_pins": all("==" in value for value in python_dependencies),
            "pip_audit_ci": "pip_audit" in audit_text,
            "npm_audit_ci": "npm audit --omit=dev" in workflow_text,
        },
        "sbom_artifacts": sbom_paths,
        "published_sbom_artifacts": [_published_sbom_path(path) for path in sbom_paths],
        "sbom_summary": _sbom_summary(root, sbom_paths),
        "sbom_gap": not sbom_paths,
    }


def _safe_output(output: Path, *, root: Path) -> Path:
    resolved = output.resolve()
    forbidden = {Path("/").resolve(), root.resolve(), Path.home().resolve()}
    if resolved in forbidden or resolved.name in {"", ".", ".."}:
        raise ResilienceReportError(f"unsafe report output directory: {resolved}")
    return resolved


def load_attack_trees(
    path: Path, projection: dict[str, Any], model: dict[str, Any]
) -> dict[str, Any]:
    """Validate curated trees against the graph this build is publishing.

    A curated tree is only worth showing if its citations still resolve, so a
    renamed route or deleted service fails the build rather than shipping a tree
    that points at code which no longer exists.
    """

    try:
        return validate_library(
            _read_mapping(path, label="attack tree library"),
            flow_ids={flow["id"] for flow in projection["flows"]},
            graph_node_ids={node["id"] for node in projection["nodes"]},
            scenario_ids={scenario["id"] for scenario in model["scenarios"]},
        )
    except AttackTreeLibraryError as error:
        raise ResilienceReportError(str(error)) from error


def build_site(
    *,
    root: Path,
    catalogue_path: Path,
    model_path: Path,
    static_path: Path,
    output: Path,
    source_commit: str,
    attack_trees_path: Path | None = None,
) -> dict[str, Any]:
    """Build a deterministic static report and return its manifest."""

    root = root.resolve()
    catalogue = load_catalog(catalogue_path)
    model = validate_risk_model(
        _read_mapping(model_path, label="risk model"), catalogue
    )
    for filename in STATIC_FILES:
        if not (static_path / filename).is_file():
            raise ResilienceReportError(f"missing static report asset: {filename}")
    repository_evidence = collect_repository_evidence(root)
    projection = build_public_projection(
        catalogue,
        model,
        source_commit=source_commit,
        repository_evidence=repository_evidence,
    )

    attack_trees = load_attack_trees(
        attack_trees_path or (root / "report" / "attack-trees.json"), projection, model
    )

    output = _safe_output(output, root=root)
    staging = output.parent / f".{output.name}.staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    for filename in STATIC_FILES:
        shutil.copyfile(static_path / filename, staging / filename)
    (staging / ".nojekyll").write_text("", encoding="utf-8")
    data_dir = staging / "data"
    data_dir.mkdir()
    for source_path, published_path in zip(
        repository_evidence["sbom_artifacts"],
        repository_evidence["published_sbom_artifacts"],
        strict=True,
    ):
        target = staging / published_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / source_path, target)
    (data_dir / "bantam-graph.json").write_bytes(_canonical_bytes(projection) + b"\n")
    (data_dir / "risk-model.json").write_bytes(_canonical_bytes(model) + b"\n")
    (data_dir / "attack-trees.json").write_bytes(_canonical_bytes(attack_trees) + b"\n")
    manifest = {
        "version": 1,
        "source_commit": source_commit,
        "catalogue_digest": catalogue["graph_digest"],
        "projection_digest": projection["projection_digest"],
        "risk_model_digest": _digest(model),
        "attack_tree_digest": _digest(attack_trees),
    }
    (staging / "build-manifest.json").write_bytes(_canonical_bytes(manifest) + b"\n")
    if output.exists():
        shutil.rmtree(output)
    staging.replace(output)
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build",))
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument(
        "--catalogue", type=Path, default=Path("bantam/workflow_catalog.json")
    )
    parser.add_argument("--model", type=Path, default=Path("report/risk-model.json"))
    parser.add_argument("--static", type=Path, default=Path("report/site"))
    parser.add_argument(
        "--attack-trees", type=Path, default=Path("report/attack-trees.json")
    )
    parser.add_argument("--output", type=Path, default=Path("_site"))
    parser.add_argument("--commit", default=os.getenv("GITHUB_SHA", "local"))
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    manifest = build_site(
        root=arguments.root,
        catalogue_path=arguments.catalogue,
        model_path=arguments.model,
        static_path=arguments.static,
        output=arguments.output,
        source_commit=arguments.commit,
        attack_trees_path=arguments.attack_trees,
    )
    print(
        "Built Bantam resilience report "
        f"for {manifest['source_commit']} ({manifest['projection_digest'][:12]})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
