"""Determinism, evidence coverage, and custom workflow validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bantam.workflow_graph import (
    WorkflowGraphService,
    build_catalog,
    load_catalog,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def catalog() -> dict[str, object]:
    return build_catalog(REPOSITORY_ROOT)


def _flow(catalog: dict[str, object], name: str) -> dict[str, object]:
    return next(flow for flow in catalog["default_flows"] if flow["name"] == name)


def _service(catalog_path: Path) -> WorkflowGraphService:
    return WorkflowGraphService(object(), catalog_path=catalog_path)  # type: ignore[arg-type]


def test_catalog_build_is_byte_deterministic(catalog: dict[str, object]) -> None:
    second = build_catalog(REPOSITORY_ROOT)

    assert catalog == second
    assert catalog["generator"] == "bantam.workflow_graph.CatalogBuilder"
    assert len(catalog["graph_digest"]) == 64
    assert all(flow["documentation"] for flow in catalog["default_flows"])
    assert all(len(flow["node_ids"]) <= 160 for flow in catalog["default_flows"])


def test_registration_flow_links_route_functions_checks_and_docs(
    catalog: dict[str, object],
) -> None:
    flow = _flow(catalog, "Register a customer")
    nodes = {node["id"]: node for node in catalog["nodes"]}
    selected = [nodes[node_id] for node_id in flow["node_ids"]]

    assert flow["actor_roles"] == ["PUBLIC"]
    assert flow["documentation_path"] is None
    assert "# Flow: Register a customer" in flow["documentation"]
    assert selected[0]["method"] == "POST"
    assert selected[0]["path"] == "/v1/auth/register"
    assert any(
        node.get("signature", "").startswith("def register(") for node in selected
    )
    assert any(node["kind"] == "check" and node.get("signature") for node in selected)


def test_transfer_flow_contains_service_signatures_and_durable_effects(
    catalog: dict[str, object],
) -> None:
    flow = _flow(catalog, "Send money")
    nodes = {node["id"]: node for node in catalog["nodes"]}
    selected = [nodes[node_id] for node_id in flow["node_ids"]]
    signatures = {
        node["signature"]
        for node in selected
        if node["kind"] == "function" and node.get("signature")
    }
    durable_tables = {
        table
        for node in selected
        if node["kind"] == "effect" and node.get("durable")
        for table in node.get("tables", [])
    }

    assert any(signature.startswith("def create_transfer(") for signature in signatures)
    assert any(
        "LedgerService.create_transfer" in node.get("symbol", "") for node in selected
    )
    assert {
        "transactions",
        "ledger_entries",
        "account_balances",
        "outbox_events",
    } <= durable_tables
    assert any(node["kind"] == "transaction" for node in selected)


def test_postgresql_constraints_are_graph_evidence(
    catalog: dict[str, object],
) -> None:
    nodes = {node["id"]: node for node in catalog["nodes"]}
    constraint = nodes["constraint:postgres:ledger_transaction_balanced"]

    assert constraint["database_function"] == "assert_transaction_balanced"
    assert constraint["tables"] == ["ledger_entries"]
    assert any(
        edge["type"] == "enforced_by" and edge["target"] == constraint["id"]
        for edge in catalog["edges"]
    )
    ledger_effects = [
        node
        for node in catalog["nodes"]
        if node["kind"] == "effect" and "ledger_entries" in node.get("tables", [])
    ]
    assert any(
        item["name"] == "ledger_transaction_balanced"
        for node in ledger_effects
        for item in node.get("constraints", [])
    )


def test_default_flow_is_accepted_as_custom_composition(
    catalog: dict[str, object],
    tmp_path: Path,
) -> None:
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    service = _service(path)
    flow = _flow(catalog, "Register a customer")

    result = service.validate(
        {
            "name": "Registration evidence path",
            "description": "A saved view over the generated registration flow.",
            "actor_role": "PUBLIC",
            "node_ids": flow["node_ids"],
        }
    )

    assert result["valid"] is True
    assert result["errors"] == []
    documentation = service.render_documentation(result["normalized"])
    assert "# Workflow: Registration evidence path" in documentation
    assert "def register(" in documentation


def test_every_generated_default_is_a_valid_composition(
    catalog: dict[str, object],
    tmp_path: Path,
) -> None:
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    service = _service(path)

    for flow in catalog["default_flows"]:
        result = service.validate(
            {
                "name": flow["name"],
                "description": flow["description"],
                "actor_role": flow["actor_roles"][0],
                "node_ids": flow["node_ids"],
            }
        )
        assert result["valid"], (flow["flow_id"], result["errors"])


@pytest.mark.parametrize(
    ("patch", "error_code"),
    [
        ({"actor_role": "CUSTOMER"}, "ACTOR_FORBIDDEN"),
        ({"actor_role": "SYSTEM"}, "INVALID_START"),
        (
            {"node_ids": ["route:POST:/v1/auth/register", "missing:node"]},
            "UNKNOWN_NODE",
        ),
        (
            {"node_ids": ["route:POST:/v1/auth/register", "function:bantam.api.login"]},
            "DISCONNECTED_EDGE",
        ),
    ],
)
def test_invalid_custom_compositions_fail_closed(
    catalog: dict[str, object],
    tmp_path: Path,
    patch: dict[str, object],
    error_code: str,
) -> None:
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    service = _service(path)
    definition = {
        "name": "Registration evidence path",
        "description": "",
        "actor_role": "PUBLIC",
        "node_ids": _flow(catalog, "Register a customer")["node_ids"][:2],
        **patch,
    }

    result = service.validate(definition)

    assert result["valid"] is False
    assert error_code in {error["code"] for error in result["errors"]}


def test_catalog_loader_rejects_tampering(
    catalog: dict[str, object],
    tmp_path: Path,
) -> None:
    path = tmp_path / "catalog.json"
    tampered = {**catalog, "version": 999}
    path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(RuntimeError, match="digest"):
        load_catalog(path)
