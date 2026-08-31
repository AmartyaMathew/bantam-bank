"""Live persistence for financial versions, attack sets, runs, and remediations."""

from __future__ import annotations

import json
import os
from uuid import uuid4

import pytest
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from bantam.attack_simulation import AttackSimulationService
from bantam.financials import CompanyFinancialsService, load_default_profile
from bantam.seed import ADMIN_USER_ID
from bantam.workflow_graph import load_catalog
from tests.test_attack_simulation import (
    _remediation_plan,
    _sample_ids,
    _scenario_set,
    _StubModelsClient,
)


DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgres://bantam:bantam@localhost:5433/bantam?sslmode=disable",
)
pytestmark = pytest.mark.integration


def _audit_fields() -> dict[str, object]:
    request_id = uuid4()
    return {
        "actor_type": "USER",
        "actor_id": str(ADMIN_USER_ID),
        "action": "pending",
        "resource_type": "pending",
        "resource_id": "pending",
        "request_id": request_id,
        "correlation_id": request_id,
        "ip_address": None,
        "user_agent": None,
    }


def test_analysis_pipeline_pins_every_assumption_it_used() -> None:
    with ConnectionPool(
        conninfo=DATABASE_URL,
        min_size=1,
        max_size=2,
        kwargs={"autocommit": True, "row_factory": dict_row},
    ) as pool:
        financials = CompanyFinancialsService(pool)
        profile = load_default_profile()
        profile["risk_appetite"]["impact_tolerance_gbp"] = 1_800_000
        saved = financials.update(
            {"profile": profile, "change_note": "integration regression"},
            created_by=ADMIN_USER_ID,
            audit_fields=_audit_fields(),
        )
        assert saved["version"] >= 1

        client = _StubModelsClient(json.dumps(_scenario_set(_sample_ids())))
        service = AttackSimulationService(
            pool,
            builtin_catalog=load_catalog(),
            financials=financials,
            models_client=client,
        )
        created = service.generate_scenarios(
            {"graph_source": "BUILTIN", "scenario_count": 2},
            created_by=ADMIN_USER_ID,
            audit_fields=_audit_fields(),
        )
        set_id = created["scenario_set_id"]
        assert created["model_result"]["status"] == "READY"
        assert created["financial_profile_version"] == saved["version"]
        assert (
            created["financial_profile"]["risk_appetite"]["impact_tolerance_gbp"]
            == 1_800_000
        )

        baseline = service.simulate(
            set_id,
            {"scenario_id": "scenario:payments", "iterations": 2_000, "seed": 99},
            created_by=ADMIN_USER_ID,
            audit_fields=_audit_fields(),
        )
        assert baseline["result"]["baseline"]["impact_tolerance_gbp"] == 1_800_000
        assert baseline["result"]["residual"] is None

        # A later financial version must not change an analysis already stored.
        financials.update(
            {"profile": load_default_profile(), "change_note": "reverted"},
            created_by=ADMIN_USER_ID,
            audit_fields=_audit_fields(),
        )
        replay = service.simulate(
            set_id,
            {"scenario_id": "scenario:payments", "iterations": 2_000, "seed": 99},
            created_by=ADMIN_USER_ID,
            audit_fields=_audit_fields(),
        )
        assert (
            replay["result"]["baseline"]["annual_loss"]
            == baseline["result"]["baseline"]["annual_loss"]
        )

        scenario = service._scenario(service._set_row(set_id), "scenario:payments")
        client.content = json.dumps(_remediation_plan(scenario))
        plan = service.remediate(
            set_id,
            baseline["simulation_id"],
            created_by=ADMIN_USER_ID,
            audit_fields=_audit_fields(),
        )
        assert plan["model_result"]["status"] == "READY"

        residual = service.simulate(
            set_id,
            {
                "scenario_id": "scenario:payments",
                "iterations": 2_000,
                "seed": 99,
                "remediation_plan_id": str(plan["remediation_plan_id"]),
                "remediation_ids": ["fix:step-up-auth"],
            },
            created_by=ADMIN_USER_ID,
            audit_fields=_audit_fields(),
        )
        economics = residual["result"]["economics"]
        assert residual["applied_remediation_ids"] == ["fix:step-up-auth"]
        assert economics["annual_loss_reduction_gbp"] > 0

        stored = service.get(set_id)
        assert len(stored["simulations"]) >= 3
        assert len(stored["remediation_plans"]) == 1

        with pool.connection() as connection:
            actions = connection.execute(
                """
                SELECT action FROM audit_events
                WHERE action IN (
                    'COMPANY_FINANCIALS_UPDATED',
                    'ATTACK_SCENARIOS_GENERATED',
                    'ATTACK_SIMULATION_RUN',
                    'ATTACK_REMEDIATIONS_GENERATED'
                )
                """
            ).fetchall()
        recorded = {row["action"] for row in actions}
        assert recorded == {
            "COMPANY_FINANCIALS_UPDATED",
            "ATTACK_SCENARIOS_GENERATED",
            "ATTACK_SIMULATION_RUN",
            "ATTACK_REMEDIATIONS_GENERATED",
        }


def test_remediation_plan_from_another_scenario_is_refused() -> None:
    with ConnectionPool(
        conninfo=DATABASE_URL,
        min_size=1,
        max_size=2,
        kwargs={"autocommit": True, "row_factory": dict_row},
    ) as pool:
        financials = CompanyFinancialsService(pool)
        client = _StubModelsClient(json.dumps(_scenario_set(_sample_ids())))
        service = AttackSimulationService(
            pool,
            builtin_catalog=load_catalog(),
            financials=financials,
            models_client=client,
        )
        created = service.generate_scenarios(
            {"graph_source": "BUILTIN", "scenario_count": 2},
            created_by=ADMIN_USER_ID,
            audit_fields=_audit_fields(),
        )
        set_id = created["scenario_set_id"]
        simulation = service.simulate(
            set_id,
            {"scenario_id": "scenario:payments", "iterations": 1_000, "seed": 7},
            created_by=ADMIN_USER_ID,
            audit_fields=_audit_fields(),
        )
        scenario = service._scenario(service._set_row(set_id), "scenario:payments")
        client.content = json.dumps(_remediation_plan(scenario))
        plan = service.remediate(
            set_id,
            simulation["simulation_id"],
            created_by=ADMIN_USER_ID,
            audit_fields=_audit_fields(),
        )
        with pytest.raises(Exception) as error:
            service.simulate(
                set_id,
                {
                    "scenario_id": "scenario:identity",
                    "iterations": 1_000,
                    "seed": 7,
                    "remediation_plan_id": str(plan["remediation_plan_id"]),
                },
                created_by=ADMIN_USER_ID,
                audit_fields=_audit_fields(),
            )
        assert "different scenario" in str(error.value)
