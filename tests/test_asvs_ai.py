"""Tests for the untrusted-model to reviewed-scenario boundary."""

from __future__ import annotations

import ast
import json

import pytest

from bantam.asvs import CATALOG_VERSION, CONTROLS
from bantam.asvs_ai import (
    MAX_GENERATED_TESTS,
    MODEL_ENDPOINT,
    MODEL_ID,
    MODEL_PROVIDER,
    REGO_PACKAGE,
    SCENARIOS,
    _NoRedirectHandler,
    build_model_request,
    build_plan_schema,
    build_provider_schema,
    build_prompt,
    build_request_provenance,
    compile_pytest,
    compile_rego,
    validate_generated_plan,
)


def captured_source_context() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "files": [
            {
                "repository": "application",
                "path": "bantam/api.py",
                "sha256": "a" * 64,
                "excerpt": "0001: def authenticated_principal(): pass",
            },
            {
                "repository": "terraform",
                "path": "runtime.tf",
                "sha256": "b" * 64,
                "excerpt": "0001: resource google_cloud_run_v2_service bank",
            },
        ],
    }


def captured_openapi() -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "info": {"title": "Bantam API", "version": "0.2.0"},
        "paths": {
            "/v1/me": {
                "get": {
                    "operationId": "me",
                    "responses": {"401": {"description": "Unauthenticated"}},
                }
            }
        },
        "components": {"schemas": {}},
    }


def candidate_rego_module() -> str:
    lines = [
        f"package {REGO_PACKAGE}",
        "",
        "import rego.v1",
    ]
    for scenario in SCENARIOS.values():
        rule_name = f"{scenario.control_id.lower().replace('-', '_')}_pass"
        lines.extend(
            [
                "",
                f"{rule_name} if {{",
                (
                    f'    input.results["{scenario.scenario_id}"].status'
                    f" == {scenario.expected_status}"
                ),
                (
                    f'    input.results["{scenario.scenario_id}"].error_code'
                    f' == "{scenario.expected_error_code}"'
                ),
                "}",
            ]
        )
    return "\n".join(lines) + "\n"


def candidate_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "catalog_version": CATALOG_VERSION,
        "summary": "Exercise each reviewed authorization boundary with a negative test.",
        "rego_module": candidate_rego_module(),
        "tests": [
            {
                "control_id": scenario.control_id,
                "scenario_id": scenario.scenario_id,
                "name": f"Verify {scenario.scenario_id.replace('-', ' ')}",
                "objective": scenario.description,
                "grounding": (
                    "The application authorization dependency and Cloud Run "
                    "boundary require this negative check."
                ),
                "source_refs": ["bantam/api.py"],
                "terraform_refs": ["runtime.tf"],
            }
            for scenario in SCENARIOS.values()
        ],
    }


def test_validated_plan_requires_exact_reviewed_control_coverage() -> None:
    plan = validate_generated_plan(
        json.dumps(candidate_payload()), captured_source_context()
    )

    assert len(plan.tests) == len(CONTROLS)
    assert len(plan.tests) <= MAX_GENERATED_TESTS
    assert [test.control_id for test in plan.tests] == [
        control.control_id for control in CONTROLS
    ]
    assert plan.rego_module == compile_rego(plan)
    assert f"package {REGO_PACKAGE}" in plan.rego_module


def test_plan_rejects_a_scenario_mapped_to_the_wrong_control() -> None:
    payload = candidate_payload()
    tests = payload["tests"]
    assert isinstance(tests, list)
    tests[0]["scenario_id"] = "customer-admin-route-denied"
    tests[1]["scenario_id"] = "anonymous-protected-route"

    with pytest.raises(ValueError, match="outside its control"):
        validate_generated_plan(json.dumps(payload), captured_source_context())


def test_plan_rejects_missing_or_duplicate_controls() -> None:
    payload = candidate_payload()
    tests = payload["tests"]
    assert isinstance(tests, list)
    tests[-1] = dict(tests[0])

    with pytest.raises(ValueError, match="missing or duplicate"):
        validate_generated_plan(json.dumps(payload), captured_source_context())


def test_compiler_keeps_model_text_inside_string_literals() -> None:
    payload = candidate_payload()
    tests = payload["tests"]
    assert isinstance(tests, list)
    tests[0]["name"] = 'Verify quote"; raise RuntimeError("never")'
    plan = validate_generated_plan(json.dumps(payload), captured_source_context())

    source = compile_pytest(plan)
    parsed = ast.parse(source)
    calls = {
        node.func.id
        for node in ast.walk(parsed)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert "RuntimeError" not in calls
    assert calls <= {"call", "login", "str", "uuid4"}
    assert len([node for node in parsed.body if isinstance(node, ast.FunctionDef)]) == 5


def test_prompt_contains_live_source_openapi_and_reviewed_scenarios() -> None:
    source_context = captured_source_context()
    schema = build_plan_schema(source_context)
    prompt = build_prompt(source_context, captured_openapi(), schema)

    assert CATALOG_VERSION in prompt
    assert {control.control_id for control in CONTROLS} <= {
        value for value in prompt.split('"') if value.startswith("ASPIS-ASVS-")
    }
    assert set(SCENARIOS) <= set(prompt.split('"'))
    assert "bantam/api.py" in prompt
    assert "runtime.tf" in prompt
    assert "/v1/me" in prompt
    assert REGO_PACKAGE in prompt
    assert "rego_module" in prompt
    assert "BantamDemo123!" not in prompt
    assert "ASPIS_MODELS_TOKEN" not in prompt
    assert "ASPIS_MISTRAL_API_KEY" not in prompt


def test_plan_rejects_source_citations_outside_snapshot() -> None:
    payload = candidate_payload()
    tests = payload["tests"]
    assert isinstance(tests, list)
    tests[0]["source_refs"] = ["bantam/not-captured.py"]

    with pytest.raises(ValueError, match="outside the captured snapshot"):
        validate_generated_plan(json.dumps(payload), captured_source_context())


def test_model_request_uses_mistral_strict_json_schema() -> None:
    source_context = captured_source_context()
    schema = build_plan_schema(source_context)
    prompt = build_prompt(source_context, captured_openapi(), schema)

    request = build_model_request(prompt, schema)
    provider_schema = build_provider_schema(schema)

    assert request["model"] == "mistral-small-2603"
    assert request["response_format"] == {
        "type": "json_schema",
        "json_schema": {
            "name": "asvs_source_grounded_test_and_rego_plan",
            "strict": True,
            "schema": provider_schema,
        },
    }
    assert request["messages"][1]["content"] == prompt
    assert '"response_schema":' in prompt


def test_mistral_schema_keeps_structure_and_moves_rich_constraints_local() -> None:
    full_schema = build_plan_schema(captured_source_context())
    provider_schema = build_provider_schema(full_schema)

    full_json = json.dumps(full_schema, sort_keys=True)
    provider_json = json.dumps(provider_schema, sort_keys=True)
    for keyword in (
        "const",
        "maxItems",
        "maxLength",
        "minItems",
        "minLength",
        "pattern",
        "uniqueItems",
    ):
        assert f'"{keyword}"' in full_json
        assert f'"{keyword}"' not in provider_json

    properties = provider_schema["properties"]
    assert isinstance(properties, dict)
    assert properties["schema_version"] == {
        "type": "string",
        "enum": ["1.0"],
    }
    assert properties["catalog_version"] == {
        "type": "string",
        "enum": [CATALOG_VERSION],
    }
    assert provider_schema["additionalProperties"] is False
    assert provider_schema["required"] == list(full_schema["required"])


def test_local_validation_retains_constraints_omitted_from_provider() -> None:
    short_summary = candidate_payload()
    short_summary["summary"] = "too short"
    with pytest.raises(ValueError, match="test-plan schema"):
        validate_generated_plan(
            json.dumps(short_summary),
            captured_source_context(),
        )

    duplicate_reference = candidate_payload()
    tests = duplicate_reference["tests"]
    assert isinstance(tests, list)
    tests[0]["source_refs"] = ["bantam/api.py", "bantam/api.py"]
    with pytest.raises(ValueError, match="test-plan schema"):
        validate_generated_plan(
            json.dumps(duplicate_reference),
            captured_source_context(),
        )


def test_request_provenance_uses_only_the_fixed_mistral_endpoint() -> None:
    source_context = captured_source_context()
    openapi = captured_openapi()
    schema = build_plan_schema(source_context)
    request = build_model_request(
        build_prompt(source_context, openapi, schema),
        schema,
    )

    provenance = build_request_provenance(
        request,
        source_context=source_context,
        source_sha256="a" * 64,
        openapi_snapshot=openapi,
        openapi_sha256="b" * 64,
    )
    envelope = provenance["model_request"]

    assert MODEL_PROVIDER == "Mistral AI"
    assert MODEL_ID == "mistral-small-2603"
    assert MODEL_ENDPOINT == "https://api.mistral.ai/v1/chat/completions"
    assert envelope["url"] == MODEL_ENDPOINT
    assert envelope["headers"] == {
        "Accept": "application/json",
        "Authorization": "Bearer [REDACTED]",
        "Content-Type": "application/json",
    }


def test_plan_rejects_rego_with_a_network_builtin() -> None:
    payload = candidate_payload()
    payload["rego_module"] = (
        candidate_rego_module()
        + '\nexfiltrate if {\n  http.send({"method": "get", "url": "https://example.com"})\n}\n'
    )

    with pytest.raises(ValueError, match="Rego contained unsupported"):
        validate_generated_plan(json.dumps(payload), captured_source_context())


def test_plan_rejects_rego_that_changes_a_reviewed_outcome() -> None:
    payload = candidate_payload()
    payload["rego_module"] = candidate_rego_module().replace(
        "status == 401",
        "status == 200",
        1,
    )

    with pytest.raises(ValueError, match="Rego changed a reviewed scenario"):
        validate_generated_plan(json.dumps(payload), captured_source_context())


def test_model_redirects_are_rejected() -> None:
    handler = _NoRedirectHandler()

    assert (
        handler.redirect_request(
            object(),
            object(),
            302,
            "Found",
            {},
            MODEL_ENDPOINT + "/redirected",
        )
        is None
    )
