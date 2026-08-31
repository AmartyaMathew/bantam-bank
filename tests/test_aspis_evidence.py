from __future__ import annotations

import json
from pathlib import Path

import pytest

from security.aspis.core.evidence import EvidenceRecord
from security.aspis.core.report import build_report, report_exit_code
from security.aspis.tools.asvs_junit import collect_asvs_evidence


ROOT = Path(__file__).parents[1]
CATALOG = ROOT / "security/aspis/asvs/bantam-control-catalog.json"
AUTHORIZATION_TESTS = ROOT / "tests/integration/test_authorization.py"


def evidence_record(
    control_id: str,
    target: str,
    *,
    status: str = "pass",
    title: str = "Deterministic security property",
) -> dict[str, object]:
    return {
        "control_id": control_id,
        "title": title,
        "framework": "Test framework",
        "framework_ids": ["TEST-1"],
        "target": target,
        "status": status,
        "severity": "high",
        "confidence": 1.0,
        "source_evidence": ["source=test fixture"],
        "execution_evidence": ["runner=pytest"] if status != "error" else [],
        "counter_evidence": ["failure_sha256=abc"] if status == "fail" else [],
        "remediation": "Correct the tested configuration.",
        "limitations": ["runner crashed"] if status == "error" else [],
        "target_commit": "0123456789abcdef",
        "generated_by": "tests",
        "validated_by": "pytest",
    }


def write_bundle(path: Path, *records: dict[str, object]) -> None:
    path.write_text(
        json.dumps({"schema_version": "1.0", "records": list(records)}),
        encoding="utf-8",
    )


def test_pass_requires_execution_evidence() -> None:
    record = evidence_record("ASPIS-TEST-001", "gcp")
    record["execution_evidence"] = []

    with pytest.raises(ValueError, match="execution_evidence"):
        EvidenceRecord.from_mapping(record)


def test_unknown_fields_are_rejected() -> None:
    record = evidence_record("ASPIS-TEST-001", "gcp")
    record["silently_ignored"] = True

    with pytest.raises(ValueError, match="unknown evidence fields"):
        EvidenceRecord.from_mapping(record)


def test_catalog_maps_five_controls_to_real_test_functions() -> None:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    source = AUTHORIZATION_TESTS.read_text(encoding="utf-8")

    assert catalog["catalog_version"] == "5.0.0"
    assert len(catalog["controls"]) == 5
    assert len({control["control_id"] for control in catalog["controls"]}) == 5
    for control in catalog["controls"]:
        assert all(
            framework_id.startswith("v5.0.0-")
            for framework_id in control["framework_ids"]
        )
        function_name = control["pytest_node_id"].rsplit("::", 1)[-1]
        assert f"def {function_name}(" in source


def test_junit_collector_hashes_failure_details(tmp_path: Path) -> None:
    secret_marker = "do-not-copy-this-request-token"
    junit = tmp_path / "junit.xml"
    junit.write_text(
        (
            '<testsuite tests="5">'
            '<testcase name="test_protected_route_rejects_anonymous_request" '
            'time="0.1"/>'
            '<testcase name="test_customer_cannot_use_admin_route" time="0.2">'
            f'<failure message="denied">{secret_marker}</failure></testcase>'
            '<testcase name="'
            "test_customer_cannot_read_another_customers_account_history"
            '" time="0.3"/>'
            '<testcase name="'
            "test_customer_cannot_transfer_from_an_unowned_account"
            '" time="0.4"/>'
            '<testcase name="test_logout_revokes_cookie_session_token" '
            'time="0.5"/></testsuite>'
        ),
        encoding="utf-8",
    )

    bundle = collect_asvs_evidence(
        junit,
        CATALOG,
        target_commit="0123456789abcdef",
    )
    serialized = json.dumps(bundle)

    assert len(bundle["records"]) == 5
    assert {record["status"] for record in bundle["records"]} == {"pass", "fail"}
    assert secret_marker not in serialized
    failed = next(record for record in bundle["records"] if record["status"] == "fail")
    assert failed["counter_evidence"][0].startswith("pytest_failure_sha256=")


def test_missing_junit_is_error_evidence_not_a_pass(tmp_path: Path) -> None:
    bundle = collect_asvs_evidence(
        tmp_path / "missing.xml",
        CATALOG,
        target_commit="0123456789abcdef",
    )

    assert len(bundle["records"]) == 5
    assert {record["status"] for record in bundle["records"]} == {"error"}
    assert all(record["limitations"] for record in bundle["records"])


def test_report_combines_three_targets_and_escapes_html(tmp_path: Path) -> None:
    gcp = tmp_path / "gcp.json"
    snowflake = tmp_path / "snowflake.json"
    asvs = tmp_path / "asvs.json"
    write_bundle(
        gcp,
        evidence_record(
            "ASPIS-GCP-001",
            "gcp",
            title="<script>alert('not evidence')</script>",
        ),
    )
    write_bundle(
        snowflake,
        evidence_record("ASPIS-SNOW-001", "snowflake"),
    )
    write_bundle(
        asvs,
        evidence_record("ASPIS-ASVS-001", "bantam-api"),
    )
    output = tmp_path / "report"

    findings = build_report(
        [gcp, snowflake, asvs],
        output,
        run_id="test-run",
        target_commit="0123456789abcdef",
    )

    assert findings["summary"]["total"]["pass"] == 3
    assert set(findings["summary"]["targets"]) == {
        "gcp",
        "snowflake",
        "bantam-api",
    }
    rendered_html = (output / "summary.html").read_text(encoding="utf-8")
    assert "<script>" not in rendered_html
    assert "&lt;script&gt;" in rendered_html
    rendered_markdown = (output / "summary.md").read_text(encoding="utf-8")
    assert "<script>" not in rendered_markdown
    assert "&lt;script&gt;" in rendered_markdown
    manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    assert set(manifest["outputs"]) == {
        "findings.json",
        "summary.md",
        "summary.html",
    }


def test_report_rejects_duplicate_control_target_pairs(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    record = evidence_record("ASPIS-GCP-001", "gcp")
    write_bundle(first, record)
    write_bundle(second, record)

    with pytest.raises(ValueError, match="duplicate evidence"):
        build_report(
            [first, second],
            tmp_path / "report",
            run_id="test-run",
            target_commit="0123456789abcdef",
        )


def test_report_exit_code_keeps_error_distinct_from_failure() -> None:
    summary = {
        "total": {
            "pass": 3,
            "fail": 1,
            "inconclusive": 0,
            "error": 1,
        }
    }

    assert report_exit_code(summary) == 2
