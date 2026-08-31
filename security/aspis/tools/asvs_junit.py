"""Convert pytest JUnit XML into normalized, secret-minimized ASVS evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as ET

from security.aspis.core.evidence import EvidenceRecord


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _load_catalog(path: Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema_version") != "1.0":
        raise ValueError("unsupported ASVS control catalog")
    controls = document.get("controls")
    if not isinstance(controls, list) or not controls:
        raise ValueError("ASVS control catalog must contain controls")
    return controls


def _testcase_map(root: ET.Element) -> dict[str, ET.Element]:
    cases: dict[str, ET.Element] = {}
    for case in root.iter("testcase"):
        name = case.get("name", "")
        if name:
            cases[name] = case
    return cases


def _result(case: ET.Element | None) -> tuple[str, list[str], list[str], list[str]]:
    if case is None:
        return "error", [], [], ["mapped pytest test is absent from JUnit evidence"]
    duration = case.get("time", "unknown")
    execution = [f"pytest_duration_seconds={duration}"]
    failure = case.find("failure")
    error = case.find("error")
    skipped = case.find("skipped")
    if failure is not None:
        raw = (failure.get("message", "") + "\n" + (failure.text or "")).strip()
        return "fail", execution, [f"pytest_failure_sha256={_sha256_text(raw)}"], []
    if error is not None:
        raw = (error.get("message", "") + "\n" + (error.text or "")).strip()
        return (
            "error",
            execution,
            [f"pytest_error_sha256={_sha256_text(raw)}"],
            ["pytest could not complete the mapped control test"],
        )
    if skipped is not None:
        reason = skipped.get("message", "pytest skipped the mapped control test")
        return "inconclusive", execution, [], [reason[:240]]
    return "pass", execution, [], []


def collect_asvs_evidence(
    junit_path: Path,
    catalog_path: Path,
    *,
    target_commit: str,
) -> dict[str, Any]:
    """Map exact test functions to versioned ASVS controls.

    Failure and error bodies can contain request data, so the collector records
    only a SHA-256 digest. The unredacted JUnit file should remain a short-lived,
    access-controlled CI artifact.
    """
    collection_limitation = ""
    try:
        root = ET.parse(junit_path).getroot()
        cases = _testcase_map(root)
    except (OSError, ET.ParseError) as error:
        cases = {}
        collection_limitation = (
            f"JUnit evidence was unavailable or malformed ({type(error).__name__})"
        )
    records: list[dict[str, Any]] = []
    for control in _load_catalog(catalog_path):
        node_id = str(control["pytest_node_id"])
        test_name = node_id.rsplit("::", 1)[-1]
        status, execution, counter, limitations = _result(cases.get(test_name))
        if collection_limitation:
            limitations = [collection_limitation]
        record = EvidenceRecord.from_mapping(
            {
                "control_id": control["control_id"],
                "title": control["title"],
                "framework": "OWASP ASVS",
                "framework_ids": control["framework_ids"],
                "target": "bantam-api",
                "status": status,
                "severity": control["severity"],
                "confidence": 1.0 if status in {"pass", "fail"} else 0.0,
                "source_evidence": [f"pytest_node_id={node_id}"],
                "execution_evidence": execution,
                "counter_evidence": counter,
                "remediation": control["remediation"],
                "limitations": limitations,
                "target_commit": target_commit,
                "generated_by": "security.aspis.tools.asvs_junit",
                "validated_by": "pytest live API integration suite",
            }
        )
        records.append(record.to_mapping())
    return {"schema_version": "1.0", "records": records}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--junit", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target-commit", required=True)
    args = parser.parse_args(argv)
    bundle = collect_asvs_evidence(
        args.junit,
        args.catalog,
        target_commit=args.target_commit,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
