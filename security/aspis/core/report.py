"""Build JSON, Markdown, HTML, and manifest artifacts from Aspis evidence."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from security.aspis.core.evidence import EvidenceRecord, VALID_STATUSES


SCHEMA_VERSION = "1.0"
STATUS_ORDER = ("pass", "fail", "inconclusive", "error")
MAX_BUNDLE_BYTES = 10 * 1024 * 1024


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bundle(path: Path) -> list[EvidenceRecord]:
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError(f"{path.name}: bundle exceeds {MAX_BUNDLE_BYTES} bytes")
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"{path.name}: invalid JSON: {error}") from error
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "records",
    }:
        raise ValueError(
            f"{path.name}: bundle must contain only schema_version and records"
        )
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"{path.name}: unsupported schema_version")
    if not isinstance(document["records"], list):
        raise ValueError(f"{path.name}: records must be a list")
    return [EvidenceRecord.from_mapping(item) for item in document["records"]]


def load_records(paths: Iterable[Path]) -> list[EvidenceRecord]:
    """Load normalized bundles and reject duplicate control/target evidence."""
    records: list[EvidenceRecord] = []
    seen: set[tuple[str, str]] = set()
    for path in paths:
        for record in _read_bundle(path):
            key = (record.control_id, record.target)
            if key in seen:
                raise ValueError(
                    "duplicate evidence for "
                    f"{record.control_id} on {record.target}; merge it at the collector"
                )
            seen.add(key)
            records.append(record)
    if not records:
        raise ValueError("at least one evidence record is required")
    return sorted(records, key=lambda item: (item.target, item.control_id))


def _summary(records: list[EvidenceRecord]) -> dict[str, Any]:
    total = Counter(record.status for record in records)
    targets: dict[str, Counter[str]] = defaultdict(Counter)
    for record in records:
        targets[record.target][record.status] += 1
    return {
        "total": {status: total[status] for status in STATUS_ORDER},
        "targets": {
            target: {status: counts[status] for status in STATUS_ORDER}
            for target, counts in sorted(targets.items())
        },
    }


def _markdown(
    run_id: str,
    commit: str,
    summary: dict[str, Any],
    records: list[EvidenceRecord],
) -> str:
    def safe(value: str) -> str:
        return (
            html.escape(value, quote=False)
            .replace("`", "&#96;")
            .replace("|", r"\|")
            .replace("\r", " ")
            .replace("\n", " ")
        )

    lines = [
        "# Aspis evidence report",
        "",
        f"- Run: `{safe(run_id)}`",
        f"- Target commit: `{safe(commit)}`",
        "",
        "## Summary",
        "",
        "| Target | Pass | Fail | Inconclusive | Error |",
        "|---|---:|---:|---:|---:|",
    ]
    for target, counts in summary["targets"].items():
        lines.append(
            f"| {safe(target)} | {counts['pass']} | {counts['fail']} | "
            f"{counts['inconclusive']} | {counts['error']} |"
        )
    lines.extend(["", "## Control results", ""])
    for record in records:
        lines.extend(
            [
                f"### {safe(record.control_id)}: {safe(record.title)}",
                "",
                f"- Status: **{record.status.upper()}**",
                f"- Target: `{safe(record.target)}`",
                f"- Framework: {safe(record.framework)} "
                f"({safe(', '.join(record.framework_ids))})",
                f"- Severity: {record.severity}",
                f"- Confidence: {record.confidence:.2f}",
                f"- Source evidence: {safe('; '.join(record.source_evidence))}",
                f"- Evidence: {safe('; '.join(record.execution_evidence) or 'none')}",
                f"- Counter-evidence: "
                f"{safe('; '.join(record.counter_evidence) or 'none')}",
                f"- Remediation: {safe(record.remediation or 'none')}",
                f"- Limitations: {safe('; '.join(record.limitations) or 'none')}",
                "",
            ]
        )
    return "\n".join(lines)


def _html_report(
    run_id: str,
    commit: str,
    summary: dict[str, Any],
    records: list[EvidenceRecord],
) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(target)}</td>"
        f"<td>{counts['pass']}</td>"
        f"<td>{counts['fail']}</td>"
        f"<td>{counts['inconclusive']}</td>"
        f"<td>{counts['error']}</td>"
        "</tr>"
        for target, counts in summary["targets"].items()
    )
    findings = "".join(
        "<article>"
        f"<h3>{html.escape(record.control_id)}: {html.escape(record.title)}</h3>"
        f"<p><strong>Status:</strong> {html.escape(record.status.upper())}</p>"
        f"<p><strong>Target:</strong> {html.escape(record.target)}</p>"
        f"<p><strong>Framework:</strong> {html.escape(record.framework)} "
        f"({html.escape(', '.join(record.framework_ids))})</p>"
        f"<p><strong>Source evidence:</strong> "
        f"{html.escape('; '.join(record.source_evidence))}</p>"
        f"<p><strong>Evidence:</strong> "
        f"{html.escape('; '.join(record.execution_evidence) or 'none')}</p>"
        f"<p><strong>Counter-evidence:</strong> "
        f"{html.escape('; '.join(record.counter_evidence) or 'none')}</p>"
        f"<p><strong>Remediation:</strong> "
        f"{html.escape(record.remediation or 'none')}</p>"
        f"<p><strong>Limitations:</strong> "
        f"{html.escape('; '.join(record.limitations) or 'none')}</p>"
        "</article>"
        for record in records
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Aspis evidence report</title>"
        "<style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;"
        "padding:0 1rem}table{border-collapse:collapse}td,th{border:1px solid "
        "#aaa;padding:.5rem;text-align:left}article{border-top:1px solid #ccc;"
        "margin-top:1.5rem}</style></head><body>"
        "<h1>Aspis evidence report</h1>"
        f"<p><strong>Run:</strong> {html.escape(run_id)}<br>"
        f"<strong>Target commit:</strong> {html.escape(commit)}</p>"
        "<h2>Summary</h2><table><thead><tr><th>Target</th><th>Pass</th>"
        "<th>Fail</th><th>Inconclusive</th><th>Error</th></tr></thead>"
        f"<tbody>{rows}</tbody></table><h2>Control results</h2>{findings}"
        "</body></html>"
    )


def build_report(
    input_paths: Iterable[Path],
    output_dir: Path,
    *,
    run_id: str,
    target_commit: str,
) -> dict[str, Any]:
    """Validate all inputs before atomically replacing individual artifacts."""
    paths = list(input_paths)
    records = load_records(paths)
    summary = _summary(records)
    generated_at = datetime.now(UTC).isoformat()
    findings = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "target_commit": target_commit,
        "generated_at": generated_at,
        "summary": summary,
        "records": [record.to_mapping() for record in records],
    }
    findings_bytes = (
        json.dumps(findings, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    markdown_bytes = (
        _markdown(run_id, target_commit, summary, records).encode("utf-8") + b"\n"
    )
    html_bytes = _html_report(run_id, target_commit, summary, records).encode("utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "target_commit": target_commit,
        "generated_at": generated_at,
        "inputs": [
            {"name": path.name, "sha256": _sha256(path.read_bytes())} for path in paths
        ],
        "outputs": {
            "findings.json": _sha256(findings_bytes),
            "summary.md": _sha256(markdown_bytes),
            "summary.html": _sha256(html_bytes),
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "findings.json": findings_bytes,
        "summary.md": markdown_bytes,
        "summary.html": html_bytes,
        "run-manifest.json": (
            json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        ),
    }
    for name, content in artifacts.items():
        temporary = output_dir / f".{name}.tmp"
        temporary.write_bytes(content)
        temporary.replace(output_dir / name)
    return findings


def report_exit_code(summary: dict[str, Any]) -> int:
    """Return a fail-closed code without collapsing error into failure or pass."""
    counts = summary["total"]
    if counts["error"]:
        return 2
    if counts["fail"]:
        return 1
    if counts["inconclusive"]:
        return 3
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--target-commit", required=True)
    args = parser.parse_args(argv)
    findings = build_report(
        args.input,
        args.output,
        run_id=args.run_id,
        target_commit=args.target_commit,
    )
    unknown_statuses = set(findings["summary"]["total"]) - VALID_STATUSES
    if unknown_statuses:
        return 2
    return report_exit_code(findings["summary"])


if __name__ == "__main__":
    raise SystemExit(main())
