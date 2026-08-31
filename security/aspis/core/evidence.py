"""Strict, dependency-free model for normalized Aspis evidence.

Collectors can be written for Rego, SnowSQL, Semgrep, or pytest, but they must
all cross this boundary before a report is produced. The model deliberately
rejects unknown fields and unverifiable PASS records so schema drift cannot
quietly turn missing evidence into a successful control.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any


VALID_STATUSES = frozenset({"pass", "fail", "inconclusive", "error"})
VALID_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
CONTROL_ID_PATTERN = re.compile(r"^ASPIS-[A-Z0-9-]+$")
RECORD_FIELDS = frozenset(
    {
        "control_id",
        "title",
        "framework",
        "framework_ids",
        "target",
        "status",
        "severity",
        "confidence",
        "source_evidence",
        "execution_evidence",
        "counter_evidence",
        "remediation",
        "limitations",
        "target_commit",
        "generated_by",
        "validated_by",
    }
)


MAX_STRING_LENGTH = 4096
MAX_LIST_ITEMS = 100


def _non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    normalized = value.strip()
    if len(normalized) > MAX_STRING_LENGTH:
        raise ValueError(f"{field} exceeds {MAX_STRING_LENGTH} characters")
    return normalized


def _optional_string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if len(normalized) > MAX_STRING_LENGTH:
        raise ValueError(f"{field} exceeds {MAX_STRING_LENGTH} characters")
    return normalized


def _string_list(value: Any, field: str, *, required: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    if len(value) > MAX_LIST_ITEMS:
        raise ValueError(f"{field} exceeds {MAX_LIST_ITEMS} items")
    normalized = tuple(item.strip() for item in value if item.strip())
    if any(len(item) > MAX_STRING_LENGTH for item in normalized):
        raise ValueError(f"{field} contains an oversized value")
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field} must not contain duplicate values")
    if required and not normalized:
        raise ValueError(f"{field} must contain at least one value")
    return normalized


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """One control result tied to its source and execution evidence."""

    control_id: str
    title: str
    framework: str
    framework_ids: tuple[str, ...]
    target: str
    status: str
    severity: str
    confidence: float
    source_evidence: tuple[str, ...]
    execution_evidence: tuple[str, ...]
    counter_evidence: tuple[str, ...]
    remediation: str
    limitations: tuple[str, ...]
    target_commit: str
    generated_by: str
    validated_by: str

    @classmethod
    def from_mapping(cls, value: Any) -> EvidenceRecord:
        """Validate an untrusted JSON object without coercing ambiguous values."""
        if not isinstance(value, dict):
            raise ValueError("evidence record must be an object")
        unknown = set(value) - RECORD_FIELDS
        missing = RECORD_FIELDS - set(value)
        if unknown:
            raise ValueError(f"unknown evidence fields: {', '.join(sorted(unknown))}")
        if missing:
            raise ValueError(f"missing evidence fields: {', '.join(sorted(missing))}")

        control_id = _non_empty_string(value["control_id"], "control_id")
        if not CONTROL_ID_PATTERN.fullmatch(control_id):
            raise ValueError("control_id must use the ASPIS-* namespace")

        status = _non_empty_string(value["status"], "status").lower()
        if status not in VALID_STATUSES:
            raise ValueError(f"unsupported evidence status: {status}")
        severity = _non_empty_string(value["severity"], "severity").lower()
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"unsupported evidence severity: {severity}")

        confidence_value = value["confidence"]
        if isinstance(confidence_value, bool) or not isinstance(
            confidence_value, (int, float)
        ):
            raise ValueError("confidence must be a number between 0 and 1")
        confidence = float(confidence_value)
        if not 0 <= confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")

        execution = _string_list(
            value["execution_evidence"],
            "execution_evidence",
            required=status == "pass",
        )
        counter = _string_list(
            value["counter_evidence"],
            "counter_evidence",
            required=status == "fail",
        )
        limitations = _string_list(
            value["limitations"],
            "limitations",
            required=status in {"inconclusive", "error"},
        )

        return cls(
            control_id=control_id,
            title=_non_empty_string(value["title"], "title"),
            framework=_non_empty_string(value["framework"], "framework"),
            framework_ids=_string_list(
                value["framework_ids"], "framework_ids", required=True
            ),
            target=_non_empty_string(value["target"], "target"),
            status=status,
            severity=severity,
            confidence=confidence,
            source_evidence=_string_list(
                value["source_evidence"], "source_evidence", required=True
            ),
            execution_evidence=execution,
            counter_evidence=counter,
            remediation=_optional_string(value["remediation"], "remediation"),
            limitations=limitations,
            target_commit=_non_empty_string(value["target_commit"], "target_commit"),
            generated_by=_non_empty_string(value["generated_by"], "generated_by"),
            validated_by=_non_empty_string(value["validated_by"], "validated_by"),
        )

    def to_mapping(self) -> dict[str, Any]:
        """Return a JSON-ready object while preserving deterministic field order."""
        value = asdict(self)
        for field in (
            "framework_ids",
            "source_evidence",
            "execution_evidence",
            "counter_evidence",
            "limitations",
        ):
            value[field] = list(value[field])
        return value
