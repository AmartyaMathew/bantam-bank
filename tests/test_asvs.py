"""Deterministic regressions for the administrator-triggered ASVS runner."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from bantam.asvs import (
    CONTROLS,
    BrowserSession,
    HttpExchange,
    LiveAsvsRunner,
    LoopbackHttpTransport,
    ProbeUnavailable,
)
from bantam.seed import DEMO_PASSWORD


def exchange(
    method: str,
    path: str,
    status: int,
    *,
    error_code: str | None = None,
    payload: dict[str, Any] | None = None,
    cookies: tuple[str, ...] = (),
) -> HttpExchange:
    body = dict(payload or {})
    if error_code is not None:
        body["error"] = {"code": error_code, "message": "redacted test error"}
    return HttpExchange(
        method=method,
        path=path,
        status=status,
        payload=body,
        set_cookie_headers=cookies,
        duration_ms=4,
    )


def passing_script() -> list[HttpExchange | Exception]:
    return [
        exchange("GET", "/v1/me", 401, error_code="UNAUTHENTICATED"),
        exchange(
            "POST",
            "/v1/auth/login",
            200,
            payload={"csrf_token": "sensitive-csrf-nonce", "role": "CUSTOMER"},
            cookies=(
                "bantam_session=sensitive-cookie-value; HttpOnly; Path=/; SameSite=Lax",
            ),
        ),
        exchange("GET", "/v1/admin/customers", 403, error_code="FORBIDDEN"),
        exchange(
            "GET",
            "/v1/accounts/20000000-0000-0000-0000-000000000002/transactions",
            404,
            error_code="NOT_FOUND",
        ),
        exchange("POST", "/v1/transfers", 403, error_code="FORBIDDEN"),
        exchange(
            "POST",
            "/v1/auth/logout",
            200,
            payload={"status": "logged_out"},
        ),
        exchange("GET", "/v1/me", 401, error_code="UNAUTHENTICATED"),
    ]


@dataclass
class ScriptedTransport:
    outcomes: list[HttpExchange | Exception]
    calls: list[dict[str, object]] = field(default_factory=list)

    def call(
        self,
        method: str,
        path: str,
        *,
        session: BrowserSession | None = None,
        body: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpExchange:
        self.calls.append(
            {
                "method": method,
                "path": path,
                "session": session,
                "body": body,
                "headers": headers,
            }
        )
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_live_runner_passes_reviewed_controls_without_leaking_session_material() -> (
    None
):
    transport = ScriptedTransport(passing_script())

    evidence = LiveAsvsRunner(transport, "0123456789abcdef").run()
    serialized = json.dumps([record.to_mapping() for record in evidence])

    assert len(evidence) == 5
    assert {record.status for record in evidence} == {"pass"}
    assert [record.control_id for record in evidence] == [
        control.control_id for control in CONTROLS
    ]
    assert DEMO_PASSWORD not in serialized
    assert "sensitive-cookie-value" not in serialized
    assert "sensitive-csrf-nonce" not in serialized
    assert all(record.execution_evidence for record in evidence)


def test_live_runner_preserves_counter_evidence_for_a_failed_assertion() -> None:
    outcomes = passing_script()
    outcomes[2] = exchange("GET", "/v1/admin/customers", 200, payload={"customers": []})

    evidence = LiveAsvsRunner(ScriptedTransport(outcomes), "0123456789abcdef").run()
    failed = next(
        record for record in evidence if record.control_id == "ASPIS-ASVS-AC-002"
    )

    assert failed.status == "fail"
    assert failed.execution_evidence == ()
    assert failed.counter_evidence
    assert "Expected HTTP 403" in failed.counter_evidence[0]


def test_live_runner_marks_dependent_controls_error_when_login_is_unavailable() -> None:
    transport = ScriptedTransport(
        [
            exchange("GET", "/v1/me", 401, error_code="UNAUTHENTICATED"),
            ProbeUnavailable("synthetic login unavailable"),
        ]
    )

    evidence = LiveAsvsRunner(transport, "0123456789abcdef").run()

    assert evidence[0].status == "pass"
    assert {record.status for record in evidence[1:]} == {"error"}
    assert all(record.limitations for record in evidence[1:])


def test_loopback_transport_rejects_arbitrary_urls_before_network_access() -> None:
    transport = LoopbackHttpTransport(8080)

    with pytest.raises(ProbeUnavailable, match="local absolute path"):
        transport.call("GET", "https://attacker.example/collect")
