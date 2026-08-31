"""Live, administrator-triggered OWASP ASVS verification for Bantam.

The runner deliberately exercises the public HTTP boundary instead of calling
authorization helpers directly. It is available to the regular administrator
panel in every environment, but synthetic live probes can only be enabled in a
seeded development deployment. Production therefore retains the evidence view
without acquiring a hidden test-user or SSRF capability.
"""

from __future__ import annotations

import hashlib
import http.cookies
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any, Protocol
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from bantam import audit
from bantam.errors import BantamError
from bantam.seed import ALICE_ACCOUNT_ID, BOB_ACCOUNT_ID, DEMO_PASSWORD
from security.aspis.core.evidence import VALID_SEVERITIES, EvidenceRecord


MAX_HTTP_RESPONSE_BYTES = 65_536
RUN_COOLDOWN_SECONDS = 30
RUN_LOCK_NAME = "bantam_asvs_live_runner"
GENERATOR = "bantam-asvs-live-runner/1.0"
VALIDATOR = "deterministic-live-http-assertion/1.0"
EXPECTED_CONTROL_IDS = frozenset(
    {
        "ASPIS-ASVS-AC-001",
        "ASPIS-ASVS-AC-002",
        "ASPIS-ASVS-AC-003",
        "ASPIS-ASVS-AC-004",
        "ASPIS-ASVS-AC-005",
    }
)


@dataclass(frozen=True, slots=True)
class ControlDefinition:
    """One reviewed catalog entry displayed and executed by the admin panel."""

    control_id: str
    title: str
    framework_ids: tuple[str, ...]
    severity: str
    remediation: str

    def to_mapping(self) -> dict[str, object]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "framework_ids": list(self.framework_ids),
            "severity": self.severity,
            "remediation": self.remediation,
        }


@dataclass(frozen=True, slots=True)
class BrowserSession:
    """Ephemeral cookie and CSRF material that is never serialized as evidence."""

    cookie_header: str
    csrf_token: str


@dataclass(frozen=True, slots=True)
class HttpExchange:
    """Bounded result from one loopback API request."""

    method: str
    path: str
    status: int
    payload: dict[str, Any]
    set_cookie_headers: tuple[str, ...]
    duration_ms: int

    @property
    def error_code(self) -> str | None:
        error = self.payload.get("error")
        if not isinstance(error, dict):
            return None
        value = error.get("code")
        return value if isinstance(value, str) else None


class ProbeTransport(Protocol):
    """Small seam used to unit-test the workflow without a network listener."""

    def call(
        self,
        method: str,
        path: str,
        *,
        session: BrowserSession | None = None,
        body: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpExchange: ...


class ProbeUnavailable(RuntimeError):
    """Raised when a live probe cannot produce trustworthy HTTP evidence."""


def load_catalog() -> tuple[str, tuple[ControlDefinition, ...]]:
    """Load the reviewed JSON catalog from the packaged Aspis resource."""

    raw = (
        files("security.aspis.asvs")
        .joinpath("bantam-control-catalog.json")
        .read_text(encoding="utf-8")
    )
    document = json.loads(raw)
    if not isinstance(document, dict) or document.get("schema_version") != "1.0":
        raise RuntimeError("unsupported ASVS control catalog")
    version = document.get("catalog_version")
    controls = document.get("controls")
    if not isinstance(version, str) or not version.strip():
        raise RuntimeError("ASVS catalog version is missing")
    if not isinstance(controls, list) or not 1 <= len(controls) <= 25:
        raise RuntimeError("ASVS catalog must contain between 1 and 25 controls")

    parsed: list[ControlDefinition] = []
    identifiers: set[str] = set()
    for value in controls:
        if not isinstance(value, dict):
            raise RuntimeError("ASVS catalog controls must be objects")
        control_id = value.get("control_id")
        framework_ids = value.get("framework_ids")
        if (
            not isinstance(control_id, str)
            or not control_id.startswith("ASPIS-ASVS-")
            or control_id in identifiers
            or not isinstance(framework_ids, list)
            or not framework_ids
            or any(not isinstance(item, str) for item in framework_ids)
        ):
            raise RuntimeError("ASVS catalog contains an invalid control mapping")
        identifiers.add(control_id)
        parsed.append(
            ControlDefinition(
                control_id=control_id,
                title=str(value.get("title", "")).strip(),
                framework_ids=tuple(framework_ids),
                severity=str(value.get("severity", "")).strip().lower(),
                remediation=str(value.get("remediation", "")).strip(),
            )
        )
    if any(
        not item.title
        or not item.remediation
        or item.severity not in VALID_SEVERITIES
        or any(not framework_id.strip() for framework_id in item.framework_ids)
        for item in parsed
    ):
        raise RuntimeError(
            "ASVS catalog controls require valid titles, severity, mappings, "
            "and remediation"
        )
    if identifiers != EXPECTED_CONTROL_IDS:
        raise RuntimeError(
            "ASVS catalog and reviewed live-runner assertions are out of sync"
        )
    return version, tuple(parsed)


CATALOG_VERSION, CONTROLS = load_catalog()
CONTROL_BY_ID = {control.control_id: control for control in CONTROLS}


def _read_payload(response: Any) -> dict[str, Any]:
    raw = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
    if len(raw) > MAX_HTTP_RESPONSE_BYTES:
        raise ProbeUnavailable("probe response exceeded the safe evidence limit")
    try:
        payload = json.loads(raw) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeUnavailable("probe response was not a valid JSON object") from error
    if not isinstance(payload, dict):
        raise ProbeUnavailable("probe response was not a JSON object")
    return payload


class LoopbackHttpTransport:
    """HTTP transport pinned to the running API's loopback listener."""

    def __init__(self, port: int, timeout_seconds: float = 4.0) -> None:
        self.base_url = f"http://127.0.0.1:{port}"
        self.timeout_seconds = timeout_seconds
        # Environment proxy variables must never redirect security probes.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(
        self,
        method: str,
        path: str,
        *,
        session: BrowserSession | None = None,
        body: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpExchange:
        if not path.startswith("/") or "://" in path:
            raise ProbeUnavailable("probe path must be a local absolute path")
        method = method.upper()
        request_headers = {
            "Accept": "application/json",
            "X-Request-ID": str(uuid4()),
            **(headers or {}),
        }
        if session is not None:
            request_headers["Cookie"] = session.cookie_header
            if method not in {"GET", "HEAD", "OPTIONS"}:
                request_headers["X-CSRF-Token"] = session.csrf_token
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            request_headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=request_headers,
            method=method,
        )
        started = time.perf_counter()
        try:
            with self.opener.open(request, timeout=self.timeout_seconds) as response:
                payload = _read_payload(response)
                return HttpExchange(
                    method=method,
                    path=path,
                    status=response.status,
                    payload=payload,
                    set_cookie_headers=tuple(
                        response.headers.get_all("Set-Cookie", [])
                    ),
                    duration_ms=max(0, round((time.perf_counter() - started) * 1000)),
                )
        except urllib.error.HTTPError as error:
            payload = _read_payload(error)
            return HttpExchange(
                method=method,
                path=path,
                status=error.code,
                payload=payload,
                set_cookie_headers=tuple(error.headers.get_all("Set-Cookie", [])),
                duration_ms=max(0, round((time.perf_counter() - started) * 1000)),
            )
        except (TimeoutError, urllib.error.URLError, OSError) as error:
            raise ProbeUnavailable(
                "the live Bantam API probe was unavailable"
            ) from error


def _browser_session(exchange: HttpExchange) -> BrowserSession:
    if exchange.status != 200:
        raise ProbeUnavailable("synthetic customer authentication was rejected")
    if "access_token" in exchange.payload:
        raise ProbeUnavailable("login unexpectedly returned a browser bearer token")
    csrf_token = exchange.payload.get("csrf_token")
    if not isinstance(csrf_token, str) or not csrf_token:
        raise ProbeUnavailable("login did not issue a CSRF token")

    cookie = http.cookies.SimpleCookie()
    for value in exchange.set_cookie_headers:
        if len(value) > 4096:
            raise ProbeUnavailable("login cookie exceeded the safe probe limit")
        cookie.load(value)
    cookie_header = "; ".join(
        f"{name}={morsel.value}" for name, morsel in cookie.items()
    )
    if not cookie_header:
        raise ProbeUnavailable("login did not issue a session cookie")
    return BrowserSession(cookie_header=cookie_header, csrf_token=csrf_token)


def _observed(exchange: HttpExchange) -> str:
    code = exchange.error_code or "none"
    return (
        f"{exchange.method} {exchange.path} returned HTTP {exchange.status} "
        f"with error code {code} in {exchange.duration_ms} ms"
    )


class LiveAsvsRunner:
    """Execute the five reviewed authorization/session probes in one session."""

    def __init__(self, transport: ProbeTransport, target_commit: str) -> None:
        self.transport = transport
        self.target_commit = target_commit

    def _record(
        self,
        control_id: str,
        method: str,
        path: str,
        expected_status: int,
        expected_code: str,
        outcome: HttpExchange | Exception,
    ) -> EvidenceRecord:
        control = CONTROL_BY_ID[control_id]
        source = (
            f"Live loopback HTTP probe: {method} {path}",
            "security/aspis/asvs/bantam-control-catalog.json",
        )
        if isinstance(outcome, Exception):
            return EvidenceRecord(
                control_id=control.control_id,
                title=control.title,
                framework=f"OWASP ASVS {CATALOG_VERSION}",
                framework_ids=control.framework_ids,
                target="Bantam live API",
                status="error",
                severity=control.severity,
                confidence=0.0,
                source_evidence=source,
                execution_evidence=(),
                counter_evidence=(),
                remediation=control.remediation,
                limitations=("The live HTTP probe could not complete safely.",),
                target_commit=self.target_commit,
                generated_by=GENERATOR,
                validated_by=VALIDATOR,
            )

        passed = (
            outcome.status == expected_status and outcome.error_code == expected_code
        )
        observation = _observed(outcome)
        return EvidenceRecord(
            control_id=control.control_id,
            title=control.title,
            framework=f"OWASP ASVS {CATALOG_VERSION}",
            framework_ids=control.framework_ids,
            target="Bantam live API",
            status="pass" if passed else "fail",
            severity=control.severity,
            confidence=1.0,
            source_evidence=source,
            execution_evidence=(observation,) if passed else (),
            counter_evidence=(
                (
                    f"Expected HTTP {expected_status} with error code "
                    f"{expected_code}; {observation}"
                ),
            )
            if not passed
            else (),
            remediation=control.remediation,
            limitations=(),
            target_commit=self.target_commit,
            generated_by=GENERATOR,
            validated_by=VALIDATOR,
        )

    def _call(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> HttpExchange | Exception:
        try:
            return self.transport.call(method, path, **kwargs)
        except ProbeUnavailable as error:
            return error

    def run(self) -> tuple[EvidenceRecord, ...]:
        evidence: list[EvidenceRecord] = []

        anonymous = self._call("GET", "/v1/me")
        evidence.append(
            self._record(
                "ASPIS-ASVS-AC-001",
                "GET",
                "/v1/me",
                401,
                "UNAUTHENTICATED",
                anonymous,
            )
        )

        login = self._call(
            "POST",
            "/v1/auth/login",
            body={"email": "alice@bantam.local", "password": DEMO_PASSWORD},
        )
        try:
            if isinstance(login, Exception):
                raise login
            session = _browser_session(login)
        except ProbeUnavailable as error:
            for control_id, method, path, status, code in (
                (
                    "ASPIS-ASVS-AC-002",
                    "GET",
                    "/v1/admin/customers",
                    403,
                    "FORBIDDEN",
                ),
                (
                    "ASPIS-ASVS-AC-003",
                    "GET",
                    f"/v1/accounts/{BOB_ACCOUNT_ID}/transactions",
                    404,
                    "NOT_FOUND",
                ),
                (
                    "ASPIS-ASVS-AC-004",
                    "POST",
                    "/v1/transfers",
                    403,
                    "FORBIDDEN",
                ),
                (
                    "ASPIS-ASVS-AC-005",
                    "GET",
                    "/v1/me",
                    401,
                    "UNAUTHENTICATED",
                ),
            ):
                evidence.append(
                    self._record(control_id, method, path, status, code, error)
                )
            return tuple(evidence)

        admin = self._call("GET", "/v1/admin/customers", session=session)
        evidence.append(
            self._record(
                "ASPIS-ASVS-AC-002",
                "GET",
                "/v1/admin/customers",
                403,
                "FORBIDDEN",
                admin,
            )
        )

        other_history_path = f"/v1/accounts/{BOB_ACCOUNT_ID}/transactions"
        other_history = self._call("GET", other_history_path, session=session)
        evidence.append(
            self._record(
                "ASPIS-ASVS-AC-003",
                "GET",
                other_history_path,
                404,
                "NOT_FOUND",
                other_history,
            )
        )

        transfer = self._call(
            "POST",
            "/v1/transfers",
            session=session,
            headers={"Idempotency-Key": f"asvs-{uuid4()}"},
            body={
                "source_account_id": str(BOB_ACCOUNT_ID),
                "destination_account_id": str(ALICE_ACCOUNT_ID),
                "amount_minor": 100,
                "currency": "GBP",
                "description": "ASVS authorization verification",
            },
        )
        evidence.append(
            self._record(
                "ASPIS-ASVS-AC-004",
                "POST",
                "/v1/transfers",
                403,
                "FORBIDDEN",
                transfer,
            )
        )

        logout = self._call("POST", "/v1/auth/logout", session=session)
        if isinstance(logout, Exception) or logout.status != 200:
            replay: HttpExchange | Exception = ProbeUnavailable(
                "the synthetic session could not be terminated"
            )
        else:
            replay = self._call("GET", "/v1/me", session=session)
        evidence.append(
            self._record(
                "ASPIS-ASVS-AC-005",
                "GET",
                "/v1/me",
                401,
                "UNAUTHENTICATED",
                replay,
            )
        )
        return tuple(evidence)


def _run_status(records: tuple[EvidenceRecord, ...]) -> str:
    statuses = {record.status for record in records}
    if "error" in statuses:
        return "ERROR"
    if "fail" in statuses:
        return "FAIL"
    if "inconclusive" in statuses:
        return "INCONCLUSIVE"
    return "PASS"


def _serialize_run(row: dict[str, Any], *, include_evidence: bool) -> dict[str, Any]:
    result = {
        "run_id": row["run_id"],
        "status": row["status"],
        "catalog_version": row["catalog_version"],
        "target_commit": row["target_commit"],
        "controls_total": row["controls_total"],
        "controls_passed": row["controls_passed"],
        "controls_failed": row["controls_failed"],
        "controls_inconclusive": row["controls_inconclusive"],
        "controls_error": row["controls_error"],
        "evidence_sha256": row["evidence_sha256"],
        "duration_ms": row["duration_ms"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "initiated_by": row["initiated_by"],
    }
    if include_evidence:
        result["evidence"] = row["evidence"]
    return result


class AsvsService:
    """Persist immutable ASVS runs and expose a bounded administrator view."""

    def __init__(
        self,
        pool: ConnectionPool,
        *,
        runner_enabled: bool,
        target_commit: str,
        api_port: int,
    ) -> None:
        self.pool = pool
        self.runner_enabled = runner_enabled
        self.target_commit = target_commit
        self.api_port = api_port

    def overview(self, limit: int = 10) -> dict[str, object]:
        limit = max(1, min(limit, 25))
        with self.pool.connection() as connection:
            # One ordered snapshot keeps the latest artifact and history
            # consistent if another administrator completes a run concurrently.
            history = connection.execute(
                """
                WITH recent AS (
                    SELECT run_id, status, catalog_version, target_commit,
                           controls_total, controls_passed, controls_failed,
                           controls_inconclusive, controls_error, evidence_sha256,
                           duration_ms, started_at, completed_at, initiated_by,
                           evidence
                    FROM asvs_runs
                    ORDER BY completed_at DESC, run_id DESC
                    LIMIT %s
                )
                SELECT run_id, status, catalog_version, target_commit,
                       controls_total, controls_passed, controls_failed,
                       controls_inconclusive, controls_error, evidence_sha256,
                       duration_ms, started_at, completed_at, initiated_by,
                       CASE
                           WHEN ROW_NUMBER() OVER (
                               ORDER BY completed_at DESC, run_id DESC
                           ) = 1
                           THEN evidence
                           ELSE NULL
                       END AS evidence
                FROM recent
                ORDER BY completed_at DESC, run_id DESC
                """,
                (limit,),
            ).fetchall()
        latest = history[0] if history else None
        return {
            "catalog": {
                "name": "OWASP Application Security Verification Standard",
                "version": CATALOG_VERSION,
                "controls": [control.to_mapping() for control in CONTROLS],
            },
            "runner_enabled": self.runner_enabled,
            "cooldown_seconds": RUN_COOLDOWN_SECONDS,
            # Exception acceptance is intentionally not implemented by this
            # demo: observed failures cannot be changed into passing evidence.
            "accepted_exceptions": 0,
            "latest_run": _serialize_run(latest, include_evidence=True)
            if latest
            else None,
            "history": [_serialize_run(row, include_evidence=False) for row in history],
        }

    def execute(
        self,
        initiated_by: UUID,
        audit_fields: dict[str, object],
    ) -> dict[str, Any]:
        if not self.runner_enabled:
            raise BantamError(
                "ASVS_RUNNER_DISABLED",
                "live ASVS probes are disabled in this environment",
                409,
            )

        with self.pool.connection() as connection:
            acquired = connection.execute(
                "SELECT pg_try_advisory_lock(hashtext(%s)) AS acquired",
                (RUN_LOCK_NAME,),
            ).fetchone()
            if not acquired or not acquired["acquired"]:
                raise BantamError(
                    "ASVS_RUN_IN_PROGRESS",
                    "another ASVS verification run is already in progress",
                    409,
                )
            try:
                recent = connection.execute(
                    """
                    SELECT EXTRACT(EPOCH FROM (now() - completed_at)) AS age_seconds
                    FROM asvs_runs
                    ORDER BY completed_at DESC
                    LIMIT 1
                    """
                ).fetchone()
                if recent and float(recent["age_seconds"]) < RUN_COOLDOWN_SECONDS:
                    raise BantamError(
                        "ASVS_RUN_COOLDOWN",
                        (
                            "wait at least "
                            f"{RUN_COOLDOWN_SECONDS} seconds between live runs"
                        ),
                        429,
                    )

                started_at = datetime.now(UTC)
                started = time.perf_counter()
                records = LiveAsvsRunner(
                    LoopbackHttpTransport(self.api_port),
                    self.target_commit,
                ).run()
                completed_at = datetime.now(UTC)
                duration_ms = max(0, round((time.perf_counter() - started) * 1000))
                # Revalidate at the normalization boundary so a future probe
                # cannot persist schema drift or unverifiable PASS evidence.
                evidence = [
                    EvidenceRecord.from_mapping(record.to_mapping()).to_mapping()
                    for record in records
                ]
                bundle = {
                    "schema_version": "1.0",
                    "catalog_version": CATALOG_VERSION,
                    "target_commit": self.target_commit,
                    "records": evidence,
                }
                evidence_sha256 = hashlib.sha256(
                    json.dumps(
                        bundle,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8")
                ).hexdigest()
                status = _run_status(records)
                counts = {
                    value: sum(record.status == value for record in records)
                    for value in ("pass", "fail", "inconclusive", "error")
                }
                run_id = uuid4()
                with connection.transaction():
                    row = connection.execute(
                        """
                        INSERT INTO asvs_runs (
                            run_id, initiated_by, status, catalog_version,
                            target_commit, controls_total, controls_passed,
                            controls_failed, controls_inconclusive, controls_error,
                            evidence, evidence_sha256, duration_ms,
                            started_at, completed_at
                        ) VALUES (
                            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                        )
                        RETURNING run_id, status, catalog_version, target_commit,
                                  controls_total, controls_passed, controls_failed,
                                  controls_inconclusive, controls_error,
                                  evidence_sha256, duration_ms, started_at,
                                  completed_at, initiated_by, evidence
                        """,
                        (
                            run_id,
                            initiated_by,
                            status,
                            CATALOG_VERSION,
                            self.target_commit,
                            len(records),
                            counts["pass"],
                            counts["fail"],
                            counts["inconclusive"],
                            counts["error"],
                            Jsonb(evidence),
                            evidence_sha256,
                            duration_ms,
                            started_at,
                            completed_at,
                        ),
                    ).fetchone()
                    fields = dict(audit_fields)
                    fields["resource_id"] = str(run_id)
                    existing_metadata = fields.get("metadata")
                    fields["metadata"] = {
                        **(
                            existing_metadata
                            if isinstance(existing_metadata, dict)
                            else {}
                        ),
                        "status": status,
                        "controls_total": len(records),
                        "controls_passed": counts["pass"],
                        "controls_failed": counts["fail"],
                        "controls_inconclusive": counts["inconclusive"],
                        "controls_error": counts["error"],
                        "evidence_sha256": evidence_sha256,
                        "target_commit": self.target_commit,
                    }
                    audit.record(connection, **fields)
                return _serialize_run(row, include_evidence=True)
            finally:
                connection.execute(
                    "SELECT pg_advisory_unlock(hashtext(%s))",
                    (RUN_LOCK_NAME,),
                )
