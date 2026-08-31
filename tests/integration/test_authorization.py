"""Live API regressions for role checks and object ownership (IDOR)."""

from __future__ import annotations

import http.cookies
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from email.message import Message
from uuid import uuid4

import pyotp
import pytest

from bantam.seed import ALICE_ACCOUNT_ID, BOB_ACCOUNT_ID, DEMO_PASSWORD


API_URL = os.getenv("TEST_API_URL", "http://localhost:8080").rstrip("/")
pytestmark = pytest.mark.integration
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass(frozen=True, slots=True)
class BrowserSession:
    cookie_header: str
    csrf_token: str


def _cookie_header(headers: Message) -> str:
    cookie = http.cookies.SimpleCookie()
    for value in headers.get_all("Set-Cookie", []):
        cookie.load(value)
    return "; ".join(f"{key}={morsel.value}" for key, morsel in cookie.items())


def call(
    method: str,
    path: str,
    *,
    session: BrowserSession | None = None,
    body: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
    include_headers: bool = False,
):
    request_headers = {"Accept": "application/json", **(headers or {})}
    if session:
        request_headers["Cookie"] = session.cookie_header
        if method.upper() in UNSAFE_METHODS:
            request_headers["X-CSRF-Token"] = session.csrf_token
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{API_URL}{path}", data=data, headers=request_headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read())
            if include_headers:
                return response.status, payload, response.headers
            return response.status, payload
    except urllib.error.HTTPError as error:
        payload = json.loads(error.read())
        if include_headers:
            return error.code, payload, error.headers
        return error.code, payload
    except urllib.error.URLError as error:
        pytest.skip(f"live Bantam API is unavailable: {error}")


_ADMIN_SESSION: BrowserSession | None = None
_TOTP_SECRETS: dict[str, str] = {}


def _browser_session(payload, headers: Message) -> BrowserSession:
    assert "access_token" not in payload
    return BrowserSession(
        cookie_header=_cookie_header(headers),
        csrf_token=str(payload["csrf_token"]),
    )


def login(email: str, password: str = DEMO_PASSWORD) -> BrowserSession:
    global _ADMIN_SESSION
    if email == "admin@bantam.local" and _ADMIN_SESSION:
        return _ADMIN_SESSION

    status, payload, headers = call(
        "POST",
        "/v1/auth/login",
        body={"email": email, "password": password},
        include_headers=True,
    )
    if status == 202:
        if payload["status"] == "mfa_enrollment_required":
            setup_status, setup = call(
                "POST",
                "/v1/auth/mfa/setup",
                body={
                    "transaction_id": payload["transaction_id"],
                    "method": "totp",
                    "label": "Integration authenticator",
                },
            )
            assert setup_status == 200
            secret = str(setup["totp_secret"])
            _TOTP_SECRETS[email] = secret
        else:
            setup = payload
            secret = _TOTP_SECRETS[email]
        status, payload, headers = call(
            "POST",
            "/v1/auth/mfa/totp",
            body={
                "transaction_id": setup["transaction_id"],
                "code": pyotp.TOTP(secret).now(),
            },
            include_headers=True,
        )

    assert status == 200
    session = _browser_session(payload, headers)
    if email == "admin@bantam.local":
        _ADMIN_SESSION = session
    return session


def test_protected_route_rejects_anonymous_request() -> None:
    status, payload = call("GET", "/v1/me")

    assert status == 401
    assert payload["error"]["code"] == "UNAUTHENTICATED"


def test_logout_revokes_cookie_session_token() -> None:
    alice = login("alice@bantam.local")

    status, payload = call("POST", "/v1/auth/logout", session=alice)

    assert status == 200
    assert payload["status"] == "logged_out"

    status, payload = call("GET", "/v1/me", session=alice)

    assert status == 401
    assert payload["error"]["code"] == "UNAUTHENTICATED"


def test_customer_cannot_read_another_customers_account_history() -> None:
    alice = login("alice@bantam.local")

    status, payload = call(
        "GET", f"/v1/accounts/{BOB_ACCOUNT_ID}/transactions", session=alice
    )

    assert status == 404
    assert payload["error"]["code"] == "NOT_FOUND"


def test_customer_cannot_transfer_from_an_unowned_account() -> None:
    alice = login("alice@bantam.local")

    status, payload = call(
        "POST",
        "/v1/transfers",
        session=alice,
        headers={"Idempotency-Key": f"idor-{uuid4()}"},
        body={
            "source_account_id": str(BOB_ACCOUNT_ID),
            "destination_account_id": str(ALICE_ACCOUNT_ID),
            "amount_minor": 100,
            "currency": "GBP",
            "description": "authorization regression",
        },
    )

    assert status == 403
    assert payload["error"]["code"] == "FORBIDDEN"


def test_customer_cannot_use_admin_route() -> None:
    alice = login("alice@bantam.local")

    status, payload = call("GET", "/v1/admin/customers", session=alice)

    assert status == 403
    assert payload["error"]["code"] == "FORBIDDEN"


def test_customer_cannot_read_asvs_evidence() -> None:
    alice = login("alice@bantam.local")

    status, payload = call("GET", "/v1/admin/asvs", session=alice)

    assert status == 403
    assert payload["error"]["code"] == "FORBIDDEN"


def test_approved_aspis_auditor_can_choose_optional_totp_mfa() -> None:
    email = f"aspis-auditor-{uuid4()}@example.test"
    password = "AuditorWorkspace123!"

    status, payload = call(
        "POST",
        "/v1/auth/register/aspis-auditor",
        body={"email": email, "password": password},
    )
    assert status == 202
    assert payload["status"] == "accepted"

    status, pending = call(
        "POST",
        "/v1/auth/login",
        body={"email": email, "password": password},
    )
    assert status == 403
    assert pending["error"]["code"] == "APPROVAL_PENDING"

    administrator = login("admin@bantam.local")
    status, queue = call(
        "GET",
        "/v1/admin/aspis-auditor-requests?limit=250",
        session=administrator,
    )
    assert status == 200
    approval = next(
        request for request in queue["requests"] if request["email"] == email
    )
    status, decision = call(
        "POST",
        f"/v1/admin/aspis-auditor-requests/{approval['request_id']}/decision",
        session=administrator,
        body={"decision": "APPROVE", "reason": "integration authorization test"},
    )
    assert status == 200
    assert decision["status"] == "APPROVED"

    auditor = login(email, password)
    status, profile = call("GET", "/v1/me", session=auditor)
    assert status == 200
    assert profile["role"] == "ASPIS_AUDITOR"
    assert profile["customer_id"] is None
    assert profile["mfa_enabled"] is False

    status, setup = call(
        "POST",
        "/v1/me/mfa/enrollment",
        session=auditor,
        body={
            "password": password,
            "method": "totp",
            "label": "Auditor authenticator",
        },
    )
    assert status == 200
    secret = str(setup["totp_secret"])
    totp = pyotp.TOTP(secret)
    enrollment_time = int(time.time())
    status, enrolled, headers = call(
        "POST",
        "/v1/auth/mfa/totp",
        session=auditor,
        body={
            "transaction_id": setup["transaction_id"],
            "code": totp.at(enrollment_time - totp.interval),
        },
        include_headers=True,
    )
    assert status == 200
    auditor = _browser_session(enrolled, headers)

    status, profile = call("GET", "/v1/me", session=auditor)
    assert status == 200
    assert profile["mfa_enabled"] is True

    status, _ = call("POST", "/v1/auth/logout", session=auditor)
    assert status == 200
    status, challenge = call(
        "POST",
        "/v1/auth/login",
        body={"email": email, "password": password},
    )
    assert status == 202
    assert challenge["status"] == "mfa_required"
    assert challenge["methods"] == ["totp"]

    status, completed, headers = call(
        "POST",
        "/v1/auth/mfa/totp",
        body={
            "transaction_id": challenge["transaction_id"],
            "code": totp.now(),
        },
        include_headers=True,
    )
    assert status == 200
    auditor = _browser_session(completed, headers)

    status, overview = call("GET", "/v1/admin/asvs", session=auditor)
    assert status == 200
    assert overview["ai_generator"]["limits"]["per_account_per_day"] == 5
    assert overview["ai_generator"]["usage"]["account_daily"] == 0

    for method, path in (
        ("GET", "/v1/admin/customers"),
        ("GET", "/v1/audit/events"),
        ("POST", "/v1/reconciliation/runs"),
        ("GET", "/v1/accounts"),
        ("GET", "/v1/admin/aspis-auditor-requests"),
    ):
        status, denied = call(method, path, session=auditor)
        assert status == 403
        assert denied["error"]["code"] == "FORBIDDEN"


def test_admin_can_run_and_read_redacted_asvs_evidence() -> None:
    administrator = login("admin@bantam.local")

    status, run = call(
        "POST",
        "/v1/admin/asvs/runs",
        session=administrator,
    )

    assert status == 201
    assert run["status"] == "PASS"
    assert run["controls_total"] == 5
    assert run["controls_passed"] == 5
    assert len(run["evidence_sha256"]) == 64
    serialized = json.dumps(run)
    assert DEMO_PASSWORD not in serialized
    assert administrator.cookie_header not in serialized
    assert administrator.csrf_token not in serialized

    status, overview = call("GET", "/v1/admin/asvs", session=administrator)

    assert status == 200
    assert overview["latest_run"]["run_id"] == run["run_id"]
    assert overview["accepted_exceptions"] == 0
    assert len(overview["catalog"]["controls"]) == 5


def test_registration_does_not_enumerate_existing_email() -> None:
    status, payload = call(
        "POST",
        "/v1/auth/register",
        body={
            "legal_name": "Synthetic Applicant",
            "date_of_birth": "1990-01-01",
            "email": "alice@bantam.local",
            "phone": "",
            "password": "IndependentPass123!",
        },
    )

    assert status == 202
    assert payload["status"] == "accepted"
