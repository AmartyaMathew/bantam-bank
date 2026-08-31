"""Unit tests for HTTP and credential trust-boundary helpers."""

from __future__ import annotations

import asyncio
import ipaddress
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from bantam.security import (
    CSRF_COOKIE_NAME,
    DatabaseRateLimiter,
    RequestBodyLimitMiddleware,
    SlidingWindowRateLimiter,
    client_ip,
    csrf_problem,
    normalise_idempotency_key,
    password_problem,
)


def request(
    *,
    peer: str = "203.0.113.10",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    method: str = "GET",
):
    return SimpleNamespace(
        client=SimpleNamespace(host=peer),
        headers=headers or {},
        cookies=cookies or {},
        method=method,
    )


def test_password_problem_accepts_demo_password() -> None:
    assert password_problem("BantamDemo123!") is None


def test_password_problem_rejects_too_many_bcrypt_bytes() -> None:
    assert (
        password_problem("BantamDemo123!" * 8) == "password must be 72 bytes or fewer"
    )


def test_sliding_window_rate_limiter_blocks_until_window_expires() -> None:
    limiter = SlidingWindowRateLimiter(limit=2, window=timedelta(seconds=10))

    assert limiter.check("login:alice", now=100).allowed
    assert limiter.check("login:alice", now=101).allowed

    blocked = limiter.check("login:alice", now=102)
    assert not blocked.allowed
    assert blocked.retry_after_seconds == 8

    assert limiter.check("login:alice", now=111).allowed


def test_database_rate_limiter_hashes_pii_bearing_key() -> None:
    observed: list[str] = []

    class Result:
        def fetchone(self):
            now = datetime.now(UTC)
            return {"attempts": 1, "window_started_at": now, "checked_at": now}

    class Connection:
        def execute(self, query, parameters=None):
            if "INSERT INTO auth_rate_limits" in query:
                observed.append(parameters[0])
                return Result()
            raise AssertionError("unexpected maintenance query")

    class Pool:
        def connection(self):
            return nullcontext(Connection())

    result = DatabaseRateLimiter(Pool(), limit=3, window=timedelta(minutes=1)).check(
        "login:account:alice@example.test"
    )

    assert result.allowed
    assert len(observed[0]) == 64
    assert "alice" not in observed[0]


def test_idempotency_key_validation() -> None:
    assert normalise_idempotency_key(" transfer-123 ") == "transfer-123"

    with pytest.raises(ValueError, match="invalid"):
        normalise_idempotency_key("bad key")


def test_forwarded_address_is_ignored_from_untrusted_peer() -> None:
    incoming = request(headers={"x-forwarded-for": "198.51.100.8"})

    assert (
        client_ip(incoming, (ipaddress.ip_network("127.0.0.1/32"),)) == "203.0.113.10"
    )


def test_forwarded_address_is_used_from_trusted_proxy() -> None:
    incoming = request(
        peer="127.0.0.1",
        headers={"x-forwarded-for": "198.51.100.8, 10.0.0.4"},
    )
    trusted = (
        ipaddress.ip_network("127.0.0.1/32"),
        ipaddress.ip_network("10.0.0.0/8"),
    )

    assert client_ip(incoming, trusted) == "198.51.100.8"


def test_trusted_nginx_uses_rightmost_cloud_run_forwarded_address() -> None:
    incoming = request(
        peer="127.0.0.1",
        headers={"x-forwarded-for": "192.0.2.123, 198.51.100.8"},
    )

    # The prefix can be client supplied. With only the direct Nginx sidecar
    # trusted, the platform-sanitized rightmost address remains authoritative.
    assert (
        client_ip(incoming, (ipaddress.ip_network("127.0.0.1/32"),)) == "198.51.100.8"
    )


def test_malformed_forwarded_chain_falls_back_to_peer() -> None:
    incoming = request(peer="127.0.0.1", headers={"x-forwarded-for": "not-an-ip"})

    assert client_ip(incoming, (ipaddress.ip_network("127.0.0.1/32"),)) == "127.0.0.1"


def test_cookie_write_requires_matching_csrf_proof() -> None:
    valid = request(
        method="POST",
        headers={"x-csrf-token": "nonce"},
        cookies={CSRF_COOKIE_NAME: "nonce"},
    )
    missing = request(method="POST")
    cross_site = request(
        method="POST",
        headers={"x-csrf-token": "nonce", "sec-fetch-site": "cross-site"},
        cookies={CSRF_COOKIE_NAME: "nonce"},
    )

    assert csrf_problem(valid) is None
    assert csrf_problem(missing) == "CSRF token is required"
    assert csrf_problem(cross_site) == "cross-site request rejected"


def test_body_limit_rejects_chunked_request_without_content_length() -> None:
    async def scenario() -> list[dict[str, object]]:
        messages = iter(
            [
                {"type": "http.request", "body": b"1234", "more_body": True},
                {"type": "http.request", "body": b"5", "more_body": False},
            ]
        )
        sent: list[dict[str, object]] = []

        async def receive():
            return next(messages)

        async def send(message):
            sent.append(message)

        async def downstream(scope, receive, send):  # pragma: no cover - must not run
            raise AssertionError("oversized request reached downstream application")

        middleware = RequestBodyLimitMiddleware(downstream, max_bytes=4)
        await middleware(
            {"type": "http", "method": "POST", "headers": []}, receive, send
        )
        return sent

    sent = asyncio.run(scenario())

    assert sent[0]["status"] == 413
    assert b"REQUEST_TOO_LARGE" in sent[1]["body"]


def test_body_limit_replays_bounded_body() -> None:
    async def scenario() -> bytes:
        messages = iter([{"type": "http.request", "body": b"safe", "more_body": False}])
        observed = b""

        async def receive():
            return next(messages)

        async def send(message):
            del message

        async def downstream(scope, receive, send):
            nonlocal observed
            del scope, send
            observed = (await receive())["body"]

        middleware = RequestBodyLimitMiddleware(downstream, max_bytes=4)
        await middleware(
            {"type": "http", "method": "POST", "headers": []}, receive, send
        )
        return observed

    assert asyncio.run(scenario()) == b"safe"
