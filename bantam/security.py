"""Security primitives shared by the HTTP edge and domain services.

The helpers in this module sit on trust boundaries: proxy metadata, request
bodies, credentials, cookies, and abuse controls.  Keeping them small and
testable makes it harder for an endpoint to invent a weaker local variant.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import time
from collections import defaultdict, deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from threading import Lock
from typing import Any

from psycopg_pool import ConnectionPool


MAX_BCRYPT_PASSWORD_BYTES = 72
MIN_PASSWORD_LENGTH = 14
MAX_FORWARDED_HOPS = 10
SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
SESSION_COOKIE_NAME = "bantam_session"
CSRF_COOKIE_NAME = "bantam_csrf"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
}
API_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
DOCS_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; img-src 'self' data: https://fastapi.tiangolo.com; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "font-src 'self' https://cdn.jsdelivr.net; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'none'"
)
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


def _is_trusted(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    return any(
        address.version == network.version and address in network
        for network in networks
    )


def client_ip(
    request: Any,
    trusted_proxy_cidrs: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network] = (),
) -> str:
    """Return the originating IP without trusting attacker-supplied headers.

    ``X-Forwarded-For`` is considered only when the immediate peer belongs to a
    configured proxy network.  Walking the chain from right to left preserves
    the first untrusted hop and resists a client prepending a forged address.
    """

    raw_peer = request.client.host if request.client and request.client.host else ""
    try:
        peer = ipaddress.ip_address(raw_peer)
    except ValueError:
        return "unknown"
    if not _is_trusted(peer, trusted_proxy_cidrs):
        return peer.compressed

    raw_forwarded = request.headers.get("x-forwarded-for", "")
    values = [item.strip() for item in raw_forwarded.split(",") if item.strip()]
    if not values or len(values) > MAX_FORWARDED_HOPS:
        return peer.compressed
    try:
        chain = [ipaddress.ip_address(value) for value in values]
    except ValueError:
        # A malformed chain is not partially trusted; the direct peer remains
        # the only authenticated network fact.
        return peer.compressed

    for address in reversed([*chain, peer]):
        if not _is_trusted(address, trusted_proxy_cidrs):
            return address.compressed
    return chain[0].compressed


def add_security_headers(request: Any, response: Any) -> None:
    """Apply browser hardening consistently to success and error responses."""

    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    docs_path = request.url.path.startswith(("/docs", "/redoc", "/openapi.json"))
    response.headers.setdefault(
        "Content-Security-Policy",
        DOCS_CONTENT_SECURITY_POLICY if docs_path else API_CONTENT_SECURITY_POLICY,
    )
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Pragma", "no-cache")
    if request.url.scheme == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )


def password_problem(
    password: str, *, disallowed_values: Iterable[str] = ()
) -> str | None:
    """Return a user-safe explanation when a proposed password is unsuitable."""

    if len(password) < MIN_PASSWORD_LENGTH:
        return f"password must be at least {MIN_PASSWORD_LENGTH} characters"
    if len(password.encode()) > MAX_BCRYPT_PASSWORD_BYTES:
        return "password must be 72 bytes or fewer"
    checks = (
        (r"[a-z]", "a lowercase letter"),
        (r"[A-Z]", "an uppercase letter"),
        (r"\d", "a number"),
        (r"[^A-Za-z0-9]", "a symbol"),
    )
    missing = [label for pattern, label in checks if not re.search(pattern, password)]
    if missing:
        return "password must include " + ", ".join(missing)

    folded = password.casefold()
    for value in disallowed_values:
        cleaned = value.strip().casefold()
        if len(cleaned) >= 4 and cleaned in folded:
            return "password must not contain personal details"
        local_part = cleaned.split("@", 1)[0]
        if len(local_part) >= 4 and local_part in folded:
            return "password must not contain personal details"
    return None


def validate_password(password: str, *, disallowed_values: Iterable[str] = ()) -> None:
    problem = password_problem(password, disallowed_values=disallowed_values)
    if problem:
        raise ValueError(problem)


def normalise_idempotency_key(raw: str | None) -> str:
    value = (raw or "").strip()
    if not value:
        raise ValueError("required")
    if not IDEMPOTENCY_KEY_PATTERN.fullmatch(value):
        raise ValueError("invalid")
    return value


def csrf_problem(request: Any) -> str | None:
    """Validate double-submit CSRF proof for cookie-authenticated writes."""

    if request.method.upper() in SAFE_HTTP_METHODS:
        return None
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        return "cross-site request rejected"
    cookie = request.cookies.get(CSRF_COOKIE_NAME, "")
    header = request.headers.get("x-csrf-token", "")
    if not cookie or not header or len(cookie) > 128 or len(header) > 128:
        return "CSRF token is required"
    if not hmac.compare_digest(cookie, header):
        return "CSRF token is invalid"
    return None


@dataclass(frozen=True, slots=True)
class RateLimit:
    allowed: bool
    retry_after_seconds: int


class SlidingWindowRateLimiter:
    """Thread-safe in-memory limiter used by focused unit tests and small tools."""

    def __init__(
        self, *, limit: int, window: timedelta, max_keys: int = 10_000
    ) -> None:
        self.limit = max(1, limit)
        self.window_seconds = max(1.0, window.total_seconds())
        self.max_keys = max(100, max_keys)
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str, *, now: float | None = None) -> RateLimit:
        current = time.monotonic() if now is None else now
        with self._lock:
            if len(self._attempts) >= self.max_keys and key not in self._attempts:
                self._prune(current)
                if len(self._attempts) >= self.max_keys:
                    # Saturation is itself suspicious; fail closed instead of
                    # allowing arbitrary identifiers to exhaust process memory.
                    return RateLimit(False, int(self.window_seconds))

            attempts = self._attempts[key]
            cutoff = current - self.window_seconds
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if len(attempts) >= self.limit:
                retry_after = int(
                    max(1.0, self.window_seconds - (current - attempts[0]))
                )
                return RateLimit(False, retry_after)
            attempts.append(current)
            return RateLimit(True, 0)

    def _prune(self, current: float) -> None:
        cutoff = current - self.window_seconds
        expired = [
            key
            for key, values in self._attempts.items()
            if not values or values[-1] <= cutoff
        ]
        for key in expired:
            self._attempts.pop(key, None)


# Preserve the old import name for downstream exercises while accurately naming
# the implementation everywhere new code is written.
FixedWindowRateLimiter = SlidingWindowRateLimiter


class DatabaseRateLimiter:
    """PostgreSQL-backed fixed-window limit shared by every API replica.

    Keys are SHA-256 digests, so email addresses and raw IPs do not become a
    second PII store.  PostgreSQL's upsert row lock makes each increment atomic.
    """

    def __init__(self, pool: ConnectionPool, *, limit: int, window: timedelta) -> None:
        self.pool = pool
        self.limit = max(1, limit)
        self.window_seconds = max(1, int(window.total_seconds()))
        self._maintenance_lock = Lock()
        self._checks = 0

    def check(self, key: str) -> RateLimit:
        key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
        with self.pool.connection() as connection:
            row = connection.execute(
                """
                INSERT INTO auth_rate_limits (
                    key_hash, window_started_at, attempts, updated_at
                ) VALUES (%s, now(), 1, now())
                ON CONFLICT (key_hash) DO UPDATE
                SET attempts = CASE
                        WHEN auth_rate_limits.window_started_at
                             <= now() - make_interval(secs => %s)
                        THEN 1 ELSE auth_rate_limits.attempts + 1
                    END,
                    window_started_at = CASE
                        WHEN auth_rate_limits.window_started_at
                             <= now() - make_interval(secs => %s)
                        THEN now() ELSE auth_rate_limits.window_started_at
                    END,
                    updated_at = now()
                RETURNING attempts, window_started_at, now() AS checked_at
                """,
                (key_hash, self.window_seconds, self.window_seconds),
            ).fetchone()
            if self._maintenance_due():
                connection.execute(
                    """
                    DELETE FROM auth_rate_limits
                    WHERE updated_at < now() - interval '24 hours'
                    """
                )
        if row["attempts"] <= self.limit:
            return RateLimit(True, 0)
        elapsed = (row["checked_at"] - row["window_started_at"]).total_seconds()
        return RateLimit(False, int(max(1, self.window_seconds - elapsed)))

    def _maintenance_due(self) -> bool:
        # Opportunistic bounded cleanup avoids a new scheduler dependency. It is
        # not on every request, so the indexed delete remains inexpensive.
        with self._maintenance_lock:
            self._checks += 1
            return self._checks % 256 == 0


class RequestBodyLimitMiddleware:
    """Reject oversized bodies even when ``Content-Length`` is absent or false.

    The middleware reads at most ``max_bytes`` plus the first overflowing chunk,
    then replays the bounded body to FastAPI.  This covers chunked requests that
    would bypass a header-only size check.
    """

    def __init__(self, app: Any, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                declared_length = int(raw_length)
            except ValueError:
                await self._reject(
                    scope,
                    receive,
                    send,
                    400,
                    "INVALID_CONTENT_LENGTH",
                    "invalid request size",
                )
                return
            if declared_length < 0:
                await self._reject(
                    scope,
                    receive,
                    send,
                    400,
                    "INVALID_CONTENT_LENGTH",
                    "invalid request size",
                )
                return
            if declared_length > self.max_bytes:
                await self._reject(
                    scope,
                    receive,
                    send,
                    413,
                    "REQUEST_TOO_LARGE",
                    "request body is too large",
                )
                return

        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                await self._reject(
                    scope,
                    receive,
                    send,
                    413,
                    "REQUEST_TOO_LARGE",
                    "request body is too large",
                )
                return
            more_body = bool(message.get("more_body", False))

        delivered = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(
        scope: dict[str, Any],
        receive: Any,
        send: Any,
        status: int,
        code: str,
        message: str,
    ) -> None:
        payload = json.dumps({"error": {"code": code, "message": message}}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
            (b"cache-control", b"no-store"),
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"content-security-policy", API_CONTENT_SECURITY_POLICY.encode()),
        ]
        await send(
            {"type": "http.response.start", "status": status, "headers": headers}
        )
        await send({"type": "http.response.body", "body": payload})
