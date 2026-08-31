"""Password hashing, session tokens, and signed demo claims.

Authentication and account-status assertions use separate keys so compromise of
one trust domain does not automatically grant signing authority in the other.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import bcrypt
import jwt

from bantam.domain import (
    ROLE_ASPIS_ADMIN,
    ROLE_ASPIS_AUDITOR,
    ROLE_BANK_ADMIN,
    ROLE_COMPLIANCE_AUDITOR,
    ROLE_CUSTOMER,
    ROLE_RISK_ANALYST,
    Principal,
)
from bantam.security import validate_password

if TYPE_CHECKING:
    from psycopg import Connection
    from psycopg_pool import ConnectionPool


ALLOWED_ROLES = {
    ROLE_ASPIS_ADMIN,
    ROLE_ASPIS_AUDITOR,
    ROLE_BANK_ADMIN,
    ROLE_COMPLIANCE_AUDITOR,
    ROLE_CUSTOMER,
    ROLE_RISK_ANALYST,
}
JWT_ALGORITHM = "HS256"
BCRYPT_ROUNDS = 12
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(
    b"bantam-dummy-password-for-timing", bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
).decode()


@dataclass(frozen=True, slots=True)
class ParsedAccessToken:
    """Verified JWT metadata needed for revocation and authorization."""

    principal: Principal
    jti: UUID
    expires_at: datetime
    auth_methods: tuple[str, ...]
    mfa_at: datetime | None


_REVOCATION_POOL: "ConnectionPool | None" = None


def set_revocation_pool(pool: "ConnectionPool | None") -> None:
    """Register the application database pool used for JWT revocation checks."""

    global _REVOCATION_POOL
    _REVOCATION_POOL = pool


def revoke_access_token(connection: "Connection", token: ParsedAccessToken) -> None:
    """Add an explicitly logged-out JWT to the short-lived revocation list."""

    connection.execute("DELETE FROM session_revocations WHERE expires_at <= now()")
    connection.execute(
        """
        INSERT INTO session_revocations (jti, user_id, expires_at)
        VALUES (%s, %s, %s)
        ON CONFLICT (jti) DO NOTHING
        """,
        (token.jti, token.principal.user_id, token.expires_at),
    )


def _reject_revoked_token(token_id: UUID) -> None:
    if _REVOCATION_POOL is None:
        return
    try:
        with _REVOCATION_POOL.connection() as connection:
            row = connection.execute(
                """
                SELECT EXISTS (
                    SELECT 1 FROM session_revocations
                    WHERE jti = %s AND expires_at > now()
                ) AS revoked
                """,
                (token_id,),
            ).fetchone()
    except Exception as error:  # pragma: no cover - defensive fail-closed path
        raise ValueError("invalid access token") from error
    if row and row["revoked"]:
        raise ValueError("invalid access token")


def hash_password(password: str, *, disallowed_values=()) -> str:
    """Validate and hash a password using an explicit bcrypt work factor."""

    validate_password(password, disallowed_values=disallowed_values)
    return bcrypt.hashpw(
        password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode()


def check_password(password_hash: str, password: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except (TypeError, ValueError):
        return False


class AuthService:
    """Issue and verify short-lived API session JWTs."""

    def __init__(self, secret: str, ttl: timedelta) -> None:
        self.secret = secret
        self.ttl = ttl

    def issue(
        self,
        principal: Principal,
        *,
        auth_methods: tuple[str, ...] = ("pwd",),
        mfa_at: datetime | None = None,
    ) -> tuple[str, datetime]:
        if principal.role not in ALLOWED_ROLES:
            raise ValueError("unknown role")
        if (
            not auth_methods
            or "pwd" not in auth_methods
            or not set(auth_methods) <= {"pwd", "webauthn", "otp"}
            or len(set(auth_methods)) != len(auth_methods)
        ):
            raise ValueError("invalid authentication methods")
        if mfa_at is not None:
            if mfa_at.tzinfo is None or not {"webauthn", "otp"} & set(auth_methods):
                raise ValueError("invalid MFA timestamp")
            mfa_at = mfa_at.astimezone(UTC)
        now = datetime.now(UTC)
        expires_at = now + self.ttl
        token_id = uuid4()
        claims: dict[str, object] = {
            "sub": str(principal.user_id),
            "iss": "bantam-auth",
            "aud": ["bantam-api"],
            "iat": now,
            "nbf": now,
            "exp": expires_at,
            "jti": str(token_id),
            "role": principal.role,
            "amr": list(auth_methods),
        }
        if mfa_at is not None:
            claims["mfa_at"] = int(mfa_at.timestamp())
        if principal.customer_id:
            claims["customer_id"] = str(principal.customer_id)
        token = jwt.encode(
            claims,
            self.secret,
            algorithm=JWT_ALGORITHM,
            headers={"typ": "JWT"},
        )
        return token, expires_at

    def parse(self, raw_token: str) -> Principal:
        return self.parse_with_claims(raw_token).principal

    def parse_with_claims(self, raw_token: str) -> ParsedAccessToken:
        if len(raw_token) > 4096:
            raise ValueError("invalid access token")
        try:
            header = jwt.get_unverified_header(raw_token)
            if header.get("alg") != JWT_ALGORITHM or header.get("typ") != "JWT":
                raise ValueError("invalid access token")
            claims = jwt.decode(
                raw_token,
                self.secret,
                algorithms=[JWT_ALGORITHM],
                audience="bantam-api",
                issuer="bantam-auth",
                options={
                    "require": [
                        "sub",
                        "exp",
                        "iat",
                        "nbf",
                        "iss",
                        "aud",
                        "jti",
                        "role",
                        "amr",
                    ]
                },
            )
            role = str(claims["role"])
            if role not in ALLOWED_ROLES:
                raise ValueError("unknown role")
            raw_auth_methods = claims["amr"]
            if not isinstance(raw_auth_methods, list):
                raise ValueError("invalid authentication methods")
            auth_methods = tuple(str(method) for method in raw_auth_methods)
            if (
                not auth_methods
                or "pwd" not in auth_methods
                or not set(auth_methods) <= {"pwd", "webauthn", "otp"}
                or len(set(auth_methods)) != len(auth_methods)
            ):
                raise ValueError("invalid authentication methods")
            raw_mfa_at = claims.get("mfa_at")
            mfa_at = (
                datetime.fromtimestamp(int(raw_mfa_at), UTC)
                if raw_mfa_at is not None
                else None
            )
            if (mfa_at is None) != (not bool({"webauthn", "otp"} & set(auth_methods))):
                raise ValueError("invalid MFA timestamp")
            customer_id = claims.get("customer_id")
            if (role == ROLE_CUSTOMER) != bool(customer_id):
                raise ValueError("customer identity does not match role")
            principal = Principal(
                user_id=UUID(str(claims["sub"])),
                role=role,
                customer_id=UUID(str(customer_id)) if customer_id else None,
            )
            parsed = ParsedAccessToken(
                principal=principal,
                jti=UUID(str(claims["jti"])),
                expires_at=datetime.fromtimestamp(int(claims["exp"]), UTC),
                auth_methods=auth_methods,
                mfa_at=mfa_at,
            )
            _reject_revoked_token(parsed.jti)
            return parsed
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as error:
            raise ValueError("invalid access token") from error


def password_hash_for_check(password_hash: str | None) -> str:
    """Use a real bcrypt hash to keep unknown-user login timing comparable."""

    return password_hash or _DUMMY_PASSWORD_HASH


class SignedClaimService:
    """Issue locally verifiable, short-lived account-status assertions.

    This is a signed demonstration payload, not a public verifiable credential:
    an external verifier would need a managed asymmetric key and published key
    discovery rather than this repository's HMAC model.
    """

    def __init__(self, secret: str, ttl: timedelta = timedelta(hours=24)) -> None:
        self.secret = secret
        self.ttl = ttl

    def issue_account_status(
        self,
        *,
        claim_id: UUID,
        customer_id: UUID,
        has_active_account: bool,
        kyc_status: str,
    ) -> tuple[str, datetime]:
        now = datetime.now(UTC)
        expires_at = now + self.ttl
        claims: dict[str, object] = {
            "jti": str(claim_id),
            "iss": "did:xbank:bantam",
            "sub": f"did:xid:person:{customer_id}",
            "aud": ["bantam-account-status-verifier"],
            "iat": now,
            "nbf": now,
            "exp": expires_at,
            "claim_type": "bank_account_status",
            "has_active_account": has_active_account,
            "kyc_status": kyc_status,
        }
        token = jwt.encode(
            claims,
            self.secret,
            algorithm=JWT_ALGORITHM,
            headers={"typ": "bantam-account-status+jwt"},
        )
        return token, expires_at

    def verify_account_status(self, token: str) -> dict[str, object]:
        """Verify a demonstration assertion for tests or trusted consumers."""

        if len(token) > 8192:
            raise ValueError("invalid account-status assertion")
        try:
            header = jwt.get_unverified_header(token)
            if (
                header.get("alg") != JWT_ALGORITHM
                or header.get("typ") != "bantam-account-status+jwt"
            ):
                raise ValueError("invalid account-status assertion")
            return jwt.decode(
                token,
                self.secret,
                algorithms=[JWT_ALGORITHM],
                audience="bantam-account-status-verifier",
                issuer="did:xbank:bantam",
                options={
                    "require": [
                        "jti",
                        "iss",
                        "sub",
                        "aud",
                        "iat",
                        "nbf",
                        "exp",
                        "claim_type",
                    ]
                },
            )
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as error:
            raise ValueError("invalid account-status assertion") from error
