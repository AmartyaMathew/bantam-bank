from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest

from bantam.auth import (
    AuthService,
    SignedClaimService,
    check_password,
    hash_password,
    password_hash_for_check,
)
from bantam.domain import (
    ROLE_ASPIS_ADMIN,
    ROLE_ASPIS_AUDITOR,
    ROLE_CUSTOMER,
    Principal,
)


def test_password_hash_round_trip() -> None:
    password_hash = hash_password("BantamDemo123!")

    assert password_hash != "BantamDemo123!"
    assert check_password(password_hash, "BantamDemo123!")
    assert not check_password(password_hash, "not-the-password")


def test_password_minimum_length() -> None:
    with pytest.raises(ValueError, match="at least 14"):
        hash_password("short")


def test_password_complexity() -> None:
    with pytest.raises(ValueError, match="uppercase"):
        hash_password("bantamdemo123!")


def test_password_rejects_personal_details() -> None:
    with pytest.raises(ValueError, match="personal details"):
        hash_password(
            "AliceMorgan123!",
            disallowed_values=("alice@example.test", "Alice Morgan"),
        )


def test_dummy_password_hash_can_be_checked() -> None:
    assert not check_password(password_hash_for_check(None), "BantamDemo123!")


def test_jwt_round_trip_preserves_principal() -> None:
    service = AuthService("a" * 32, timedelta(minutes=15))
    principal = Principal(user_id=uuid4(), customer_id=uuid4(), role=ROLE_CUSTOMER)

    token, expires_at = service.issue(principal)

    assert service.parse(token) == principal
    parsed = service.parse_with_claims(token)
    assert parsed.principal == principal
    assert parsed.jti
    assert parsed.expires_at.tzinfo is not None
    assert parsed.auth_methods == ("pwd",)
    assert parsed.mfa_at is None
    assert expires_at.tzinfo is not None


def test_jwt_round_trip_accepts_aspis_auditor() -> None:
    service = AuthService("a" * 32, timedelta(minutes=15))
    principal = Principal(user_id=uuid4(), role=ROLE_ASPIS_AUDITOR)

    token, _ = service.issue(principal)

    assert service.parse(token) == principal


def test_jwt_round_trip_preserves_mfa_assurance() -> None:
    service = AuthService("a" * 32, timedelta(minutes=15))
    principal = Principal(user_id=uuid4(), role=ROLE_ASPIS_ADMIN)
    verified_at = datetime.now(UTC)

    token, _ = service.issue(
        principal,
        auth_methods=("pwd", "webauthn"),
        mfa_at=verified_at,
    )

    parsed = service.parse_with_claims(token)
    assert parsed.principal == principal
    assert parsed.auth_methods == ("pwd", "webauthn")
    assert parsed.mfa_at is not None
    assert abs((parsed.mfa_at - verified_at).total_seconds()) < 1


def test_jwt_rejects_mfa_method_without_timestamp() -> None:
    service = AuthService("a" * 32, timedelta(minutes=15))
    principal = Principal(user_id=uuid4(), role=ROLE_ASPIS_ADMIN)

    token, _ = service.issue(
        principal,
        auth_methods=("pwd", "otp"),
        mfa_at=datetime.now(UTC),
    )
    claims = jwt.decode(
        token,
        "a" * 32,
        algorithms=["HS256"],
        audience="bantam-api",
        issuer="bantam-auth",
    )
    claims.pop("mfa_at")
    tampered = jwt.encode(
        claims,
        "a" * 32,
        algorithm="HS256",
        headers={"typ": "JWT"},
    )

    with pytest.raises(ValueError, match="invalid access token"):
        service.parse(tampered)


def test_jwt_rejects_wrong_secret() -> None:
    issuer = AuthService("a" * 32, timedelta(minutes=15))
    verifier = AuthService("b" * 32, timedelta(minutes=15))
    token, _ = issuer.issue(Principal(user_id=uuid4(), role="BANK_ADMIN"))

    with pytest.raises(ValueError, match="invalid access token"):
        verifier.parse(token)


def test_jwt_rejects_unknown_role() -> None:
    service = AuthService("a" * 32, timedelta(minutes=15))
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": str(uuid4()),
            "iss": "bantam-auth",
            "aud": ["bantam-api"],
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=15),
            "jti": str(uuid4()),
            "role": "ROOT",
        },
        "a" * 32,
        algorithm="HS256",
    )

    with pytest.raises(ValueError, match="invalid access token"):
        service.parse(token)


def test_jwt_rejects_customer_role_without_customer_identity() -> None:
    service = AuthService("a" * 32, timedelta(minutes=15))
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": str(uuid4()),
            "iss": "bantam-auth",
            "aud": ["bantam-api"],
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=15),
            "jti": str(uuid4()),
            "role": ROLE_CUSTOMER,
        },
        "a" * 32,
        algorithm="HS256",
        headers={"typ": "JWT"},
    )

    with pytest.raises(ValueError, match="invalid access token"):
        service.parse(token)


def test_account_status_assertion_is_signed_and_bound() -> None:
    service = SignedClaimService("c" * 32)
    claim_id = uuid4()
    customer_id = uuid4()

    token, expires_at = service.issue_account_status(
        claim_id=claim_id,
        customer_id=customer_id,
        has_active_account=True,
        kyc_status="verified",
    )
    claims = service.verify_account_status(token)

    assert claims["jti"] == str(claim_id)
    assert claims["sub"] == f"did:xid:person:{customer_id}"
    assert claims["has_active_account"] is True
    assert expires_at.tzinfo is not None


def test_account_status_assertion_rejects_wrong_key() -> None:
    issuer = SignedClaimService("c" * 32)
    verifier = SignedClaimService("d" * 32)
    token, _ = issuer.issue_account_status(
        claim_id=uuid4(),
        customer_id=uuid4(),
        has_active_account=False,
        kyc_status="pending",
    )

    with pytest.raises(ValueError, match="invalid account-status assertion"):
        verifier.verify_account_status(token)
