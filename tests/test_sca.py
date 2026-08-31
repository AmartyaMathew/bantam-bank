"""Regression tests for transaction-bound SCA and one-time consumption."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from bantam.domain import ROLE_CUSTOMER, Principal
from bantam.errors import BantamError
from bantam.sca import SCAService


class Result:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class ChallengeConnection:
    """Minimal stateful Psycopg stand-in for the SCA transaction tests."""

    def __init__(self, challenge: dict[str, object]) -> None:
        self.challenge = challenge

    def execute(self, query: str, parameters):
        if "FROM sca_challenges" in query:
            return Result(dict(self.challenge))
        if "UPDATE sca_challenges" in query:
            if self.challenge["status"] != "PENDING":
                return Result(None)
            self.challenge["status"] = "CONSUMED"
            return Result({"challenge_id": parameters[0]})
        raise AssertionError(f"unexpected SQL in SCA test: {query}")


def challenge_fixture():
    service = SCAService("s" * 32, timedelta(minutes=5), 500_000, False)
    principal = Principal(user_id=uuid4(), customer_id=uuid4(), role=ROLE_CUSTOMER)
    challenge_id = uuid4()
    source_id = uuid4()
    destination_id = uuid4()
    amount = 600_000
    code = "381204"
    challenge = {
        "user_id": principal.user_id,
        "source_account_id": source_id,
        "destination_account_id": destination_id,
        "amount_minor": amount,
        "code_hash": service._hash(
            challenge_id,
            principal.user_id,
            source_id,
            destination_id,
            amount,
            code,
        ),
        "status": "PENDING",
        "expires_at": datetime.now(UTC) + timedelta(minutes=4),
    }
    return (
        service,
        principal,
        challenge_id,
        source_id,
        destination_id,
        amount,
        code,
        challenge,
    )


_UNSET = object()


def validate(
    fixture,
    *,
    principal=_UNSET,
    source=_UNSET,
    destination=_UNSET,
    amount=_UNSET,
    code=_UNSET,
):
    (
        service,
        expected_principal,
        challenge_id,
        source_id,
        destination_id,
        expected_amount,
        expected_code,
        challenge,
    ) = fixture
    connection = ChallengeConnection(challenge)
    service.validate_and_consume(
        connection,
        expected_principal if principal is _UNSET else principal,
        source_id if source is _UNSET else source,
        destination_id if destination is _UNSET else destination,
        expected_amount if amount is _UNSET else amount,
        challenge_id,
        expected_code if code is _UNSET else code,
    )
    return connection


def test_sca_success_consumes_challenge_once() -> None:
    fixture = challenge_fixture()
    connection = validate(fixture)

    assert connection.challenge["status"] == "CONSUMED"
    with pytest.raises(BantamError) as replayed:
        fixture[0].validate_and_consume(
            connection,
            fixture[1],
            fixture[3],
            fixture[4],
            fixture[5],
            fixture[2],
            fixture[6],
        )
    assert replayed.value.code == "SCA_FAILED"


@pytest.mark.parametrize("change", ["principal", "source", "destination", "amount"])
def test_sca_rejects_every_changed_binding(change: str) -> None:
    fixture = challenge_fixture()
    overrides = {
        "principal": Principal(
            user_id=uuid4(), customer_id=fixture[1].customer_id, role=ROLE_CUSTOMER
        ),
        "source": uuid4(),
        "destination": uuid4(),
        "amount": fixture[5] + 1,
    }

    with pytest.raises(BantamError) as raised:
        validate(fixture, **{change: overrides[change]})

    assert raised.value.code == "SCA_FAILED"
    assert fixture[-1]["status"] == "PENDING"


def test_sca_rejects_wrong_code_and_expired_challenge() -> None:
    wrong_code = challenge_fixture()
    with pytest.raises(BantamError) as raised:
        validate(wrong_code, code="000000")
    assert raised.value.code == "SCA_FAILED"

    expired = challenge_fixture()
    expired[-1]["expires_at"] = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(BantamError) as raised:
        validate(expired)
    assert raised.value.code == "SCA_FAILED"


@pytest.mark.parametrize("code", ["", "12345", "1234567", "１２３４５６", "abcdef"])
def test_sca_requires_exactly_six_ascii_digits(code: str) -> None:
    fixture = challenge_fixture()

    with pytest.raises(BantamError) as raised:
        validate(fixture, code=code)

    assert raised.value.code == "SCA_REQUIRED"
