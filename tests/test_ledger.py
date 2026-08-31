from __future__ import annotations

from uuid import uuid4

import pytest

from bantam.domain import ROLE_BANK_ADMIN, ROLE_CUSTOMER, Principal, TransferCommand
from bantam.errors import BantamError
from bantam.ledger import LedgerService


def command(**overrides) -> TransferCommand:
    values = {
        "request_id": uuid4(),
        "idempotency_key": "test-transfer-1",
        "actor": Principal(user_id=uuid4(), customer_id=uuid4(), role=ROLE_CUSTOMER),
        "source_account_id": uuid4(),
        "destination_account_id": uuid4(),
        "amount_minor": 2500,
        "currency": "gbp",
        "description": "  Dinner split  ",
    }
    values.update(overrides)
    return TransferCommand(**values)


def test_transfer_normalisation() -> None:
    normalised = LedgerService._normalise(command())

    assert normalised.currency == "GBP"
    assert normalised.description == "Dinner split"
    assert normalised.idempotency_key == "test-transfer-1"


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"amount_minor": 0}, "amount_minor must be positive"),
        ({"currency": "USD"}, "only GBP is supported"),
        ({"idempotency_key": " "}, "invalid idempotency key"),
    ],
)
def test_transfer_validation(override, message: str) -> None:
    with pytest.raises(BantamError, match=message):
        LedgerService._normalise(command(**override))


def test_only_admin_can_use_operator_override() -> None:
    with pytest.raises(BantamError) as raised:
        LedgerService._normalise(command(operator_override=True))
    assert raised.value.code == "FORBIDDEN"

    admin = Principal(user_id=uuid4(), role=ROLE_BANK_ADMIN)
    assert LedgerService._normalise(
        command(actor=admin, operator_override=True)
    ).operator_override


def test_account_lock_reads_available_balance_for_spend_check() -> None:
    source_id = uuid4()
    destination_id = uuid4()

    class Result:
        def fetchall(self):
            return [
                {"account_id": source_id},
                {"account_id": destination_id},
            ]

    class Connection:
        query = ""

        def execute(self, query, parameters):
            self.query = query
            assert parameters == (source_id, destination_id)
            return Result()

    connection = Connection()
    LedgerService._lock_accounts(connection, source_id, destination_id)

    assert "available_balance_minor AS balance_minor" in connection.query
