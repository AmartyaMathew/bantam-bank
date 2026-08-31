"""One-shot production administrator bootstrap regressions."""

from __future__ import annotations

from uuid import UUID

import pytest

import bantam.seed as seed_module
from bantam.domain import ROLE_ASPIS_ADMIN, ROLE_BANK_ADMIN


class FakeResult:
    def __init__(self, row=None) -> None:
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, existing=None) -> None:
        self.existing = existing
        self.executions: list[tuple[str, tuple[object, ...]]] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def transaction(self):
        return self

    def execute(self, statement: str, parameters=()) -> FakeResult:
        normalized = " ".join(statement.split())
        self.executions.append((normalized, tuple(parameters)))
        if normalized.startswith("SELECT user_id, role FROM user_accounts"):
            return FakeResult(self.existing)
        return FakeResult()


class FakePool:
    def __init__(self, connection: FakeConnection) -> None:
        self._connection = connection

    def connection(self) -> FakeConnection:
        return self._connection


def test_bank_admin_bootstrap_creates_exact_role(monkeypatch) -> None:
    connection = FakeConnection()
    monkeypatch.setattr(seed_module, "hash_password", lambda *args, **kwargs: "hash")

    user_id = seed_module.bootstrap_bank_admin(
        FakePool(connection),
        email=" Admin@Example.Test ",
        password="GeneratedBootstrapPassword123!",
    )

    inserts = [
        parameters
        for statement, parameters in connection.executions
        if statement.startswith("INSERT INTO user_accounts")
    ]
    assert len(inserts) == 1
    assert inserts[0] == (
        user_id,
        "admin@example.test",
        "hash",
        ROLE_BANK_ADMIN,
    )


def test_bank_admin_bootstrap_never_resets_existing_account(monkeypatch) -> None:
    existing_id = UUID("10000000-0000-0000-0000-000000000099")
    connection = FakeConnection({"user_id": existing_id, "role": ROLE_BANK_ADMIN})
    monkeypatch.setattr(seed_module, "hash_password", lambda *args, **kwargs: "hash")

    result = seed_module.bootstrap_bank_admin(
        FakePool(connection),
        email="admin@example.test",
        password="GeneratedBootstrapPassword123!",
    )

    assert result == existing_id
    assert not any(
        statement.startswith("INSERT INTO user_accounts")
        for statement, _ in connection.executions
    )


def test_bank_admin_bootstrap_rejects_role_collision(monkeypatch) -> None:
    connection = FakeConnection(
        {
            "user_id": UUID("10000000-0000-0000-0000-000000000098"),
            "role": ROLE_ASPIS_ADMIN,
        }
    )
    monkeypatch.setattr(seed_module, "hash_password", lambda *args, **kwargs: "hash")

    with pytest.raises(ValueError, match="different account role"):
        seed_module.bootstrap_bank_admin(
            FakePool(connection),
            email="admin@example.test",
            password="GeneratedBootstrapPassword123!",
        )


def test_bank_admin_bootstrap_validates_email_before_database(monkeypatch) -> None:
    monkeypatch.setattr(seed_module, "hash_password", lambda *args, **kwargs: "hash")

    with pytest.raises(ValueError, match="BANK_ADMIN_BOOTSTRAP_EMAIL"):
        seed_module.bootstrap_bank_admin(
            FakePool(FakeConnection()),
            email="invalid",
            password="GeneratedBootstrapPassword123!",
        )
