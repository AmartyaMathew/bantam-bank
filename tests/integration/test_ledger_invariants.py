"""Live PostgreSQL checks for invariants the application cannot bypass."""

from __future__ import annotations

import os

import psycopg
import pytest
from psycopg import errors
from psycopg.rows import dict_row


DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not DATABASE_URL, reason="TEST_DATABASE_URL is not configured"),
]


def connect():
    return psycopg.connect(DATABASE_URL, autocommit=True, row_factory=dict_row)


def test_every_transaction_is_balanced() -> None:
    with connect() as connection:
        unbalanced = connection.execute(
            """
            SELECT transaction_id, COUNT(*) AS entries, SUM(amount_minor) AS total
            FROM ledger_entries
            GROUP BY transaction_id
            HAVING COUNT(*) < 2 OR SUM(amount_minor) <> 0
            """
        ).fetchall()

    assert unbalanced == []


def test_balance_projection_matches_ledger() -> None:
    with connect() as connection:
        mismatches = connection.execute(
            """
            SELECT b.account_id
            FROM account_balances b
            LEFT JOIN ledger_entries e ON e.account_id = b.account_id
            GROUP BY b.account_id, b.current_balance_minor
            HAVING b.current_balance_minor <> COALESCE(SUM(e.amount_minor), 0)
            """
        ).fetchall()

    assert mismatches == []


def test_ledger_entries_are_immutable() -> None:
    with connect() as connection:
        entry = connection.execute(
            "SELECT ledger_entry_id FROM ledger_entries LIMIT 1"
        ).fetchone()
        if entry is None:
            pytest.skip("seed data has not posted a ledger entry")
        with pytest.raises(errors.RaiseException, match="append-only"):
            connection.execute(
                "UPDATE ledger_entries SET amount_minor = amount_minor WHERE ledger_entry_id = %s",
                (entry["ledger_entry_id"],),
            )


def test_database_rejects_negative_customer_projection() -> None:
    with connect() as connection:
        account = connection.execute(
            """
            SELECT account_id FROM bank_accounts
            WHERE account_type = 'CURRENT'
            LIMIT 1
            """
        ).fetchone()
        if account is None:
            pytest.skip("seed data has not created a customer account")
        with pytest.raises(errors.CheckViolation, match="cannot have a negative"):
            connection.execute(
                """
                UPDATE account_balances
                SET current_balance_minor = -1, available_balance_minor = -1
                WHERE account_id = %s
                """,
                (account["account_id"],),
            )


def test_available_projection_cannot_exceed_current_projection() -> None:
    with connect() as connection:
        account = connection.execute(
            "SELECT account_id FROM account_balances LIMIT 1"
        ).fetchone()
        if account is None:
            pytest.skip("seed data has not created an account balance")
        with pytest.raises(errors.CheckViolation):
            connection.execute(
                """
                UPDATE account_balances
                SET available_balance_minor = current_balance_minor + 1
                WHERE account_id = %s
                """,
                (account["account_id"],),
            )


def test_account_classification_is_immutable() -> None:
    with connect() as connection:
        system = connection.execute(
            "SELECT account_id FROM bank_accounts WHERE account_type = 'SYSTEM' LIMIT 1"
        ).fetchone()
        customer = connection.execute(
            "SELECT customer_id FROM customers LIMIT 1"
        ).fetchone()
        if system is None or customer is None:
            pytest.skip("seed data has not created system and customer identities")
        with pytest.raises(errors.CheckViolation, match="classification is immutable"):
            connection.execute(
                """
                UPDATE bank_accounts
                SET account_type = 'CURRENT', customer_id = %s,
                    allow_negative = false
                WHERE account_id = %s
                """,
                (customer["customer_id"], system["account_id"]),
            )


def test_posted_transaction_metadata_is_immutable() -> None:
    with connect() as connection:
        transaction = connection.execute(
            "SELECT transaction_id FROM transactions WHERE status = 'POSTED' LIMIT 1"
        ).fetchone()
        if transaction is None:
            pytest.skip("seed data has not posted a transaction")
        with pytest.raises(errors.RaiseException, match="history is immutable"):
            connection.execute(
                """
                UPDATE transactions SET description = description || ' changed'
                WHERE transaction_id = %s
                """,
                (transaction["transaction_id"],),
            )


def test_asvs_evidence_runs_are_immutable() -> None:
    with connect() as connection:
        run = connection.execute(
            "SELECT run_id FROM asvs_runs ORDER BY completed_at DESC LIMIT 1"
        ).fetchone()
        if run is None:
            pytest.skip("no ASVS evidence run has been recorded")
        with pytest.raises(errors.RaiseException, match="append-only"):
            connection.execute(
                "UPDATE asvs_runs SET status = status WHERE run_id = %s",
                (run["run_id"],),
            )
