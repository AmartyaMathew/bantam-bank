"""Atomic money movement and reconciliation over the immutable ledger.

The service deliberately owns the full transfer transaction: authorization,
SCA consumption, account locks, postings, balance projections, audit evidence,
and outbox publication either commit together or do not commit at all.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from psycopg import errors, sql
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from bantam import audit
from bantam.domain import (
    ACCOUNT_ACTIVE,
    KYC_VERIFIED,
    ROLE_BANK_ADMIN,
    TransferCommand,
)
from bantam.errors import (
    ACCOUNT_FROZEN,
    CONFLICT,
    CURRENCY_MISMATCH,
    FORBIDDEN,
    INSUFFICIENT_FUNDS,
    KYC_NOT_VERIFIED,
    NOT_FOUND,
    validation,
)
from bantam.money import balanced
from bantam.sca import SCAService


TRANSACTION_COLUMNS = """
    transaction_id, idempotency_key, request_id,
    source_account_id, destination_account_id, amount_minor,
    currency, description, transaction_type, status,
    failure_reason, created_at, posted_at
"""

# Psycopg's composable SQL API keeps even source-code-owned structural SQL out
# of Python interpolation.  Values continue to use `%s` parameters at call
# sites; these objects contain column identifiers only.
TRANSACTION_PROJECTION = sql.SQL(TRANSACTION_COLUMNS)
ALIASED_TRANSACTION_PROJECTION = sql.SQL(", ").join(
    sql.Identifier("t", column.strip())
    for column in TRANSACTION_COLUMNS.split(",")
    if column.strip()
)


def transaction_payload(row) -> dict[str, object]:
    payload = dict(row)
    if payload.get("failure_reason") is None:
        payload.pop("failure_reason", None)
    if payload.get("posted_at") is None:
        payload.pop("posted_at", None)
    return payload


class LedgerService:
    def __init__(self, pool: ConnectionPool, sca: SCAService) -> None:
        self.pool = pool
        self.sca = sca

    def create_transfer(
        self, command: TransferCommand
    ) -> tuple[dict[str, object], bool]:
        command = self._normalise(command)
        existing = self.find_by_idempotency(
            command.actor.user_id, command.idempotency_key
        )
        if existing:
            return existing, True

        try:
            with self.pool.connection() as connection:
                with connection.transaction():
                    connection.execute(
                        """
                        SELECT pg_advisory_xact_lock(
                            hashtextextended(%s::text || ':' || %s::text, 0)
                        )
                        """,
                        (command.actor.user_id, command.idempotency_key),
                    )
                    existing = connection.execute(
                        sql.SQL(
                            """
                        SELECT {}
                        FROM transactions
                        WHERE initiated_by_user_id = %s AND idempotency_key = %s
                        """
                        ).format(TRANSACTION_PROJECTION),
                        (command.actor.user_id, command.idempotency_key),
                    ).fetchone()
                    if existing:
                        return transaction_payload(existing), True

                    accounts = self._lock_accounts(
                        connection,
                        command.source_account_id,
                        command.destination_account_id,
                    )
                    source = accounts[command.source_account_id]
                    destination = accounts[command.destination_account_id]

                    if (
                        source["status"] != ACCOUNT_ACTIVE
                        or destination["status"] != ACCOUNT_ACTIVE
                    ):
                        raise ACCOUNT_FROZEN()
                    if (
                        source["currency"] != command.currency
                        or destination["currency"] != command.currency
                    ):
                        raise CURRENCY_MISMATCH()

                    if not command.operator_override:
                        if (
                            command.actor.customer_id is None
                            or source["customer_id"] is None
                            or command.actor.customer_id != source["customer_id"]
                        ):
                            raise FORBIDDEN()
                        customer = connection.execute(
                            "SELECT kyc_status FROM customers WHERE customer_id = %s",
                            (command.actor.customer_id,),
                        ).fetchone()
                        if not customer or customer["kyc_status"] != KYC_VERIFIED:
                            raise KYC_NOT_VERIFIED()
                        self.sca.validate_and_consume(
                            connection,
                            command.actor,
                            command.source_account_id,
                            command.destination_account_id,
                            command.amount_minor,
                            command.sca_challenge_id,
                            command.sca_code,
                        )

                    if (
                        not source["allow_negative"]
                        and source["balance_minor"] < command.amount_minor
                    ):
                        raise INSUFFICIENT_FUNDS()
                    if not balanced(-command.amount_minor, command.amount_minor):
                        raise RuntimeError("internal ledger invariant failed")

                    if command.reverses_transaction_id:
                        self._validate_reversal(connection, command)

                    transaction_id = uuid4()
                    posted_at = datetime.now(UTC)
                    connection.execute(
                        """
                        INSERT INTO transactions (
                            transaction_id, idempotency_key, request_id,
                            initiated_by_user_id, source_account_id,
                            destination_account_id, amount_minor, currency,
                            description, transaction_type,
                            reverses_transaction_id, status, posted_at
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'POSTED',%s)
                        """,
                        (
                            transaction_id,
                            command.idempotency_key,
                            command.request_id,
                            command.actor.user_id,
                            command.source_account_id,
                            command.destination_account_id,
                            command.amount_minor,
                            command.currency,
                            command.description,
                            command.transaction_type,
                            command.reverses_transaction_id,
                            posted_at,
                        ),
                    )

                    debit_entry_id = uuid4()
                    credit_entry_id = uuid4()
                    connection.execute(
                        """
                        INSERT INTO ledger_entries (
                            ledger_entry_id, transaction_id, account_id,
                            amount_minor, currency, direction, entry_type
                        ) VALUES
                            (%s,%s,%s,%s,%s,'DEBIT',%s),
                            (%s,%s,%s,%s,%s,'CREDIT',%s)
                        """,
                        (
                            debit_entry_id,
                            transaction_id,
                            command.source_account_id,
                            -command.amount_minor,
                            command.currency,
                            command.transaction_type,
                            credit_entry_id,
                            transaction_id,
                            command.destination_account_id,
                            command.amount_minor,
                            command.currency,
                            command.transaction_type,
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE account_balances
                        SET current_balance_minor = current_balance_minor - %s,
                            available_balance_minor = available_balance_minor - %s,
                            last_ledger_entry_id = %s, updated_at = now()
                        WHERE account_id = %s
                        """,
                        (
                            command.amount_minor,
                            command.amount_minor,
                            debit_entry_id,
                            command.source_account_id,
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE account_balances
                        SET current_balance_minor = current_balance_minor + %s,
                            available_balance_minor = available_balance_minor + %s,
                            last_ledger_entry_id = %s, updated_at = now()
                        WHERE account_id = %s
                        """,
                        (
                            command.amount_minor,
                            command.amount_minor,
                            credit_entry_id,
                            command.destination_account_id,
                        ),
                    )
                    if command.reverses_transaction_id:
                        connection.execute(
                            "UPDATE transactions SET status = 'REVERSED' WHERE transaction_id = %s",
                            (command.reverses_transaction_id,),
                        )

                    payload = {
                        "transaction_id": str(transaction_id),
                        "source_account_id": str(command.source_account_id),
                        "destination_account_id": str(command.destination_account_id),
                        "amount_minor": command.amount_minor,
                        "currency": command.currency,
                        "transaction_type": command.transaction_type,
                        "initiated_by_user_id": str(command.actor.user_id),
                    }
                    connection.execute(
                        """
                        INSERT INTO outbox_events (
                            outbox_event_id, aggregate_type, aggregate_id,
                            event_type, event_version, payload
                        ) VALUES (%s,'transaction',%s,'payment.transfer_posted.v1',1,%s)
                        """,
                        (uuid4(), transaction_id, Jsonb(payload)),
                    )
                    audit.record(
                        connection,
                        actor_type="USER",
                        actor_id=str(command.actor.user_id),
                        action="LEDGER_POSTED",
                        resource_type="transaction",
                        resource_id=str(transaction_id),
                        request_id=command.request_id,
                        correlation_id=command.request_id,
                        metadata={
                            "amount_minor": command.amount_minor,
                            "currency": command.currency,
                            "type": command.transaction_type,
                        },
                    )
        except errors.UniqueViolation as error:
            existing = self.find_by_idempotency(
                command.actor.user_id, command.idempotency_key
            )
            if existing:
                return existing, True
            raise CONFLICT() from error

        return (
            {
                "transaction_id": transaction_id,
                "idempotency_key": command.idempotency_key,
                "request_id": command.request_id,
                "source_account_id": command.source_account_id,
                "destination_account_id": command.destination_account_id,
                "amount_minor": command.amount_minor,
                "currency": command.currency,
                "description": command.description,
                "transaction_type": command.transaction_type,
                "status": "POSTED",
                "created_at": posted_at,
                "posted_at": posted_at,
            },
            False,
        )

    def find_by_idempotency(
        self, user_id: UUID, idempotency_key: str
    ) -> dict[str, object] | None:
        with self.pool.connection() as connection:
            row = connection.execute(
                sql.SQL(
                    """
                SELECT {}
                FROM transactions
                WHERE initiated_by_user_id = %s AND idempotency_key = %s
                """
                ).format(TRANSACTION_PROJECTION),
                (user_id, idempotency_key),
            ).fetchone()
        return transaction_payload(row) if row else None

    def reconcile(self) -> list[dict[str, object]]:
        with self.pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT b.account_id,
                       b.current_balance_minor AS projected_balance_minor,
                       COALESCE(SUM(e.amount_minor), 0)::bigint
                           AS authoritative_balance_minor
                FROM account_balances b
                LEFT JOIN ledger_entries e ON e.account_id = b.account_id
                GROUP BY b.account_id, b.current_balance_minor
                ORDER BY b.account_id
                """
            ).fetchall()
        return [
            {
                **dict(row),
                "matches": row["projected_balance_minor"]
                == row["authoritative_balance_minor"],
            }
            for row in rows
        ]

    @staticmethod
    def _normalise(command: TransferCommand) -> TransferCommand:
        normalised = TransferCommand(
            request_id=command.request_id or uuid4(),
            idempotency_key=command.idempotency_key.strip(),
            actor=command.actor,
            source_account_id=command.source_account_id,
            destination_account_id=command.destination_account_id,
            amount_minor=command.amount_minor,
            currency=command.currency.strip().upper(),
            description=command.description.strip(),
            sca_challenge_id=command.sca_challenge_id,
            sca_code=command.sca_code,
            operator_override=command.operator_override,
            transaction_type=command.transaction_type or "TRANSFER",
            reverses_transaction_id=command.reverses_transaction_id,
        )
        if not normalised.idempotency_key or len(normalised.idempotency_key) > 128:
            raise validation("invalid idempotency key")
        if normalised.amount_minor <= 0:
            raise validation("amount_minor must be positive")
        if normalised.source_account_id == normalised.destination_account_id:
            raise validation("source and destination must differ")
        if normalised.currency != "GBP":
            raise validation("only GBP is supported in V1")
        if normalised.operator_override and normalised.actor.role != ROLE_BANK_ADMIN:
            raise FORBIDDEN()
        return normalised

    @staticmethod
    def _lock_accounts(connection, source_id: UUID, destination_id: UUID):
        # Available balance is the spendable projection.  It currently equals
        # current balance, but keeping the check here makes future holds safe.
        rows = connection.execute(
            """
            SELECT a.account_id, a.customer_id, a.account_type, a.currency,
                   a.status, a.allow_negative,
                   b.available_balance_minor AS balance_minor
            FROM bank_accounts a
            JOIN account_balances b USING (account_id)
            WHERE a.account_id = %s OR a.account_id = %s
            ORDER BY a.account_id
            FOR UPDATE OF a, b
            """,
            (source_id, destination_id),
        ).fetchall()
        if len(rows) != 2:
            raise NOT_FOUND()
        return {row["account_id"]: row for row in rows}

    @staticmethod
    def _validate_reversal(connection, command: TransferCommand) -> None:
        original = connection.execute(
            """
            SELECT status, transaction_type, source_account_id,
                   destination_account_id, amount_minor, currency
            FROM transactions
            WHERE transaction_id = %s
            FOR UPDATE
            """,
            (command.reverses_transaction_id,),
        ).fetchone()
        if not original:
            raise NOT_FOUND()
        if original["status"] != "POSTED" or original["transaction_type"] == "REVERSAL":
            raise CONFLICT()
        if (
            command.source_account_id != original["destination_account_id"]
            or command.destination_account_id != original["source_account_id"]
            or command.amount_minor != original["amount_minor"]
            or command.currency != original["currency"]
        ):
            raise CONFLICT()
