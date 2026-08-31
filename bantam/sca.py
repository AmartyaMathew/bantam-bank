"""Transaction-bound strong customer authentication for high-value transfers.

An OTP is never stored directly.  Its HMAC binds the user, both accounts,
amount, challenge ID, and code; GBP is the only V1 currency, so changing any
money-movement input invalidates the challenge.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from psycopg import Connection
from psycopg_pool import ConnectionPool

from bantam.domain import Principal
from bantam.errors import FORBIDDEN, NOT_FOUND, SCA_FAILED, SCA_REQUIRED, validation


class SCAService:
    """Create and atomically consume one-time transfer challenges."""

    def __init__(
        self, secret: str, ttl: timedelta, threshold: int, demo_mode: bool
    ) -> None:
        self.secret = secret.encode()
        self.ttl = ttl
        self.threshold = threshold
        self.demo_mode = demo_mode

    def required(self, amount_minor: int) -> bool:
        return amount_minor >= self.threshold

    def create(
        self,
        pool: ConnectionPool,
        principal: Principal,
        source_account_id: UUID,
        destination_account_id: UUID,
        amount_minor: int,
    ) -> dict[str, object]:
        if principal.customer_id is None:
            raise FORBIDDEN()
        if amount_minor <= 0:
            raise validation("amount must be positive")
        if source_account_id == destination_account_id:
            raise validation("source and destination must differ")

        with pool.connection() as connection:
            owns_source = connection.execute(
                """
                SELECT EXISTS (
                    SELECT 1 FROM bank_accounts
                    WHERE account_id = %s AND customer_id = %s AND status = 'ACTIVE'
                ) AS value
                """,
                (source_account_id, principal.customer_id),
            ).fetchone()["value"]
            if not owns_source:
                raise FORBIDDEN()

            destination_active = connection.execute(
                """
                SELECT EXISTS (
                    SELECT 1 FROM bank_accounts
                    WHERE account_id = %s AND status = 'ACTIVE'
                ) AS value
                """,
                (destination_account_id,),
            ).fetchone()["value"]
            if not destination_active:
                raise NOT_FOUND()

            if not self.required(amount_minor):
                return {
                    "challenge_id": UUID(int=0),
                    "expires_at": datetime.min.replace(tzinfo=UTC),
                    "required": False,
                }

            challenge_id = uuid4()
            code = f"{secrets.randbelow(1_000_000):06d}"
            expires_at = datetime.now(UTC) + self.ttl
            code_hash = self._hash(
                challenge_id,
                principal.user_id,
                source_account_id,
                destination_account_id,
                amount_minor,
                code,
            )
            connection.execute(
                """
                INSERT INTO sca_challenges (
                    challenge_id, user_id, source_account_id,
                    destination_account_id, amount_minor, code_hash, expires_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    challenge_id,
                    principal.user_id,
                    source_account_id,
                    destination_account_id,
                    amount_minor,
                    code_hash,
                    expires_at,
                ),
            )

        challenge: dict[str, object] = {
            "challenge_id": challenge_id,
            "expires_at": expires_at,
            "required": True,
        }
        if self.demo_mode:
            challenge["demo_code"] = code
        return challenge

    def validate_and_consume(
        self,
        connection: Connection,
        principal: Principal,
        source_account_id: UUID,
        destination_account_id: UUID,
        amount_minor: int,
        challenge_id: UUID | None,
        code: str,
    ) -> None:
        if not self.required(amount_minor):
            return
        if (
            challenge_id is None
            or len(code) != 6
            or not code.isascii()
            or not code.isdigit()
        ):
            raise SCA_REQUIRED()

        challenge = connection.execute(
            """
            SELECT user_id, source_account_id, destination_account_id,
                   amount_minor, code_hash, status, expires_at
            FROM sca_challenges
            WHERE challenge_id = %s
            FOR UPDATE
            """,
            (challenge_id,),
        ).fetchone()
        if not challenge:
            raise SCA_FAILED()
        if (
            challenge["status"] != "PENDING"
            or datetime.now(UTC) > challenge["expires_at"]
        ):
            raise SCA_FAILED()
        if (
            challenge["user_id"] != principal.user_id
            or challenge["source_account_id"] != source_account_id
            or challenge["destination_account_id"] != destination_account_id
            or challenge["amount_minor"] != amount_minor
        ):
            raise SCA_FAILED()

        expected = self._hash(
            challenge_id,
            principal.user_id,
            source_account_id,
            destination_account_id,
            amount_minor,
            code,
        )
        if not hmac.compare_digest(expected, challenge["code_hash"]):
            raise SCA_FAILED()
        consumed = connection.execute(
            """
            UPDATE sca_challenges
            SET status = 'CONSUMED', consumed_at = now()
            WHERE challenge_id = %s AND status = 'PENDING'
            RETURNING challenge_id
            """,
            (challenge_id,),
        ).fetchone()
        if not consumed:
            # The row lock should make this unreachable, but the conditional
            # update is a second replay barrier if locking changes later.
            raise SCA_FAILED()

    def _hash(
        self,
        challenge_id: UUID,
        user_id: UUID,
        source_account_id: UUID,
        destination_account_id: UUID,
        amount_minor: int,
        code: str,
    ) -> str:
        bound_value = (
            f"{challenge_id}:{user_id}:{source_account_id}:"
            f"{destination_account_id}:{amount_minor}:{code}"
        )
        return hmac.new(self.secret, bound_value.encode(), hashlib.sha256).hexdigest()
