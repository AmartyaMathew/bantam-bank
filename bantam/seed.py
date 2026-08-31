"""Idempotent synthetic identities, accounts, and balanced opening postings."""

from __future__ import annotations

import hashlib
import logging
from uuid import UUID, uuid4

from psycopg_pool import ConnectionPool

from bantam import audit
from bantam.auth import hash_password
from bantam.domain import (
    ADMIN_PERMISSION_SCOPES,
    ROLE_ASPIS_ADMIN,
    ROLE_BANK_ADMIN,
    Principal,
    TransferCommand,
)
from bantam.ledger import LedgerService


LOGGER = logging.getLogger(__name__)
# This public credential belongs only to idempotently generated fake-money
# identities. Production startup disables seeding and demo mode.
DEMO_PASSWORD = "BantamDemo123!"  # nosec B105

ADMIN_USER_ID = UUID("10000000-0000-0000-0000-000000000001")
RISK_USER_ID = UUID("10000000-0000-0000-0000-000000000002")
AUDIT_USER_ID = UUID("10000000-0000-0000-0000-000000000003")
ALICE_USER_ID = UUID("10000000-0000-0000-0000-000000000004")
BOB_USER_ID = UUID("10000000-0000-0000-0000-000000000005")

ALICE_CUSTOMER_ID = UUID("20000000-0000-0000-0000-000000000001")
BOB_CUSTOMER_ID = UUID("20000000-0000-0000-0000-000000000002")

TREASURY_ACCOUNT_ID = UUID("30000000-0000-0000-0000-000000000001")
ALICE_ACCOUNT_ID = UUID("30000000-0000-0000-0000-000000000002")
BOB_ACCOUNT_ID = UUID("30000000-0000-0000-0000-000000000003")


def reference_hash(reference: str) -> str:
    return hashlib.sha256(reference.encode()).hexdigest()


def grant_bank_admin_permissions(
    connection,
    user_id: UUID,
    *,
    granted_by: UUID | None = None,
) -> None:
    for scope in ADMIN_PERMISSION_SCOPES:
        connection.execute(
            """
            INSERT INTO admin_permissions (user_id, scope, granted_by)
            VALUES (%s,%s,%s)
            ON CONFLICT DO NOTHING
            """,
            (user_id, scope, granted_by),
        )


def _bootstrap_administrator(
    pool: ConnectionPool,
    *,
    email: str,
    password: str,
    role: str,
    email_variable: str,
    disallowed_label: str,
    audit_actor_id: str,
    audit_action: str,
    log_label: str,
) -> UUID:
    """Create one immutable-role administrator without resetting credentials."""

    normalized_email = email.strip().lower()
    if not normalized_email or "@" not in normalized_email:
        raise ValueError(f"{email_variable} must be a valid email address")
    password_hash = hash_password(
        password,
        disallowed_values=(normalized_email, disallowed_label),
    )
    with pool.connection() as connection:
        with connection.transaction():
            existing = connection.execute(
                """
                SELECT user_id, role FROM user_accounts
                WHERE email = %s
                FOR UPDATE
                """,
                (normalized_email,),
            ).fetchone()
            if existing:
                if existing["role"] != role:
                    raise ValueError(
                        "bootstrap email belongs to a different account role"
                    )
                if role == ROLE_BANK_ADMIN:
                    grant_bank_admin_permissions(connection, existing["user_id"])
                return existing["user_id"]
            user_id = uuid4()
            connection.execute(
                """
                INSERT INTO user_accounts (
                    user_id, email, password_hash, role, customer_id,
                    mfa_enabled
                ) VALUES (%s,%s,%s,%s,NULL,false)
                """,
                (user_id, normalized_email, password_hash, role),
            )
            if role == ROLE_BANK_ADMIN:
                grant_bank_admin_permissions(connection, user_id)
            audit.record(
                connection,
                actor_type="SYSTEM",
                actor_id=audit_actor_id,
                action=audit_action,
                resource_type="user_account",
                resource_id=str(user_id),
                metadata={"role": role},
            )
    LOGGER.info(
        "%s ready",
        log_label,
        extra={"email": normalized_email, "user_id": str(user_id)},
    )
    return user_id


def bootstrap_aspis_admin(
    pool: ConnectionPool,
    *,
    email: str,
    password: str,
) -> UUID:
    """Idempotently create the narrow production Aspis administrator."""

    return _bootstrap_administrator(
        pool,
        email=email,
        password=password,
        role=ROLE_ASPIS_ADMIN,
        email_variable="ASPIS_ADMIN_BOOTSTRAP_EMAIL",
        disallowed_label="aspis admin",
        audit_actor_id="aspis-admin-bootstrap",
        audit_action="ASPIS_ADMIN_BOOTSTRAPPED",
        log_label="Aspis administrator",
    )


def bootstrap_bank_admin(
    pool: ConnectionPool,
    *,
    email: str,
    password: str,
) -> UUID:
    """Idempotently create the first production banking administrator."""

    return _bootstrap_administrator(
        pool,
        email=email,
        password=password,
        role=ROLE_BANK_ADMIN,
        email_variable="BANK_ADMIN_BOOTSTRAP_EMAIL",
        disallowed_label="bank admin",
        audit_actor_id="bank-admin-bootstrap",
        audit_action="BANK_ADMIN_BOOTSTRAPPED",
        log_label="Bank administrator",
    )


def seed(pool: ConnectionPool, ledger: LedgerService) -> None:
    password_hash = hash_password(DEMO_PASSWORD)
    with pool.connection() as connection:
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO customers (
                    customer_id, legal_name, date_of_birth, email, phone,
                    kyc_status, risk_rating, status
                ) VALUES
                    (%s,'Alice Morgan','1992-04-18','alice@bantam.local',
                     '+44 7700 900101','KYC_VERIFIED','LOW','ACTIVE'),
                    (%s,'Bob Chen','1988-11-03','bob@bantam.local',
                     '+44 7700 900102','KYC_VERIFIED','LOW','ACTIVE')
                ON CONFLICT DO NOTHING
                """,
                (ALICE_CUSTOMER_ID, BOB_CUSTOMER_ID),
            )
            connection.execute(
                """
                INSERT INTO user_accounts (
                    user_id, email, password_hash, role, customer_id, mfa_enabled
                ) VALUES
                    (%s,'admin@bantam.local',%s,'BANK_ADMIN',NULL,false),
                    (%s,'risk@bantam.local',%s,'RISK_ANALYST',NULL,false),
                    (%s,'auditor@bantam.local',%s,'COMPLIANCE_AUDITOR',NULL,false),
                    (%s,'alice@bantam.local',%s,'CUSTOMER',%s,false),
                    (%s,'bob@bantam.local',%s,'CUSTOMER',%s,false)
                ON CONFLICT DO NOTHING
                """,
                (
                    ADMIN_USER_ID,
                    password_hash,
                    RISK_USER_ID,
                    password_hash,
                    AUDIT_USER_ID,
                    password_hash,
                    ALICE_USER_ID,
                    password_hash,
                    ALICE_CUSTOMER_ID,
                    BOB_USER_ID,
                    password_hash,
                    BOB_CUSTOMER_ID,
                ),
            )
            grant_bank_admin_permissions(connection, ADMIN_USER_ID)
            connection.execute(
                """
                INSERT INTO bank_accounts (
                    account_id, customer_id, account_number_hash,
                    account_reference, account_type, currency, status,
                    allow_negative
                ) VALUES
                    (%s,NULL,%s,'XB-TREASURY','SYSTEM','GBP','ACTIVE',true),
                    (%s,%s,%s,'XB-ALICE-001','CURRENT','GBP','ACTIVE',false),
                    (%s,%s,%s,'XB-BOB-001','CURRENT','GBP','ACTIVE',false)
                ON CONFLICT DO NOTHING
                """,
                (
                    TREASURY_ACCOUNT_ID,
                    reference_hash("XB-TREASURY"),
                    ALICE_ACCOUNT_ID,
                    ALICE_CUSTOMER_ID,
                    reference_hash("XB-ALICE-001"),
                    BOB_ACCOUNT_ID,
                    BOB_CUSTOMER_ID,
                    reference_hash("XB-BOB-001"),
                ),
            )
            connection.execute(
                """
                INSERT INTO account_balances (
                    account_id, available_balance_minor,
                    current_balance_minor, currency
                ) VALUES (%s,0,0,'GBP'),(%s,0,0,'GBP'),(%s,0,0,'GBP')
                ON CONFLICT DO NOTHING
                """,
                (TREASURY_ACCOUNT_ID, ALICE_ACCOUNT_ID, BOB_ACCOUNT_ID),
            )

    admin = Principal(user_id=ADMIN_USER_ID, role=ROLE_BANK_ADMIN)
    for key, destination, amount in (
        ("seed-alice-opening-balance-v1", ALICE_ACCOUNT_ID, 250_000),
        ("seed-bob-opening-balance-v1", BOB_ACCOUNT_ID, 100_000),
    ):
        ledger.create_transfer(
            TransferCommand(
                request_id=uuid4(),
                idempotency_key=key,
                actor=admin,
                source_account_id=TREASURY_ACCOUNT_ID,
                destination_account_id=destination,
                amount_minor=amount,
                currency="GBP",
                description="Synthetic opening balance",
                operator_override=True,
                transaction_type="DEMO_DEPOSIT",
            )
        )

    LOGGER.info("Bantam demo data ready")
    # Credentials are documented for this synthetic environment; emitting a
    # password-shaped value to logs would normalize a dangerous production habit.
    LOGGER.info("admin", extra={"email": "admin@bantam.local"})
    LOGGER.info("risk analyst", extra={"email": "risk@bantam.local"})
    LOGGER.info("auditor", extra={"email": "auditor@bantam.local"})
    LOGGER.info(
        "customer",
        extra={"email": "alice@bantam.local", "account_id": str(ALICE_ACCOUNT_ID)},
    )
    LOGGER.info(
        "customer",
        extra={"email": "bob@bantam.local", "account_id": str(BOB_ACCOUNT_ID)},
    )
