"""Small immutable domain types and canonical role/state constants."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


ROLE_CUSTOMER = "CUSTOMER"
ROLE_BANK_ADMIN = "BANK_ADMIN"
ROLE_RISK_ANALYST = "RISK_ANALYST"
ROLE_COMPLIANCE_AUDITOR = "COMPLIANCE_AUDITOR"
ROLE_ASPIS_AUDITOR = "ASPIS_AUDITOR"
ROLE_ASPIS_ADMIN = "ASPIS_ADMIN"
ROLE_PENDING_APPROVAL = "PENDING_APPROVAL"
ROLE_SERVICE_ACCOUNT = "SERVICE_ACCOUNT"

ADMIN_PERMISSION_SCOPES = (
    "admin_users",
    "customers",
    "transactions",
    "risk",
    "audit",
    "asvs",
    "aspis_auditors",
    "reconciliation",
    "workflows",
    "attack_lab",
    "company_financials",
)

KYC_PENDING = "PENDING_KYC"
KYC_REVIEW = "PENDING_REVIEW"
KYC_VERIFIED = "KYC_VERIFIED"
KYC_REJECTED = "KYC_REJECTED"

ACCOUNT_ACTIVE = "ACTIVE"
ACCOUNT_FROZEN = "FROZEN"
ACCOUNT_CLOSED = "CLOSED"


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: UUID
    role: str
    customer_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class TransferCommand:
    request_id: UUID
    idempotency_key: str
    actor: Principal
    source_account_id: UUID
    destination_account_id: UUID
    amount_minor: int
    currency: str
    description: str = ""
    sca_challenge_id: UUID | None = None
    sca_code: str = ""
    operator_override: bool = False
    transaction_type: str = "TRANSFER"
    reverses_transaction_id: UUID | None = None
