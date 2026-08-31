"""Strict Pydantic request schemas with bounded fields and no extra keys."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterRequest(RequestModel):
    legal_name: str = Field(min_length=2, max_length=120)
    date_of_birth: str = Field(min_length=10, max_length=10)
    email: str = Field(min_length=3, max_length=254)
    phone: str = Field(default="", max_length=32)
    password: str = Field(min_length=14, max_length=128)


AdminPermissionScope = Literal[
    "admin_users",
    "customers",
    "transactions",
    "risk",
    "audit",
    "asvs",
    "aspis_auditors",
    "reconciliation",
    "workflows",
]


class AspisAuditorRegisterRequest(RequestModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=14, max_length=128)


class AdminUserCreateRequest(RequestModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=14, max_length=128)
    permissions: list[AdminPermissionScope] = Field(min_length=1, max_length=9)


class LoginRequest(RequestModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class MfaSetupRequest(RequestModel):
    transaction_id: UUID
    method: Literal["passkey", "totp"]
    label: str = Field(default="", max_length=80)


class MfaPasskeyRequest(RequestModel):
    transaction_id: UUID
    credential: dict[str, object]


class MfaTotpRequest(RequestModel):
    transaction_id: UUID
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class MfaEnrollmentRequest(RequestModel):
    password: str = Field(min_length=1, max_length=128)
    method: Literal["passkey", "totp"]
    label: str = Field(default="", max_length=80)


class AspisAuditorDecisionRequest(RequestModel):
    decision: Literal["APPROVE", "REJECT"]
    reason: str = Field(default="", max_length=500)


class OpenAccountRequest(RequestModel):
    currency: str = "GBP"


class SCAChallengeRequest(RequestModel):
    source_account_id: UUID
    destination_account_id: UUID
    amount_minor: int = Field(gt=0, le=100_000_000)


class TransferRequest(RequestModel):
    source_account_id: UUID
    destination_account_id: UUID
    amount_minor: int = Field(gt=0, le=100_000_000)
    currency: str = Field(min_length=3, max_length=3)
    description: str = Field(default="", max_length=140)
    sca_challenge_id: UUID | None = None
    sca_code: str = Field(default="", max_length=6, pattern=r"^\d{0,6}$")


class KYCDecisionRequest(RequestModel):
    decision: str = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=500)


class AccountStatusRequest(RequestModel):
    status: str = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=500)


class DemoDepositRequest(RequestModel):
    amount_minor: int = Field(gt=0, le=100_000_000)
    currency: str = Field(default="GBP", min_length=3, max_length=3)
    description: str = Field(default="", max_length=140)


class ReverseRequest(RequestModel):
    reason: str = Field(min_length=1, max_length=500)


class ManualRiskAlertRequest(RequestModel):
    transaction_id: UUID
    severity: str = Field(min_length=1, max_length=32)
    explanation: str = Field(min_length=1, max_length=1000)


class ReviewRiskAlertRequest(RequestModel):
    status: str = Field(min_length=1, max_length=32)
    note: str = Field(default="", max_length=1000)


class WorkflowDefinitionRequest(RequestModel):
    name: str = Field(min_length=3, max_length=100)
    description: str = Field(default="", max_length=500)
    actor_role: str = Field(min_length=3, max_length=40)
    node_ids: list[str] = Field(min_length=2, max_length=160)


class RepositoryGraphRequest(RequestModel):
    repository: str = Field(min_length=3, max_length=220)
    ref: str = Field(default="main", min_length=1, max_length=180)
    root_path: str = Field(default="", max_length=500)
    language: Literal["auto", "python", "terraform"] = "auto"
    send_to_mistral: bool = True


class RepositoryWorkflowDefinitionRequest(RequestModel):
    name: str = Field(min_length=3, max_length=100)
    description: str = Field(default="", max_length=500)
    actor_role: str = Field(min_length=3, max_length=40)
    node_ids: list[str] = Field(min_length=1, max_length=160)


class CompanyFinancialsRequest(RequestModel):
    profile: dict[str, object]
    change_note: str = Field(default="", max_length=500)


class AttackScenarioRequest(RequestModel):
    graph_source: Literal["BUILTIN", "REPOSITORY_SNAPSHOT"] = "BUILTIN"
    snapshot_id: UUID | None = None
    scenario_count: int = Field(default=3, ge=2, le=5)
    send_to_mistral: bool = True


class AttackSimulationRequest(RequestModel):
    scenario_id: str = Field(min_length=1, max_length=120)
    iterations: int = Field(default=10_000, ge=1_000, le=50_000)
    seed: int = Field(default=20_250_101, ge=0, le=4_294_967_295)
    remediation_plan_id: UUID | None = None
    remediation_ids: list[str] = Field(default_factory=list, max_length=10)
