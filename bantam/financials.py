"""Editable, versioned company financial profile used by risk quantification.

Bantam is a synthetic bank, so every figure here is a planning assumption rather
than an accounting fact.  The profile is kept deliberately small and explicit so
that a reviewer can see exactly which numbers reach a Monte Carlo simulation or
a model prompt, and so that a finance owner can replace them without touching
Python.  The repository ships a default profile; administrators append new
immutable versions through the API.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from bantam import audit
from bantam.errors import BantamError

if TYPE_CHECKING:
    from psycopg_pool import ConnectionPool


DEFAULT_PROFILE_PATH = Path(__file__).with_name("company_financials.json")

# Names a model may cite when it explains which financial inputs shaped an
# estimate.  Keeping the list explicit stops a model from inventing a balance
# sheet line that Bantam never supplied.
FINANCIAL_INPUT_NAMES: tuple[str, ...] = (
    "income.annual_revenue_gbp",
    "income.net_income_gbp",
    "income.operating_expenses_gbp",
    "balance_sheet.total_assets_gbp",
    "balance_sheet.customer_deposits_gbp",
    "balance_sheet.shareholder_equity_gbp",
    "balance_sheet.liquid_reserves_gbp",
    "operations.active_customers",
    "operations.daily_payment_volume_gbp",
    "operations.average_payment_gbp",
    "operations.employees",
    "risk_appetite.impact_tolerance_gbp",
    "risk_appetite.maximum_credible_single_loss_gbp",
    "risk_appetite.annual_security_budget_gbp",
    "risk_appetite.cost_of_capital_pct",
    "insurance.cyber_cover_gbp",
    "insurance.retention_gbp",
    "regulatory.maximum_penalty_pct_of_revenue",
    "regulatory.notification_window_hours",
)

_MONEY = Field(ge=0, le=1_000_000_000_000)


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class IncomeStatement(_Section):
    annual_revenue_gbp: float = _MONEY
    net_income_gbp: float = Field(ge=-1_000_000_000_000, le=1_000_000_000_000)
    operating_expenses_gbp: float = _MONEY


class BalanceSheet(_Section):
    total_assets_gbp: float = _MONEY
    customer_deposits_gbp: float = _MONEY
    shareholder_equity_gbp: float = _MONEY
    liquid_reserves_gbp: float = _MONEY


class OperatingProfile(_Section):
    active_customers: int = Field(ge=0, le=1_000_000_000)
    daily_payment_volume_gbp: float = _MONEY
    average_payment_gbp: float = _MONEY
    employees: int = Field(ge=0, le=1_000_000)


class RiskAppetite(_Section):
    impact_tolerance_gbp: float = Field(gt=0, le=1_000_000_000_000)
    maximum_credible_single_loss_gbp: float = Field(gt=0, le=1_000_000_000_000)
    annual_security_budget_gbp: float = _MONEY
    cost_of_capital_pct: float = Field(ge=0, le=100)


class InsuranceProgramme(_Section):
    cyber_cover_gbp: float = _MONEY
    retention_gbp: float = _MONEY


class RegulatoryContext(_Section):
    regime: str = Field(min_length=2, max_length=200)
    maximum_penalty_pct_of_revenue: float = Field(ge=0, le=100)
    notification_window_hours: int = Field(ge=1, le=8_760)


class CompanyFinancialProfile(BaseModel):
    """A reviewed set of planning figures for one synthetic reporting year."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: Literal["1.0"]
    legal_entity: str = Field(min_length=2, max_length=200)
    reporting_currency: Literal["GBP"]
    fiscal_year: int = Field(ge=2000, le=2100)
    statement_of_scope: str = Field(min_length=20, max_length=1_000)
    income: IncomeStatement
    balance_sheet: BalanceSheet
    operations: OperatingProfile
    risk_appetite: RiskAppetite
    insurance: InsuranceProgramme
    regulatory: RegulatoryContext
    notes: list[str] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def _coherent(self) -> "CompanyFinancialProfile":
        appetite = self.risk_appetite
        if appetite.impact_tolerance_gbp > appetite.maximum_credible_single_loss_gbp:
            raise ValueError(
                "impact tolerance cannot exceed the maximum credible single loss"
            )
        if self.insurance.retention_gbp > self.insurance.cyber_cover_gbp:
            raise ValueError("insurance retention cannot exceed the cyber cover limit")
        if (
            self.balance_sheet.shareholder_equity_gbp
            > self.balance_sheet.total_assets_gbp
        ):
            raise ValueError("shareholder equity cannot exceed total assets")
        for note in self.notes:
            if not 4 <= len(note) <= 400:
                raise ValueError("each note must be 4-400 characters")
        return self


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def profile_digest(profile: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(profile).encode("utf-8")).hexdigest()


def parse_profile(value: Any) -> dict[str, Any]:
    """Validate an untrusted profile document and return its canonical form."""

    try:
        return CompanyFinancialProfile.model_validate(value).model_dump()
    except ValidationError as error:
        first = error.errors()[0]
        location = ".".join(str(part) for part in first["loc"]) or "profile"
        raise BantamError(
            "INVALID_FINANCIAL_PROFILE",
            f"{location}: {first['msg']}",
            422,
        ) from error


def load_default_profile(path: Path = DEFAULT_PROFILE_PATH) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BantamError(
            "FINANCIAL_PROFILE_UNAVAILABLE",
            "the default company financial profile could not be read",
            500,
        ) from error
    return parse_profile(document)


def financial_inputs(profile: dict[str, Any]) -> dict[str, float]:
    """Flatten the profile to the exact named values a model may cite."""

    flattened: dict[str, float] = {}
    for name in FINANCIAL_INPUT_NAMES:
        section, _, field = name.partition(".")
        value = profile.get(section, {}).get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            flattened[name] = float(value)
    return flattened


class CompanyFinancialsService:
    """Serve the current profile and append reviewed, audited new versions."""

    def __init__(
        self,
        pool: "ConnectionPool",
        *,
        default_profile_path: Path = DEFAULT_PROFILE_PATH,
    ) -> None:
        self.pool = pool
        self.default_profile = load_default_profile(default_profile_path)

    def current(self) -> dict[str, Any]:
        with self.pool.connection() as connection:
            row = connection.execute(
                """
                SELECT profile_id, version, profile, profile_digest, change_note,
                       created_by, created_at
                FROM company_financial_profiles
                ORDER BY version DESC
                LIMIT 1
                """
            ).fetchone()
        if row is None:
            return {
                "profile_id": None,
                "version": 0,
                "source": "REPOSITORY_DEFAULT",
                "profile": self.default_profile,
                "profile_digest": profile_digest(self.default_profile),
                "change_note": "Shipped default assumptions; no reviewed version saved yet.",
                "created_by": None,
                "created_at": None,
                "financial_inputs": financial_inputs(self.default_profile),
            }
        record = dict(row)
        return {
            **record,
            "source": "REVIEWED_VERSION",
            "financial_inputs": financial_inputs(record["profile"]),
        }

    def overview(self) -> dict[str, Any]:
        current = self.current()
        with self.pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT profile_id, version, profile_digest, change_note,
                       created_by, created_at
                FROM company_financial_profiles
                ORDER BY version DESC
                LIMIT 25
                """
            ).fetchall()
        return {
            "current": current,
            "history": [dict(row) for row in rows],
            "repository_default": self.default_profile,
            "input_names": list(FINANCIAL_INPUT_NAMES),
        }

    def update(
        self,
        request: dict[str, Any],
        *,
        created_by: UUID,
        audit_fields: dict[str, object],
    ) -> dict[str, Any]:
        profile = parse_profile(request.get("profile"))
        note = str(request.get("change_note", "")).strip()[:500]
        digest = profile_digest(profile)
        profile_id = uuid4()
        with self.pool.connection() as connection:
            with connection.transaction():
                row = connection.execute(
                    """
                    INSERT INTO company_financial_profiles (
                        profile_id, version, profile, profile_digest,
                        change_note, created_by
                    )
                    SELECT %s,
                           COALESCE(MAX(version), 0) + 1,
                           %s, %s, %s, %s
                    FROM company_financial_profiles
                    RETURNING profile_id, version, profile, profile_digest,
                              change_note, created_by, created_at
                    """,
                    (profile_id, Jsonb(profile), digest, note, created_by),
                ).fetchone()
                audit.record(
                    connection,
                    **{
                        **audit_fields,
                        "action": "COMPANY_FINANCIALS_UPDATED",
                        "resource_type": "company_financial_profile",
                        "resource_id": str(profile_id),
                        "metadata": {
                            "version": row["version"],
                            "profile_digest": digest,
                            "fiscal_year": profile["fiscal_year"],
                            "impact_tolerance_gbp": profile["risk_appetite"][
                                "impact_tolerance_gbp"
                            ],
                        },
                    },
                )
        record = dict(row)
        return {
            **record,
            "source": "REVIEWED_VERSION",
            "financial_inputs": financial_inputs(record["profile"]),
        }
