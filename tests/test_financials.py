"""Validation and grounding rules for the editable company financial profile."""

from __future__ import annotations

import copy

import pytest

from bantam.errors import BantamError
from bantam.financials import (
    FINANCIAL_INPUT_NAMES,
    financial_inputs,
    load_default_profile,
    parse_profile,
    profile_digest,
)


def test_repository_default_profile_is_valid_and_clearly_synthetic() -> None:
    profile = load_default_profile()
    assert profile["reporting_currency"] == "GBP"
    assert "synthetic" in profile["statement_of_scope"].casefold()
    assert (
        profile["risk_appetite"]["impact_tolerance_gbp"]
        <= profile["risk_appetite"]["maximum_credible_single_loss_gbp"]
    )


def test_every_declared_input_name_resolves_to_a_number() -> None:
    inputs = financial_inputs(load_default_profile())
    assert set(inputs) == set(FINANCIAL_INPUT_NAMES)
    assert all(isinstance(value, float) for value in inputs.values())


def test_digest_changes_when_any_figure_changes() -> None:
    profile = load_default_profile()
    changed = copy.deepcopy(profile)
    changed["income"]["annual_revenue_gbp"] += 1
    assert profile_digest(profile) != profile_digest(changed)


def test_tolerance_above_maximum_credible_loss_is_rejected() -> None:
    profile = load_default_profile()
    profile["risk_appetite"]["impact_tolerance_gbp"] = (
        profile["risk_appetite"]["maximum_credible_single_loss_gbp"] + 1
    )
    with pytest.raises(BantamError) as error:
        parse_profile(profile)
    assert error.value.code == "INVALID_FINANCIAL_PROFILE"


def test_retention_above_cover_is_rejected() -> None:
    profile = load_default_profile()
    profile["insurance"]["retention_gbp"] = profile["insurance"]["cyber_cover_gbp"] + 1
    with pytest.raises(BantamError):
        parse_profile(profile)


def test_unknown_field_is_rejected_rather_than_silently_stored() -> None:
    profile = load_default_profile()
    profile["shadow_budget_gbp"] = 1_000_000
    with pytest.raises(BantamError):
        parse_profile(profile)


def test_negative_revenue_is_rejected() -> None:
    profile = load_default_profile()
    profile["income"]["annual_revenue_gbp"] = -1
    with pytest.raises(BantamError):
        parse_profile(profile)
