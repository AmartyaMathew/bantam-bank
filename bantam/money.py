"""Integer-minor-unit checks and display formatting; floats never enter writes."""

from __future__ import annotations

from decimal import Decimal


def balanced(*entries: int) -> bool:
    return sum(entries) == 0


def format_minor(amount_minor: int, currency: str) -> str:
    amount = Decimal(amount_minor) / Decimal(100)
    return f"{currency.upper()} {amount:,.2f}"
