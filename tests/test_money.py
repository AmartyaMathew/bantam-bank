from bantam.money import balanced, format_minor


def test_balanced_double_entry_posting() -> None:
    assert balanced(-2500, 2500)
    assert not balanced(-2500, 2499)


def test_minor_unit_formatting() -> None:
    assert format_minor(250_000, "gbp") == "GBP 2,500.00"
    assert format_minor(-125, "GBP") == "GBP -1.25"
