"""Stable domain errors translated to non-sensitive HTTP responses at the edge."""

from __future__ import annotations


class BantamError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def NOT_FOUND() -> BantamError:
    return BantamError("NOT_FOUND", "resource was not found", 404)


def FORBIDDEN() -> BantamError:
    return BantamError("FORBIDDEN", "the action is not permitted", 403)


def CONFLICT() -> BantamError:
    return BantamError("CONFLICT", "the action conflicts with current state", 409)


def INSUFFICIENT_FUNDS() -> BantamError:
    return BantamError(
        "INSUFFICIENT_FUNDS", "the source account has insufficient funds"
    )


def ACCOUNT_FROZEN() -> BantamError:
    return BantamError("ACCOUNT_FROZEN", "one of the accounts is not active")


def KYC_NOT_VERIFIED() -> BantamError:
    return BantamError("KYC_NOT_VERIFIED", "KYC verification is required")


def SCA_REQUIRED() -> BantamError:
    return BantamError("SCA_REQUIRED", "a transaction-bound SCA challenge is required")


def SCA_FAILED() -> BantamError:
    return BantamError("SCA_FAILED", "the SCA challenge is invalid or expired")


def CURRENCY_MISMATCH() -> BantamError:
    return BantamError("CURRENCY_MISMATCH", "account currencies do not match")


def validation(message: str, code: str = "VALIDATION_FAILED") -> BantamError:
    return BantamError(code, message)
