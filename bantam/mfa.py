"""Passkey and authenticator-app MFA ceremonies.

Password verification and factor verification are deliberately separate.  A
short-lived, single-use database transaction connects the two steps without
issuing a partially authenticated session.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from psycopg import errors
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from bantam.domain import ROLE_ASPIS_ADMIN, ROLE_BANK_ADMIN


MFA_REQUIRED_ROLES = frozenset({ROLE_BANK_ADMIN, ROLE_ASPIS_ADMIN})
MFA_METHOD_PASSKEY = "passkey"
MFA_METHOD_TOTP = "totp"
TOTP_CODE = re.compile(r"^\d{6}$")
MAX_ATTEMPTS = 5


class MfaFailure(Exception):
    """A bounded, user-safe MFA error."""

    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class MfaCompletion:
    user_id: UUID
    customer_id: UUID | None
    role: str
    method: str
    enrolled: bool


class MfaService:
    """Own MFA factor storage, challenge state, and cryptographic verification."""

    def __init__(
        self,
        pool,
        *,
        encryption_key: str | None,
        transaction_ttl: timedelta,
        rp_id: str | None,
        rp_name: str,
        allowed_origins: tuple[str, ...],
    ) -> None:
        if not encryption_key:
            raise ValueError("MFA_ENCRYPTION_KEY is required by the API")
        try:
            self._fernet = Fernet(encryption_key.encode("ascii"))
        except (UnicodeEncodeError, ValueError) as error:
            raise ValueError("MFA_ENCRYPTION_KEY must be a Fernet key") from error
        self.pool = pool
        self.transaction_ttl = transaction_ttl
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.allowed_origins = allowed_origins

    @property
    def passkeys_enabled(self) -> bool:
        return bool(self.rp_id and self.allowed_origins)

    @staticmethod
    def role_requires_mfa(role: str) -> bool:
        return role in MFA_REQUIRED_ROLES

    def factor_methods(self, connection, user_id: UUID) -> tuple[str, ...]:
        passkey = connection.execute(
            """
            SELECT EXISTS (
                SELECT 1 FROM webauthn_credentials
                WHERE user_id = %s AND revoked_at IS NULL
            ) AS present
            """,
            (user_id,),
        ).fetchone()["present"]
        totp = connection.execute(
            """
            SELECT EXISTS (
                SELECT 1 FROM totp_credentials
                WHERE user_id = %s AND revoked_at IS NULL
            ) AS present
            """,
            (user_id,),
        ).fetchone()["present"]
        methods: list[str] = []
        if passkey and self.passkeys_enabled:
            methods.append(MFA_METHOD_PASSKEY)
        if totp:
            methods.append(MFA_METHOD_TOTP)
        if passkey and not self.passkeys_enabled and not totp:
            raise MfaFailure(
                "PASSKEY_CONFIGURATION_REQUIRED",
                "This account requires its configured passkey origin.",
                503,
            )
        return tuple(methods)

    def begin_login(self, connection, user: dict[str, Any]) -> dict[str, object] | None:
        methods = self.factor_methods(connection, user["user_id"])
        if not methods:
            if self.role_requires_mfa(user["role"]):
                return self._new_choice_transaction(
                    connection,
                    user_id=user["user_id"],
                    status="mfa_enrollment_required",
                )
            return None

        options: dict[str, object] | None = None
        challenge: bytes | None = None
        if MFA_METHOD_PASSKEY in methods:
            options, challenge = self._authentication_options(
                connection, user["user_id"]
            )
        transaction_id, expires_at = self._insert_transaction(
            connection,
            user_id=user["user_id"],
            purpose="LOGIN",
            challenge=challenge,
        )
        return {
            "status": "mfa_required",
            "transaction_id": transaction_id,
            "methods": list(methods),
            "passkey_options": options,
            "expires_at": expires_at,
        }

    def begin_authenticated_enrollment(
        self,
        connection,
        *,
        user_id: UUID,
        source_jti: UUID,
        source_expires_at: datetime,
    ) -> UUID:
        transaction_id, _ = self._insert_transaction(
            connection,
            user_id=user_id,
            purpose="ENROLL_CHOICE",
            source_jti=source_jti,
            source_expires_at=source_expires_at,
        )
        return transaction_id

    def _new_choice_transaction(
        self,
        connection,
        *,
        user_id: UUID,
        status: str,
    ) -> dict[str, object]:
        transaction_id, expires_at = self._insert_transaction(
            connection,
            user_id=user_id,
            purpose="ENROLL_CHOICE",
        )
        methods = [MFA_METHOD_TOTP]
        if self.passkeys_enabled:
            methods.insert(0, MFA_METHOD_PASSKEY)
        return {
            "status": status,
            "transaction_id": transaction_id,
            "methods": methods,
            "passkey_options": None,
            "expires_at": expires_at,
        }

    def _insert_transaction(
        self,
        connection,
        *,
        user_id: UUID,
        purpose: str,
        challenge: bytes | None = None,
        source_jti: UUID | None = None,
        source_expires_at: datetime | None = None,
    ) -> tuple[UUID, datetime]:
        now = datetime.now(UTC)
        expires_at = now + self.transaction_ttl
        transaction_id = uuid4()
        connection.execute(
            """
            DELETE FROM mfa_transactions
            WHERE user_id = %s
              AND (expires_at <= now() OR consumed_at IS NOT NULL)
            """,
            (user_id,),
        )
        connection.execute(
            """
            INSERT INTO mfa_transactions (
                transaction_id, user_id, purpose, challenge, source_jti,
                source_expires_at, expires_at
            ) VALUES (%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                transaction_id,
                user_id,
                purpose,
                challenge,
                source_jti,
                source_expires_at,
                expires_at,
            ),
        )
        return transaction_id, expires_at

    def prepare_enrollment(
        self,
        connection,
        *,
        transaction_id: UUID,
        method: str,
        label: str,
    ) -> dict[str, object]:
        method = method.strip().lower()
        if method not in {MFA_METHOD_PASSKEY, MFA_METHOD_TOTP}:
            raise MfaFailure(
                "INVALID_MFA_METHOD",
                "Choose a passkey or authenticator-app code.",
                422,
            )
        label = label.strip() or (
            "Passkey" if method == MFA_METHOD_PASSKEY else "Authenticator app"
        )
        if len(label) > 80:
            raise MfaFailure("INVALID_MFA_LABEL", "MFA label is too long.", 422)

        failure: MfaFailure | None = None
        result: dict[str, object] | None = None
        with connection.transaction():
            transaction = self._transaction_for_update(connection, transaction_id)
            if transaction["purpose"] != "ENROLL_CHOICE":
                failure = MfaFailure(
                    "INVALID_MFA_TRANSACTION",
                    "This MFA setup request is no longer available.",
                    409,
                )
            elif method == MFA_METHOD_PASSKEY:
                if not self.passkeys_enabled:
                    failure = MfaFailure(
                        "PASSKEYS_NOT_CONFIGURED",
                        "Passkeys are not configured for this hostname.",
                        503,
                    )
                else:
                    options, challenge = self._registration_options(
                        connection,
                        transaction["user_id"],
                        transaction["email"],
                    )
                    connection.execute(
                        """
                        UPDATE mfa_transactions
                        SET purpose = 'ENROLL_PASSKEY', challenge = %s,
                            factor_label = %s
                        WHERE transaction_id = %s
                        """,
                        (challenge, label, transaction_id),
                    )
                    result = {
                        "status": "mfa_enrollment_setup",
                        "transaction_id": transaction_id,
                        "method": method,
                        "passkey_options": options,
                        "expires_at": transaction["expires_at"],
                    }
            else:
                existing = connection.execute(
                    """
                    SELECT 1 FROM totp_credentials
                    WHERE user_id = %s AND revoked_at IS NULL
                    """,
                    (transaction["user_id"],),
                ).fetchone()
                if existing:
                    failure = MfaFailure(
                        "TOTP_ALREADY_ENROLLED",
                        "Remove the existing authenticator app before replacing it.",
                        409,
                    )
                else:
                    secret = pyotp.random_base32()
                    encrypted = self._fernet.encrypt(secret.encode("ascii"))
                    uri = pyotp.TOTP(secret).provisioning_uri(
                        name=transaction["email"],
                        issuer_name=self.rp_name,
                    )
                    connection.execute(
                        """
                        UPDATE mfa_transactions
                        SET purpose = 'ENROLL_TOTP', pending_secret = %s,
                            factor_label = %s
                        WHERE transaction_id = %s
                        """,
                        (encrypted, label, transaction_id),
                    )
                    result = {
                        "status": "mfa_enrollment_setup",
                        "transaction_id": transaction_id,
                        "method": method,
                        "totp_secret": secret,
                        "totp_uri": uri,
                        "expires_at": transaction["expires_at"],
                    }
        if failure:
            raise failure
        if result is None:  # pragma: no cover - defensive invariant
            raise MfaFailure("MFA_FAILED", "MFA setup could not be started.", 500)
        return result

    def complete_passkey(
        self,
        connection,
        *,
        transaction_id: UUID,
        credential: dict[str, object],
    ) -> MfaCompletion:
        failure: MfaFailure | None = None
        completion: MfaCompletion | None = None
        try:
            raw_id = base64url_to_bytes(str(credential["rawId"]))
        except (KeyError, TypeError, ValueError) as error:
            raise MfaFailure(
                "INVALID_PASSKEY_RESPONSE",
                "The passkey response was invalid.",
                401,
            ) from error

        try:
            with connection.transaction():
                transaction = self._transaction_for_update(connection, transaction_id)
                if transaction["purpose"] == "LOGIN":
                    stored = connection.execute(
                        """
                        SELECT credential_id, public_key, sign_count
                        FROM webauthn_credentials
                        WHERE user_id = %s AND credential_id = %s
                          AND revoked_at IS NULL
                        FOR UPDATE
                        """,
                        (transaction["user_id"], raw_id),
                    ).fetchone()
                    if not stored:
                        failure = self._record_failure(
                            connection,
                            transaction_id,
                            "The passkey could not be verified.",
                        )
                    else:
                        try:
                            verified = verify_authentication_response(
                                credential=credential,
                                expected_challenge=bytes(transaction["challenge"]),
                                expected_rp_id=self.rp_id or "",
                                expected_origin=list(self.allowed_origins),
                                credential_public_key=bytes(stored["public_key"]),
                                credential_current_sign_count=stored["sign_count"],
                                require_user_verification=True,
                            )
                        except (
                            InvalidAuthenticationResponse,
                            KeyError,
                            TypeError,
                            ValueError,
                        ):
                            failure = self._record_failure(
                                connection,
                                transaction_id,
                                "The passkey could not be verified.",
                            )
                        else:
                            connection.execute(
                                """
                                UPDATE webauthn_credentials
                                SET sign_count = %s, last_used_at = now(),
                                    backed_up = %s
                                WHERE user_id = %s AND credential_id = %s
                                """,
                                (
                                    verified.new_sign_count,
                                    verified.credential_backed_up,
                                    transaction["user_id"],
                                    raw_id,
                                ),
                            )
                elif transaction["purpose"] == "ENROLL_PASSKEY":
                    try:
                        verified = verify_registration_response(
                            credential=credential,
                            expected_challenge=bytes(transaction["challenge"]),
                            expected_rp_id=self.rp_id or "",
                            expected_origin=list(self.allowed_origins),
                            require_user_verification=True,
                        )
                    except (
                        InvalidRegistrationResponse,
                        KeyError,
                        TypeError,
                        ValueError,
                    ):
                        failure = self._record_failure(
                            connection,
                            transaction_id,
                            "The passkey could not be registered.",
                        )
                    else:
                        duplicate = connection.execute(
                            """
                            SELECT 1 FROM webauthn_credentials
                            WHERE credential_id = %s
                            """,
                            (verified.credential_id,),
                        ).fetchone()
                        if duplicate:
                            failure = self._record_failure(
                                connection,
                                transaction_id,
                                "That passkey is already registered.",
                            )
                        else:
                            response = credential.get("response")
                            transports = (
                                response.get("transports", [])
                                if isinstance(response, dict)
                                else []
                            )
                            safe_transports = sorted(
                                {
                                    str(item)
                                    for item in transports
                                    if str(item)
                                    in {
                                        "ble",
                                        "cable",
                                        "hybrid",
                                        "internal",
                                        "nfc",
                                        "smart-card",
                                        "usb",
                                    }
                                }
                            )
                            connection.execute(
                                """
                                INSERT INTO webauthn_credentials (
                                    webauthn_credential_id, user_id, credential_id,
                                    public_key, sign_count, transports, device_type,
                                    backed_up, label
                                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                                """,
                                (
                                    uuid4(),
                                    transaction["user_id"],
                                    verified.credential_id,
                                    verified.credential_public_key,
                                    verified.sign_count,
                                    safe_transports,
                                    verified.credential_device_type.value,
                                    verified.credential_backed_up,
                                    transaction["factor_label"],
                                ),
                            )
                else:
                    failure = MfaFailure(
                        "INVALID_MFA_TRANSACTION",
                        "This MFA request cannot accept a passkey.",
                        409,
                    )

                if not failure:
                    completion = self._consume(
                        connection,
                        transaction,
                        MFA_METHOD_PASSKEY,
                    )
        except errors.UniqueViolation as error:
            raise MfaFailure(
                "PASSKEY_ALREADY_ENROLLED",
                "That passkey is already registered.",
                409,
            ) from error
        if failure:
            raise failure
        if completion is None:  # pragma: no cover - defensive invariant
            raise MfaFailure("MFA_FAILED", "The passkey could not be verified.", 401)
        return completion

    def complete_totp(
        self,
        connection,
        *,
        transaction_id: UUID,
        code: str,
    ) -> MfaCompletion:
        if not TOTP_CODE.fullmatch(code):
            raise MfaFailure(
                "INVALID_OTP",
                "Enter the six-digit code from your authenticator app.",
                401,
            )

        failure: MfaFailure | None = None
        completion: MfaCompletion | None = None
        with connection.transaction():
            transaction = self._transaction_for_update(connection, transaction_id)
            stored = None
            encrypted = transaction["pending_secret"]
            last_used_step = -1
            if transaction["purpose"] == "LOGIN":
                stored = connection.execute(
                    """
                    SELECT encrypted_secret, last_used_step
                    FROM totp_credentials
                    WHERE user_id = %s AND revoked_at IS NULL
                    FOR UPDATE
                    """,
                    (transaction["user_id"],),
                ).fetchone()
                if stored:
                    encrypted = stored["encrypted_secret"]
                    last_used_step = stored["last_used_step"]
            elif transaction["purpose"] != "ENROLL_TOTP":
                failure = MfaFailure(
                    "INVALID_MFA_TRANSACTION",
                    "This MFA request cannot accept an authenticator code.",
                    409,
                )

            if not failure and not encrypted:
                failure = self._record_failure(
                    connection,
                    transaction_id,
                    "The authenticator code could not be verified.",
                )
            if not failure:
                try:
                    secret = self._fernet.decrypt(bytes(encrypted)).decode("ascii")
                except (InvalidToken, UnicodeDecodeError):
                    failure = MfaFailure(
                        "MFA_CONFIGURATION_ERROR",
                        "The authenticator could not be verified.",
                        503,
                    )
                else:
                    matched_step = self._matching_totp_step(secret, code)
                    if matched_step is None or matched_step <= last_used_step:
                        failure = self._record_failure(
                            connection,
                            transaction_id,
                            "The authenticator code is invalid or was already used.",
                        )
                    elif transaction["purpose"] == "LOGIN":
                        connection.execute(
                            """
                            UPDATE totp_credentials
                            SET last_used_step = %s, last_used_at = now()
                            WHERE user_id = %s AND revoked_at IS NULL
                            """,
                            (matched_step, transaction["user_id"]),
                        )
                    else:
                        connection.execute(
                            """
                            INSERT INTO totp_credentials (
                                user_id, encrypted_secret, label, last_used_step,
                                confirmed_at, last_used_at, revoked_at
                            ) VALUES (%s,%s,%s,%s,now(),NULL,NULL)
                            ON CONFLICT (user_id) DO UPDATE SET
                                encrypted_secret = EXCLUDED.encrypted_secret,
                                label = EXCLUDED.label,
                                last_used_step = EXCLUDED.last_used_step,
                                confirmed_at = now(),
                                last_used_at = NULL,
                                revoked_at = NULL
                            """,
                            (
                                transaction["user_id"],
                                encrypted,
                                transaction["factor_label"],
                                matched_step,
                            ),
                        )
            if not failure:
                completion = self._consume(connection, transaction, MFA_METHOD_TOTP)

        if failure:
            raise failure
        if completion is None:  # pragma: no cover - defensive invariant
            raise MfaFailure(
                "MFA_FAILED",
                "The authenticator code could not be verified.",
                401,
            )
        return completion

    def _matching_totp_step(self, secret: str, code: str) -> int | None:
        totp = pyotp.TOTP(secret)
        now = int(time.time())
        for offset in (0, -1, 1):
            candidate_time = now + offset * totp.interval
            candidate = totp.at(candidate_time)
            if secrets.compare_digest(candidate, code):
                moment = datetime.fromtimestamp(candidate_time, UTC)
                return int(totp.timecode(moment))
        return None

    def _transaction_for_update(self, connection, transaction_id: UUID):
        transaction = connection.execute(
            """
            SELECT t.transaction_id, t.user_id, t.purpose, t.challenge,
                   t.pending_secret, t.factor_label, t.source_jti,
                   t.source_expires_at, t.expires_at, t.attempts, u.email
            FROM mfa_transactions t
            JOIN user_accounts u ON u.user_id = t.user_id
            WHERE t.transaction_id = %s
              AND t.expires_at > now()
              AND t.consumed_at IS NULL
              AND t.attempts < %s
              AND u.status = 'ACTIVE'
            FOR UPDATE OF t
            """,
            (transaction_id, MAX_ATTEMPTS),
        ).fetchone()
        if not transaction:
            raise MfaFailure(
                "INVALID_MFA_TRANSACTION",
                "This MFA request expired or was already used.",
                401,
            )
        return transaction

    def _record_failure(
        self,
        connection,
        transaction_id: UUID,
        message: str,
    ) -> MfaFailure:
        connection.execute(
            """
            UPDATE mfa_transactions
            SET attempts = attempts + 1
            WHERE transaction_id = %s
            """,
            (transaction_id,),
        )
        return MfaFailure("MFA_VERIFICATION_FAILED", message, 401)

    def _consume(
        self,
        connection,
        transaction,
        method: str,
    ) -> MfaCompletion:
        connection.execute(
            """
            UPDATE mfa_transactions
            SET consumed_at = now()
            WHERE transaction_id = %s
            """,
            (transaction["transaction_id"],),
        )
        connection.execute(
            "UPDATE user_accounts SET mfa_enabled = true WHERE user_id = %s",
            (transaction["user_id"],),
        )
        if transaction["source_jti"] and transaction["source_expires_at"]:
            connection.execute(
                """
                INSERT INTO session_revocations (jti, user_id, expires_at)
                VALUES (%s,%s,%s)
                ON CONFLICT (jti) DO NOTHING
                """,
                (
                    transaction["source_jti"],
                    transaction["user_id"],
                    transaction["source_expires_at"],
                ),
            )
        user = connection.execute(
            """
            SELECT user_id, customer_id, role
            FROM user_accounts
            WHERE user_id = %s AND status = 'ACTIVE'
            """,
            (transaction["user_id"],),
        ).fetchone()
        if not user:
            raise MfaFailure(
                "UNAUTHENTICATED",
                "The user account is no longer active.",
                401,
            )
        return MfaCompletion(
            user_id=user["user_id"],
            customer_id=user["customer_id"],
            role=user["role"],
            method=method,
            enrolled=transaction["purpose"].startswith("ENROLL_"),
        )

    def _registration_options(
        self,
        connection,
        user_id: UUID,
        email: str,
    ) -> tuple[dict[str, object], bytes]:
        credentials = connection.execute(
            """
            SELECT credential_id FROM webauthn_credentials
            WHERE user_id = %s AND revoked_at IS NULL
            """,
            (user_id,),
        ).fetchall()
        options = generate_registration_options(
            rp_id=self.rp_id or "",
            rp_name=self.rp_name,
            user_id=user_id.bytes,
            user_name=email,
            user_display_name=email,
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=bytes(row["credential_id"]))
                for row in credentials
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
        return json.loads(options_to_json(options)), options.challenge

    def _authentication_options(
        self,
        connection,
        user_id: UUID,
    ) -> tuple[dict[str, object], bytes]:
        credentials = connection.execute(
            """
            SELECT credential_id FROM webauthn_credentials
            WHERE user_id = %s AND revoked_at IS NULL
            """,
            (user_id,),
        ).fetchall()
        options = generate_authentication_options(
            rp_id=self.rp_id or "",
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=bytes(row["credential_id"]))
                for row in credentials
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return json.loads(options_to_json(options)), options.challenge

    def describe(self, connection, user_id: UUID, role: str) -> dict[str, object]:
        passkeys = connection.execute(
            """
            SELECT webauthn_credential_id, label, device_type, backed_up,
                   created_at, last_used_at
            FROM webauthn_credentials
            WHERE user_id = %s AND revoked_at IS NULL
            ORDER BY created_at
            """,
            (user_id,),
        ).fetchall()
        totp = connection.execute(
            """
            SELECT label, confirmed_at, last_used_at
            FROM totp_credentials
            WHERE user_id = %s AND revoked_at IS NULL
            """,
            (user_id,),
        ).fetchone()
        return {
            "required": self.role_requires_mfa(role),
            "enabled": bool(passkeys or totp),
            "passkeys_available": self.passkeys_enabled,
            "passkeys": [dict(row) for row in passkeys],
            "totp": dict(totp) if totp else None,
        }

    def remove_passkey(
        self,
        connection,
        *,
        user_id: UUID,
        role: str,
        credential_id: UUID,
    ) -> None:
        with connection.transaction():
            present = connection.execute(
                """
                SELECT 1 FROM webauthn_credentials
                WHERE webauthn_credential_id = %s AND user_id = %s
                  AND revoked_at IS NULL
                FOR UPDATE
                """,
                (credential_id, user_id),
            ).fetchone()
            if not present:
                raise MfaFailure("NOT_FOUND", "Passkey was not found.", 404)
            self._guard_last_factor(
                connection,
                user_id=user_id,
                role=role,
                removing_passkey=credential_id,
            )
            connection.execute(
                """
                UPDATE webauthn_credentials SET revoked_at = now()
                WHERE webauthn_credential_id = %s AND user_id = %s
                """,
                (credential_id, user_id),
            )
            self._sync_enabled(connection, user_id)

    def remove_totp(self, connection, *, user_id: UUID, role: str) -> None:
        with connection.transaction():
            present = connection.execute(
                """
                SELECT 1 FROM totp_credentials
                WHERE user_id = %s AND revoked_at IS NULL
                FOR UPDATE
                """,
                (user_id,),
            ).fetchone()
            if not present:
                raise MfaFailure(
                    "NOT_FOUND",
                    "Authenticator-app factor was not found.",
                    404,
                )
            self._guard_last_factor(
                connection,
                user_id=user_id,
                role=role,
                removing_totp=True,
            )
            connection.execute(
                """
                UPDATE totp_credentials SET revoked_at = now()
                WHERE user_id = %s AND revoked_at IS NULL
                """,
                (user_id,),
            )
            self._sync_enabled(connection, user_id)

    def _guard_last_factor(
        self,
        connection,
        *,
        user_id: UUID,
        role: str,
        removing_passkey: UUID | None = None,
        removing_totp: bool = False,
    ) -> None:
        if not self.role_requires_mfa(role):
            return
        remaining_passkeys = connection.execute(
            """
            SELECT count(*) AS count
            FROM webauthn_credentials
            WHERE user_id = %s AND revoked_at IS NULL
              AND (%s::uuid IS NULL OR webauthn_credential_id <> %s::uuid)
            """,
            (user_id, removing_passkey, removing_passkey),
        ).fetchone()["count"]
        remaining_totp = connection.execute(
            """
            SELECT count(*) AS count
            FROM totp_credentials
            WHERE user_id = %s AND revoked_at IS NULL
              AND NOT %s
            """,
            (user_id, removing_totp),
        ).fetchone()["count"]
        if remaining_passkeys + remaining_totp == 0:
            raise MfaFailure(
                "MFA_FACTOR_REQUIRED",
                "Administrators must keep at least one MFA factor.",
                409,
            )

    @staticmethod
    def _sync_enabled(connection, user_id: UUID) -> None:
        connection.execute(
            """
            UPDATE user_accounts
            SET mfa_enabled = (
                EXISTS (
                    SELECT 1 FROM webauthn_credentials
                    WHERE user_id = %s AND revoked_at IS NULL
                )
                OR EXISTS (
                    SELECT 1 FROM totp_credentials
                    WHERE user_id = %s AND revoked_at IS NULL
                )
            )
            WHERE user_id = %s
            """,
            (user_id, user_id, user_id),
        )
