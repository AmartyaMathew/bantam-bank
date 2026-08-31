"""Fail-closed configuration loading for every Bantam process.

Configuration is part of the security boundary.  Values supplied by an
operator are therefore parsed strictly: a misspelled duration or boolean must
stop startup instead of silently selecting a more permissive default.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import re
from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit


_DURATION = re.compile(r"^(?P<value>\d+)(?P<unit>ms|s|m|h)$")
_ENVIRONMENTS = {"development", "test", "production"}
_DATABASE_CONNECTION_MODES = {"direct", "cloud_sql_proxy"}
_EVENT_BUSES = {"nats", "pubsub"}
_LOOPBACK_DATABASE_HOSTS = {"localhost", "127.0.0.1", "::1"}
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RP_ID = re.compile(
    r"^(?:localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$"
)
_DEVELOPMENT_MFA_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# These values have appeared in source, examples, or earlier versions.  They
# are safe only as local-development fixtures because an attacker can know them.
KNOWN_DEVELOPMENT_SECRETS = frozenset(
    {
        "local-development-jwt-secret-change-me",
        "local-development-sca-secret-change-me",
        "local-compose-jwt-secret-change-before-deploying",
        "local-compose-sca-secret-change-before-deploying",
        "local-compose-jwt-secret-for-development-only-2026",
        "local-compose-sca-secret-for-development-only-2026",
        "local-compose-claims-secret-for-development-only-2026",
        "replace-with-at-least-32-random-characters",
        "replace-with-a-separate-random-secret",
        "replace-with-a-third-independent-random-secret",
    }
)


def parse_duration(value: str, fallback: timedelta) -> timedelta:
    """Parse the compact duration syntax retained from Bantam's first version."""

    match = _DURATION.fullmatch(value.strip())
    if not match:
        return fallback
    amount = int(match.group("value"))
    unit = match.group("unit")
    if unit == "ms":
        return timedelta(milliseconds=amount)
    if unit == "s":
        return timedelta(seconds=amount)
    if unit == "m":
        return timedelta(minutes=amount)
    return timedelta(hours=amount)


def _duration(name: str, default: str) -> timedelta:
    raw = os.getenv(name, default).strip()
    parsed = parse_duration(raw, timedelta(seconds=-1))
    if parsed <= timedelta(seconds=0):
        raise ValueError(f"{name} must be a positive duration such as 15m")
    return parsed


def _integer(name: str, fallback: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return fallback
    try:
        return int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error


def _boolean(name: str, fallback: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return fallback
    normalised = value.strip().lower()
    if normalised in {"1", "true", "yes", "on"}:
        return True
    if normalised in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


def _csv(name: str) -> tuple[str, ...]:
    return tuple(
        item.strip() for item in os.getenv(name, "").split(",") if item.strip()
    )


def _optional(value: str | None) -> str | None:
    normalised = (value or "").strip()
    return normalised or None


def _proxy_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in _csv("TRUSTED_PROXY_CIDRS"):
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as error:
            raise ValueError(
                f"TRUSTED_PROXY_CIDRS contains invalid CIDR {value!r}"
            ) from error
    return tuple(networks)


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated runtime settings shared by the API, seed, and workers."""

    environment: str
    http_addr: str
    database_url: str
    database_connection_mode: str
    database_pool_min_size: int
    database_pool_max_size: int
    nats_url: str
    event_bus: str
    pubsub_project_id: str | None
    pubsub_topic: str | None
    pubsub_risk_subscription: str | None
    pubsub_notification_subscription: str | None
    jwt_secret: str
    sca_secret: str
    claims_secret: str
    mfa_encryption_key: str | None = field(repr=False)
    mfa_transaction_ttl: timedelta
    mfa_step_up_ttl: timedelta
    webauthn_rp_id: str | None
    webauthn_rp_name: str
    webauthn_allowed_origins: tuple[str, ...]
    jwt_ttl: timedelta
    sca_ttl: timedelta
    sca_threshold_minor: int
    risk_threshold_minor: int
    demo_mode: bool
    outbox_poll_interval: timedelta
    request_body_limit_bytes: int
    auth_account_rate_limit_max: int
    auth_ip_rate_limit_max: int
    auth_rate_limit_window: timedelta
    trusted_proxy_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    allowed_hosts: tuple[str, ...]
    allow_demo_seed: bool
    enable_api_docs: bool
    run_migrations_on_startup: bool
    migration_runtime_grantee: str | None
    asvs_live_runner_enabled: bool
    asvs_target_commit: str
    asvs_ai_generator_enabled: bool
    aspis_mistral_api_key: str | None = field(repr=False)
    workflow_github_token: str | None = field(repr=False)
    super_admin_email: str | None
    aspis_application_source_root: str
    aspis_terraform_source_root: str

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from the environment and reject incomplete startup."""

        environment = os.getenv("APP_ENV", "").strip().lower()
        settings = cls(
            environment=environment,
            http_addr=os.getenv("HTTP_ADDR", ":8080").strip(),
            database_url=os.getenv("DATABASE_URL", "").strip(),
            database_connection_mode=(
                os.getenv("DATABASE_CONNECTION_MODE", "direct").strip().lower()
            ),
            database_pool_min_size=_integer("DATABASE_POOL_MIN_SIZE", 1),
            database_pool_max_size=_integer("DATABASE_POOL_MAX_SIZE", 8),
            nats_url=os.getenv("NATS_URL", "nats://localhost:4222").strip(),
            event_bus=os.getenv("EVENT_BUS", "nats").strip().lower(),
            pubsub_project_id=_optional(
                os.getenv("PUBSUB_PROJECT_ID")
                or os.getenv("GOOGLE_CLOUD_PROJECT")
                or os.getenv("GCP_PROJECT")
            ),
            pubsub_topic=_optional(os.getenv("PUBSUB_TOPIC")),
            pubsub_risk_subscription=_optional(os.getenv("PUBSUB_RISK_SUBSCRIPTION")),
            pubsub_notification_subscription=_optional(
                os.getenv("PUBSUB_NOTIFICATION_SUBSCRIPTION")
            ),
            jwt_secret=os.getenv("JWT_SECRET", ""),
            sca_secret=os.getenv("SCA_SECRET", ""),
            claims_secret=os.getenv("CLAIMS_SECRET", ""),
            mfa_encryption_key=_optional(
                os.getenv("MFA_ENCRYPTION_KEY")
                or (_DEVELOPMENT_MFA_KEY if environment == "development" else None)
            ),
            mfa_transaction_ttl=_duration("MFA_TRANSACTION_TTL", "5m"),
            mfa_step_up_ttl=_duration("MFA_STEP_UP_TTL", "5m"),
            webauthn_rp_id=_optional(os.getenv("WEBAUTHN_RP_ID")),
            webauthn_rp_name=(
                os.getenv("WEBAUTHN_RP_NAME", "Bantam").strip() or "Bantam"
            ),
            webauthn_allowed_origins=_csv("WEBAUTHN_ALLOWED_ORIGINS"),
            jwt_ttl=_duration("JWT_TTL", "15m"),
            sca_ttl=_duration("SCA_TTL", "5m"),
            sca_threshold_minor=_integer("SCA_THRESHOLD_MINOR", 500_000),
            risk_threshold_minor=_integer("RISK_THRESHOLD_MINOR", 500_000),
            # Demo OTP disclosure must be consciously enabled in local tooling.
            demo_mode=_boolean("DEMO_MODE", False),
            outbox_poll_interval=_duration("OUTBOX_POLL_INTERVAL", "1s"),
            request_body_limit_bytes=_integer("REQUEST_BODY_LIMIT_BYTES", 1_048_576),
            auth_account_rate_limit_max=_integer("AUTH_ACCOUNT_RATE_LIMIT_MAX", 10),
            auth_ip_rate_limit_max=_integer("AUTH_IP_RATE_LIMIT_MAX", 50),
            auth_rate_limit_window=_duration("AUTH_RATE_LIMIT_WINDOW", "5m"),
            trusted_proxy_cidrs=_proxy_networks(),
            allowed_hosts=_csv("ALLOWED_HOSTS"),
            # Codespaces/Compose run as development, so the seed still works
            # there without extra env. Other environments fail closed.
            allow_demo_seed=_boolean("ALLOW_DEMO_SEED", environment == "development"),
            # Documentation and migration execution are separated from APP_ENV so
            # a real deployment never needs to masquerade as test just to use a
            # local Cloud SQL Auth Proxy hop.
            enable_api_docs=_boolean("API_DOCS_ENABLED", environment == "development"),
            run_migrations_on_startup=_boolean(
                "RUN_MIGRATIONS_ON_STARTUP", environment == "development"
            ),
            migration_runtime_grantee=(
                os.getenv("MIGRATION_RUNTIME_GRANTEE", "").strip() or None
            ),
            # The dashboard is always available to administrators, but live
            # probes require an explicit development-only opt-in.
            asvs_live_runner_enabled=_boolean("ASVS_LIVE_RUNNER_ENABLED", False),
            asvs_target_commit=(
                os.getenv("ASVS_TARGET_COMMIT", "unversioned").strip() or "unversioned"
            ),
            asvs_ai_generator_enabled=_boolean("ASVS_AI_GENERATOR_ENABLED", False),
            aspis_mistral_api_key=_optional(os.getenv("ASPIS_MISTRAL_API_KEY")),
            workflow_github_token=_optional(os.getenv("WORKFLOW_GITHUB_TOKEN")),
            super_admin_email=_optional(
                (
                    os.getenv("BANTAM_SUPER_ADMIN_EMAIL")
                    or os.getenv("SUPER_ADMIN_EMAIL")
                    or ""
                )
                .strip()
                .lower()
            ),
            aspis_application_source_root=os.getenv(
                "ASPIS_APPLICATION_SOURCE_ROOT",
                "/source-context/application",
            ).strip(),
            aspis_terraform_source_root=os.getenv(
                "ASPIS_TERRAFORM_SOURCE_ROOT",
                "/source-context/terraform",
            ).strip(),
        )
        settings.validate()
        return settings

    @property
    def production(self) -> bool:
        return self.environment == "production"

    @property
    def secure_cookies(self) -> bool:
        # Localhost development is intentionally HTTP; every other environment
        # must use cookies that browsers send only over HTTPS.
        return self.environment != "development"

    @property
    def api_docs_enabled(self) -> bool:
        return self.enable_api_docs

    def validate(self) -> None:
        if self.environment not in _ENVIRONMENTS:
            raise ValueError(
                "APP_ENV must be explicitly set to development, test, or production"
            )
        if not self.database_url:
            raise ValueError("DATABASE_URL is required")
        if self.event_bus not in _EVENT_BUSES:
            raise ValueError("EVENT_BUS must be nats or pubsub")
        if self.event_bus == "nats" and not self.nats_url:
            raise ValueError("NATS_URL is required when EVENT_BUS=nats")
        if self.event_bus == "pubsub":
            missing = [
                name
                for name, value in {
                    "PUBSUB_PROJECT_ID": self.pubsub_project_id,
                    "PUBSUB_TOPIC": self.pubsub_topic,
                    "PUBSUB_RISK_SUBSCRIPTION": self.pubsub_risk_subscription,
                    "PUBSUB_NOTIFICATION_SUBSCRIPTION": (
                        self.pubsub_notification_subscription
                    ),
                }.items()
                if value is None
            ]
            if missing:
                raise ValueError(
                    "EVENT_BUS=pubsub requires " + ", ".join(sorted(missing))
                )
        if self.database_connection_mode not in _DATABASE_CONNECTION_MODES:
            raise ValueError(
                "DATABASE_CONNECTION_MODE must be direct or cloud_sql_proxy"
            )
        if (
            self.database_pool_min_size < 0
            or self.database_pool_max_size == 0
            or self.database_pool_min_size > self.database_pool_max_size
            or self.database_pool_max_size > 20
        ):
            raise ValueError(
                "DATABASE_POOL_MIN_SIZE and DATABASE_POOL_MAX_SIZE must satisfy "
                "0 <= min <= max <= 20 with max greater than zero"
            )

        secrets = {
            "JWT_SECRET": self.jwt_secret,
            "SCA_SECRET": self.sca_secret,
            "CLAIMS_SECRET": self.claims_secret,
        }
        for name, value in secrets.items():
            if len(value.encode("utf-8")) < 32:
                raise ValueError(f"{name} must contain at least 32 bytes")
            if self.environment != "development" and value in KNOWN_DEVELOPMENT_SECRETS:
                raise ValueError(f"{name} uses a public development value")
            if self.production and len(set(value)) < 8:
                raise ValueError(f"{name} appears to have insufficient entropy")
        if len(set(secrets.values())) != len(secrets):
            raise ValueError(
                "JWT_SECRET, SCA_SECRET, and CLAIMS_SECRET must be independent"
            )
        if self.mfa_encryption_key is not None:
            try:
                decoded_mfa_key = base64.b64decode(
                    self.mfa_encryption_key,
                    altchars=b"-_",
                    validate=True,
                )
            except (binascii.Error, ValueError) as error:
                raise ValueError(
                    "MFA_ENCRYPTION_KEY must be a URL-safe Fernet key"
                ) from error
            if len(decoded_mfa_key) != 32:
                raise ValueError("MFA_ENCRYPTION_KEY must encode exactly 32 bytes")
            if (
                self.environment != "development"
                and self.mfa_encryption_key == _DEVELOPMENT_MFA_KEY
            ):
                raise ValueError("MFA_ENCRYPTION_KEY uses a public development value")
            if self.production and len(set(decoded_mfa_key)) < 8:
                raise ValueError(
                    "MFA_ENCRYPTION_KEY appears to have insufficient entropy"
                )
            if self.mfa_encryption_key in secrets.values():
                raise ValueError(
                    "MFA_ENCRYPTION_KEY must be independent from signing secrets"
                )

        if bool(self.webauthn_rp_id) != bool(self.webauthn_allowed_origins):
            raise ValueError(
                "WEBAUTHN_RP_ID and WEBAUTHN_ALLOWED_ORIGINS must be set together"
            )
        if self.webauthn_rp_id:
            if (
                len(self.webauthn_rp_id) > 253
                or self.webauthn_rp_id != self.webauthn_rp_id.lower()
                or not _RP_ID.fullmatch(self.webauthn_rp_id)
            ):
                raise ValueError(
                    "WEBAUTHN_RP_ID must be a lowercase hostname without a scheme"
                )
            for origin in self.webauthn_allowed_origins:
                parsed_origin = urlsplit(origin)
                if (
                    parsed_origin.username
                    or parsed_origin.password
                    or parsed_origin.query
                    or parsed_origin.fragment
                    or parsed_origin.path not in {"", "/"}
                    or not parsed_origin.hostname
                    or parsed_origin.hostname != self.webauthn_rp_id
                    or parsed_origin.scheme
                    not in ({"https"} if self.production else {"http", "https"})
                ):
                    raise ValueError(
                        "WEBAUTHN_ALLOWED_ORIGINS must contain exact origins "
                        "for WEBAUTHN_RP_ID"
                    )
                if (
                    parsed_origin.scheme == "http"
                    and parsed_origin.hostname != "localhost"
                ):
                    raise ValueError(
                        "WebAuthn permits HTTP only for localhost development"
                    )
        if not 1 <= len(self.webauthn_rp_name) <= 80:
            raise ValueError("WEBAUTHN_RP_NAME must contain 1-80 characters")

        if self.demo_mode and self.environment != "development":
            raise ValueError("DEMO_MODE may be enabled only in APP_ENV=development")
        if self.allow_demo_seed and self.environment != "development":
            raise ValueError(
                "ALLOW_DEMO_SEED may be enabled only in APP_ENV=development"
            )
        if self.asvs_live_runner_enabled and not (
            self.environment == "development"
            and self.demo_mode
            and self.allow_demo_seed
        ):
            raise ValueError(
                "ASVS_LIVE_RUNNER_ENABLED requires APP_ENV=development, "
                "DEMO_MODE=true, and ALLOW_DEMO_SEED=true"
            )
        if self.aspis_mistral_api_key is not None and (
            len(self.aspis_mistral_api_key.encode("utf-8")) > 1024
            or any(character.isspace() for character in self.aspis_mistral_api_key)
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.aspis_mistral_api_key
            )
        ):
            raise ValueError(
                "ASPIS_MISTRAL_API_KEY must be a bounded key without whitespace"
            )
        if self.workflow_github_token is not None and (
            len(self.workflow_github_token.encode("utf-8")) > 1024
            or any(character.isspace() for character in self.workflow_github_token)
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.workflow_github_token
            )
        ):
            raise ValueError(
                "WORKFLOW_GITHUB_TOKEN must be a bounded token without whitespace"
            )
        if self.super_admin_email is not None and (
            len(self.super_admin_email) > 254
            or not _EMAIL.fullmatch(self.super_admin_email)
        ):
            raise ValueError("BANTAM_SUPER_ADMIN_EMAIL must be a valid email address")
        for name, value in {
            "ASPIS_APPLICATION_SOURCE_ROOT": self.aspis_application_source_root,
            "ASPIS_TERRAFORM_SOURCE_ROOT": self.aspis_terraform_source_root,
        }.items():
            if (
                not value
                or not os.path.isabs(value)
                or len(value.encode("utf-8")) > 1024
                or any(
                    ord(character) < 32 or ord(character) == 127 for character in value
                )
            ):
                raise ValueError(
                    f"{name} must be a bounded absolute path without control characters"
                )
        if not 1 <= len(self.asvs_target_commit) <= 128 or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.asvs_target_commit
        ):
            raise ValueError(
                "ASVS_TARGET_COMMIT must contain 1-128 printable characters"
            )
        if self.enable_api_docs and self.production:
            raise ValueError("API_DOCS_ENABLED cannot be true in production")
        if self.run_migrations_on_startup and self.production:
            raise ValueError("RUN_MIGRATIONS_ON_STARTUP cannot be true in production")
        if (
            self.migration_runtime_grantee is not None
            and "\x00" in self.migration_runtime_grantee
        ):
            raise ValueError("MIGRATION_RUNTIME_GRANTEE cannot contain NUL bytes")
        if self.production and not self.allowed_hosts:
            raise ValueError("ALLOWED_HOSTS is required in production")
        if self.production and "*" in self.allowed_hosts:
            raise ValueError("ALLOWED_HOSTS cannot contain '*' in production")
        if self.production:
            database = urlsplit(self.database_url)
            sslmode = parse_qs(database.query).get("sslmode", [])
            if database.scheme not in {"postgres", "postgresql"}:
                raise ValueError("production DATABASE_URL must use PostgreSQL")
            if self.database_connection_mode == "direct":
                if sslmode != ["verify-full"]:
                    raise ValueError(
                        "production direct DATABASE_URL must use sslmode=verify-full"
                    )
            else:
                if database.hostname not in _LOOPBACK_DATABASE_HOSTS or sslmode != [
                    "disable"
                ]:
                    raise ValueError(
                        "production cloud_sql_proxy DATABASE_URL must use a "
                        "loopback host with sslmode=disable"
                    )
            if self.event_bus == "nats" and urlsplit(self.nats_url).scheme != "tls":
                raise ValueError("production NATS_URL must use the tls:// scheme")

        if self.jwt_ttl > timedelta(hours=1):
            raise ValueError("JWT_TTL cannot exceed one hour")
        if self.mfa_transaction_ttl > timedelta(minutes=10):
            raise ValueError("MFA_TRANSACTION_TTL cannot exceed ten minutes")
        if self.mfa_step_up_ttl > timedelta(minutes=10):
            raise ValueError("MFA_STEP_UP_TTL cannot exceed ten minutes")
        if self.sca_ttl > timedelta(minutes=10):
            raise ValueError("SCA_TTL cannot exceed ten minutes")
        if self.sca_threshold_minor <= 0 or self.risk_threshold_minor <= 0:
            raise ValueError("risk and SCA thresholds must be positive")
        if not 1_024 <= self.request_body_limit_bytes <= 10_485_760:
            raise ValueError(
                "REQUEST_BODY_LIMIT_BYTES must be between 1024 and 10485760"
            )
        if self.auth_account_rate_limit_max <= 0 or self.auth_ip_rate_limit_max <= 0:
            raise ValueError("authentication rate limits must be positive")
        if self.auth_account_rate_limit_max > self.auth_ip_rate_limit_max:
            raise ValueError(
                "AUTH_ACCOUNT_RATE_LIMIT_MAX cannot exceed AUTH_IP_RATE_LIMIT_MAX"
            )
        if self.auth_rate_limit_window > timedelta(hours=1):
            raise ValueError("AUTH_RATE_LIMIT_WINDOW cannot exceed one hour")

        # Validate the listen address during startup, before Uvicorn is invoked.
        self.uvicorn_address()

    def uvicorn_address(self) -> tuple[str, int]:
        if self.http_addr.startswith(":"):
            # Containers must listen on every container interface so the
            # reverse proxy can reach them; host publishing remains loopback
            # only in Compose and ingress policy owns exposure in production.
            host, raw_port = "0.0.0.0", self.http_addr[1:]  # nosec B104
        else:
            host, separator, raw_port = self.http_addr.rpartition(":")
            if not separator:
                host, raw_port = self.http_addr, "8080"
            host = host or "0.0.0.0"  # nosec B104
        try:
            port = int(raw_port)
        except ValueError as error:
            raise ValueError("HTTP_ADDR must contain a numeric port") from error
        if not 1 <= port <= 65_535:
            raise ValueError("HTTP_ADDR port must be between 1 and 65535")
        return host, port
