"""Regression tests for fail-closed runtime configuration."""

from __future__ import annotations

import os
from datetime import timedelta

import pytest

import bantam.config as config_module
from bantam.config import Settings, parse_duration


def configure_valid_environment(monkeypatch, *, environment: str = "test") -> None:
    monkeypatch.setenv("APP_ENV", environment)
    database_url = "postgres://test:test@localhost/test"
    nats_url = "nats://localhost:4222"
    if environment == "production":
        database_url = (
            "postgresql://test:test@database.example/test?sslmode=verify-full"
        )
        nats_url = "tls://nats.example:4222"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("NATS_URL", nats_url)
    monkeypatch.setenv("JWT_SECRET", "jwt-7Fj9!kQ2#rT5$yU8&bN4*mP6@xC1")
    monkeypatch.setenv("SCA_SECRET", "sca-3Hd8@vL1!pW6#zR9&fK2$uM7*qB5")
    monkeypatch.setenv("CLAIMS_SECRET", "claims-8Zn2!cV5@jX7#sD1&gL4$wQ9P")
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("ALLOWED_HOSTS", "testserver,localhost")


def test_compact_duration_compatibility() -> None:
    fallback = timedelta(seconds=9)

    assert parse_duration("250ms", fallback) == timedelta(milliseconds=250)
    assert parse_duration("15m", fallback) == timedelta(minutes=15)
    assert parse_duration("2h", fallback) == timedelta(hours=2)
    assert parse_duration("bad", fallback) == fallback


def test_settings_keep_documented_environment_contract(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("HTTP_ADDR", "127.0.0.1:9090")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,10.0.0.0/8")

    settings = Settings.from_env()

    assert settings.uvicorn_address() == ("127.0.0.1", 9090)
    assert settings.demo_mode is False
    assert settings.allow_demo_seed is False
    assert settings.database_connection_mode == "direct"
    assert settings.database_pool_min_size == 1
    assert settings.database_pool_max_size == 8
    assert settings.event_bus == "nats"
    assert settings.api_docs_enabled is False
    assert settings.run_migrations_on_startup is False
    assert settings.migration_runtime_grantee is None
    assert settings.mfa_encryption_key is None
    assert settings.mfa_transaction_ttl == timedelta(minutes=5)
    assert settings.mfa_step_up_ttl == timedelta(minutes=5)
    assert settings.webauthn_rp_id is None
    assert settings.webauthn_allowed_origins == ()
    assert settings.asvs_live_runner_enabled is False
    assert settings.asvs_target_commit == "unversioned"
    assert settings.asvs_ai_generator_enabled is False
    assert settings.aspis_mistral_api_key is None
    assert settings.workflow_github_token is None
    assert settings.super_admin_email is None
    assert settings.aspis_application_source_root == "/source-context/application"
    assert settings.aspis_terraform_source_root == "/source-context/terraform"
    assert settings.secure_cookies is True
    assert settings.request_body_limit_bytes == 1_048_576
    assert settings.auth_account_rate_limit_max == 10
    assert settings.auth_ip_rate_limit_max == 50
    assert len(settings.trusted_proxy_cidrs) == 2


def test_settings_accept_exact_webauthn_origin(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv(
        "MFA_ENCRYPTION_KEY",
        "bW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW0=",
    )
    monkeypatch.setenv("WEBAUTHN_RP_ID", "bantam.example.test")
    monkeypatch.setenv(
        "WEBAUTHN_ALLOWED_ORIGINS",
        "https://bantam.example.test",
    )

    settings = Settings.from_env()

    assert settings.mfa_encryption_key is not None
    assert settings.webauthn_rp_id == "bantam.example.test"
    assert settings.webauthn_allowed_origins == ("https://bantam.example.test",)


def test_settings_reject_partial_webauthn_configuration(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("WEBAUTHN_RP_ID", "bantam.example.test")

    with pytest.raises(ValueError, match="must be set together"):
        Settings.from_env()


def test_settings_reject_cross_origin_webauthn_configuration(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("WEBAUTHN_RP_ID", "bantam.example.test")
    monkeypatch.setenv(
        "WEBAUTHN_ALLOWED_ORIGINS",
        "https://attacker.example.test",
    )

    with pytest.raises(ValueError, match="exact origins"):
        Settings.from_env()


def test_settings_reject_invalid_mfa_encryption_key(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", "not-a-fernet-key")

    with pytest.raises(ValueError, match="MFA_ENCRYPTION_KEY"):
        Settings.from_env()


def test_settings_require_explicit_environment(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.delenv("APP_ENV")

    with pytest.raises(ValueError, match="APP_ENV"):
        Settings.from_env()


@pytest.mark.parametrize("name", ["JWT_SECRET", "SCA_SECRET", "CLAIMS_SECRET"])
def test_settings_reject_short_secrets(monkeypatch, name: str) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv(name, "too-short")

    with pytest.raises(ValueError, match=name):
        Settings.from_env()


def test_settings_reject_public_secret_in_production(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="production")
    monkeypatch.setenv(
        "JWT_SECRET", "local-compose-jwt-secret-for-development-only-2026"
    )

    with pytest.raises(ValueError, match="public development value"):
        Settings.from_env()


@pytest.mark.parametrize(
    ("database_url", "nats_url", "message"),
    [
        (
            "postgresql://test:test@database.example/test?sslmode=disable",
            "tls://nats.example:4222",
            "sslmode=verify-full",
        ),
        (
            "postgresql://test:test@database.example/test?sslmode=verify-full",
            "nats://nats.example:4222",
            "tls://",
        ),
    ],
)
def test_settings_require_encrypted_verified_production_transports(
    monkeypatch, database_url: str, nats_url: str, message: str
) -> None:
    configure_valid_environment(monkeypatch, environment="production")
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("NATS_URL", nats_url)

    with pytest.raises(ValueError, match=message):
        Settings.from_env()


def test_settings_reject_obviously_low_entropy_production_secret(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="production")
    monkeypatch.setenv("JWT_SECRET", "j" * 64)

    with pytest.raises(ValueError, match="insufficient entropy"):
        Settings.from_env()


def test_settings_reject_demo_mode_outside_development(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="production")
    monkeypatch.setenv("DEMO_MODE", "true")

    with pytest.raises(ValueError, match="DEMO_MODE"):
        Settings.from_env()


def test_settings_allow_demo_seed_by_default_in_development(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="development")

    settings = Settings.from_env()

    assert settings.allow_demo_seed is True
    assert settings.api_docs_enabled is True
    assert settings.run_migrations_on_startup is True


def test_settings_can_disable_demo_seed_in_development(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="development")
    monkeypatch.setenv("ALLOW_DEMO_SEED", "false")

    settings = Settings.from_env()

    assert settings.allow_demo_seed is False


def test_settings_enable_asvs_runner_only_for_seeded_development(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="development")
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("ASVS_LIVE_RUNNER_ENABLED", "true")
    monkeypatch.setenv("ASVS_TARGET_COMMIT", "0123456789abcdef")

    settings = Settings.from_env()

    assert settings.asvs_live_runner_enabled is True
    assert settings.asvs_target_commit == "0123456789abcdef"


def test_settings_enable_ai_generator_without_live_runner(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="production")
    monkeypatch.setenv("ASVS_AI_GENERATOR_ENABLED", "true")
    monkeypatch.setenv("ASPIS_MISTRAL_API_KEY", "mistral-test-key-without-whitespace")

    settings = Settings.from_env()

    assert settings.asvs_live_runner_enabled is False
    assert settings.asvs_ai_generator_enabled is True
    assert settings.aspis_mistral_api_key is not None
    assert settings.aspis_mistral_api_key not in repr(settings)


def test_settings_allow_ai_demo_to_start_without_optional_token(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="development")
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("ASVS_LIVE_RUNNER_ENABLED", "true")
    monkeypatch.setenv("ASVS_AI_GENERATOR_ENABLED", "true")

    settings = Settings.from_env()

    assert settings.asvs_ai_generator_enabled is True
    assert settings.aspis_mistral_api_key is None


def test_settings_never_reuse_the_retired_github_models_token(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="development")
    monkeypatch.setenv("ASPIS_MODELS_TOKEN", "github-token-must-not-leave-codespaces")

    settings = Settings.from_env()

    assert settings.aspis_mistral_api_key is None


def test_settings_reject_whitespace_in_mistral_api_key(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("ASPIS_MISTRAL_API_KEY", "key with spaces")

    with pytest.raises(ValueError, match="ASPIS_MISTRAL_API_KEY"):
        Settings.from_env()


def test_settings_accepts_server_side_workflow_github_token(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("WORKFLOW_GITHUB_TOKEN", "test-private-repository-read-token")

    settings = Settings.from_env()

    assert settings.workflow_github_token is not None
    assert settings.workflow_github_token not in repr(settings)


def test_settings_rejects_whitespace_in_workflow_github_token(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("WORKFLOW_GITHUB_TOKEN", "invalid token")

    with pytest.raises(ValueError, match="WORKFLOW_GITHUB_TOKEN"):
        Settings.from_env()


def test_settings_accepts_super_admin_email(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("BANTAM_SUPER_ADMIN_EMAIL", "Root.Admin@Example.Test")

    settings = Settings.from_env()

    assert settings.super_admin_email == "root.admin@example.test"


def test_settings_rejects_invalid_super_admin_email(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("BANTAM_SUPER_ADMIN_EMAIL", "not-an-email")

    with pytest.raises(ValueError, match="BANTAM_SUPER_ADMIN_EMAIL"):
        Settings.from_env()


def test_settings_require_absolute_source_roots(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("ASPIS_TERRAFORM_SOURCE_ROOT", "../Terraform-infra/bank")

    with pytest.raises(ValueError, match="ASPIS_TERRAFORM_SOURCE_ROOT"):
        Settings.from_env()


@pytest.mark.parametrize(
    ("environment", "demo_mode", "allow_demo_seed"),
    [
        ("production", "false", "false"),
        ("test", "false", "false"),
        ("development", "false", "true"),
        ("development", "true", "false"),
    ],
)
def test_settings_fail_closed_for_unsafe_asvs_runner_modes(
    monkeypatch,
    environment: str,
    demo_mode: str,
    allow_demo_seed: str,
) -> None:
    configure_valid_environment(monkeypatch, environment=environment)
    monkeypatch.setenv("DEMO_MODE", demo_mode)
    monkeypatch.setenv("ALLOW_DEMO_SEED", allow_demo_seed)
    monkeypatch.setenv("ASVS_LIVE_RUNNER_ENABLED", "true")

    with pytest.raises(ValueError, match="ASVS_LIVE_RUNNER_ENABLED"):
        Settings.from_env()


def test_settings_reject_control_char_in_asvs_target_commit(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("ASVS_TARGET_COMMIT", "commit\nforged")

    with pytest.raises(ValueError, match="ASVS_TARGET_COMMIT"):
        Settings.from_env()


def test_settings_reject_demo_seed_outside_development(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="production")
    monkeypatch.setenv("ALLOW_DEMO_SEED", "true")

    with pytest.raises(ValueError, match="ALLOW_DEMO_SEED"):
        Settings.from_env()


def test_settings_reject_api_docs_in_production(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="production")
    monkeypatch.setenv("API_DOCS_ENABLED", "true")

    with pytest.raises(ValueError, match="API_DOCS_ENABLED"):
        Settings.from_env()


def test_settings_reject_runtime_migrations_in_production(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="production")
    monkeypatch.setenv("RUN_MIGRATIONS_ON_STARTUP", "true")

    with pytest.raises(ValueError, match="RUN_MIGRATIONS_ON_STARTUP"):
        Settings.from_env()


def test_settings_allow_cloud_sql_proxy_in_production(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="production")
    monkeypatch.setenv("DATABASE_CONNECTION_MODE", "cloud_sql_proxy")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://bantam:bantam@127.0.0.1:5432/bantam?sslmode=disable",
    )

    settings = Settings.from_env()

    assert settings.production is True
    assert settings.database_connection_mode == "cloud_sql_proxy"
    assert settings.api_docs_enabled is False
    assert settings.run_migrations_on_startup is False


def test_settings_reject_non_loopback_cloud_sql_proxy(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="production")
    monkeypatch.setenv("DATABASE_CONNECTION_MODE", "cloud_sql_proxy")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://bantam:bantam@database.example:5432/bantam?sslmode=disable",
    )

    with pytest.raises(ValueError, match="cloud_sql_proxy"):
        Settings.from_env()


def test_settings_reject_reused_signing_keys(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("CLAIMS_SECRET", "jwt-7Fj9!kQ2#rT5$yU8&bN4*mP6@xC1")

    with pytest.raises(ValueError, match="independent"):
        Settings.from_env()


def test_settings_accept_security_limit_overrides(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("DATABASE_POOL_MIN_SIZE", "0")
    monkeypatch.setenv("DATABASE_POOL_MAX_SIZE", "6")
    monkeypatch.setenv("REQUEST_BODY_LIMIT_BYTES", "2048")
    monkeypatch.setenv("AUTH_ACCOUNT_RATE_LIMIT_MAX", "3")
    monkeypatch.setenv("AUTH_IP_RATE_LIMIT_MAX", "20")
    monkeypatch.setenv("AUTH_RATE_LIMIT_WINDOW", "1m")

    settings = Settings.from_env()

    assert settings.database_pool_min_size == 0
    assert settings.database_pool_max_size == 6
    assert settings.request_body_limit_bytes == 2048
    assert settings.auth_account_rate_limit_max == 3
    assert settings.auth_ip_rate_limit_max == 20
    assert settings.auth_rate_limit_window == timedelta(minutes=1)


@pytest.mark.parametrize(
    ("minimum", "maximum"),
    [("-1", "8"), ("9", "8"), ("0", "0"), ("1", "21")],
)
def test_settings_reject_invalid_database_pool_bounds(
    monkeypatch, minimum: str, maximum: str
) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("DATABASE_POOL_MIN_SIZE", minimum)
    monkeypatch.setenv("DATABASE_POOL_MAX_SIZE", maximum)

    with pytest.raises(ValueError, match="DATABASE_POOL"):
        Settings.from_env()


def test_settings_reject_malformed_security_values(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "not-a-network")

    with pytest.raises(ValueError, match="TRUSTED_PROXY_CIDRS"):
        Settings.from_env()


def test_settings_accept_migration_runtime_grantee(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="production")
    monkeypatch.setenv("MIGRATION_RUNTIME_GRANTEE", "btm-demo-run@example.iam")
    settings = Settings.from_env()

    assert settings.migration_runtime_grantee == "btm-demo-run@example.iam"


def test_settings_reject_nul_in_migration_runtime_grantee(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    real_getenv = os.getenv

    def fake_getenv(name: str, default: str | None = None):
        if name == "MIGRATION_RUNTIME_GRANTEE":
            return "runtime\x00role"
        return real_getenv(name, default)

    monkeypatch.setattr(config_module.os, "getenv", fake_getenv)

    with pytest.raises(ValueError, match="MIGRATION_RUNTIME_GRANTEE"):
        Settings.from_env()


def test_settings_allow_pubsub_in_production_without_nats_tls(monkeypatch) -> None:
    configure_valid_environment(monkeypatch, environment="production")
    monkeypatch.setenv("EVENT_BUS", "pubsub")
    monkeypatch.setenv("NATS_URL", "nats://not-used:4222")
    monkeypatch.setenv("PUBSUB_PROJECT_ID", "bantam-demo")
    monkeypatch.setenv("PUBSUB_TOPIC", "bantam-demo-events")
    monkeypatch.setenv("PUBSUB_RISK_SUBSCRIPTION", "bantam-demo-risk-worker")
    monkeypatch.setenv(
        "PUBSUB_NOTIFICATION_SUBSCRIPTION", "bantam-demo-notification-worker"
    )

    settings = Settings.from_env()

    assert settings.event_bus == "pubsub"
    assert settings.pubsub_project_id == "bantam-demo"
    assert settings.pubsub_topic == "bantam-demo-events"


def test_settings_require_pubsub_configuration(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("EVENT_BUS", "pubsub")

    with pytest.raises(ValueError, match="PUBSUB"):
        Settings.from_env()


def test_settings_reject_unknown_event_bus(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("EVENT_BUS", "rabbitmq")

    with pytest.raises(ValueError, match="EVENT_BUS"):
        Settings.from_env()


def test_settings_reject_unknown_database_connection_mode(monkeypatch) -> None:
    configure_valid_environment(monkeypatch)
    monkeypatch.setenv("DATABASE_CONNECTION_MODE", "magic-tunnel")

    with pytest.raises(ValueError, match="DATABASE_CONNECTION_MODE"):
        Settings.from_env()
