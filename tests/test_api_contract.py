"""Route registration smoke test without importing configuration at module load."""

from bantam.api import create_app
from bantam.config import Settings


def test_main_ui_api_contract_is_registered(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", "postgres://test:test@localhost/test")
    monkeypatch.setenv("JWT_SECRET", "j" * 32)
    monkeypatch.setenv("SCA_SECRET", "s" * 32)
    monkeypatch.setenv("CLAIMS_SECRET", "c" * 32)
    monkeypatch.setenv(
        "MFA_ENCRYPTION_KEY",
        "bW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW0=",
    )
    monkeypatch.setenv("ALLOWED_HOSTS", "testserver")
    app = create_app(settings=Settings.from_env())
    routes = {
        (method, route.path)
        for route in app.routes
        for method in getattr(route, "methods", set())
    }
    expected = {
        ("GET", "/healthz"),
        ("POST", "/v1/auth/register"),
        ("POST", "/v1/auth/login"),
        ("POST", "/v1/auth/mfa/setup"),
        ("POST", "/v1/auth/mfa/passkey"),
        ("POST", "/v1/auth/mfa/totp"),
        ("POST", "/v1/auth/logout"),
        ("GET", "/v1/me"),
        ("GET", "/v1/me/mfa"),
        ("POST", "/v1/me/mfa/enrollment"),
        ("DELETE", "/v1/me/mfa/passkeys/{credential_id}"),
        ("DELETE", "/v1/me/mfa/totp"),
        ("POST", "/v1/me/kyc/submit"),
        ("GET", "/v1/accounts"),
        ("POST", "/v1/accounts"),
        ("GET", "/v1/accounts/{account_id}/transactions"),
        ("POST", "/v1/sca/challenges"),
        ("POST", "/v1/transfers"),
        ("GET", "/v1/notifications"),
        ("POST", "/v1/claims/account-status"),
        ("GET", "/v1/admin/customers"),
        ("GET", "/v1/admin/users"),
        ("POST", "/v1/admin/users"),
        ("GET", "/v1/admin/aspis-auditor-requests"),
        (
            "POST",
            "/v1/admin/aspis-auditor-requests/{approval_request_id}/decision",
        ),
        ("GET", "/v1/admin/asvs"),
        ("POST", "/v1/admin/asvs/runs"),
        ("POST", "/v1/admin/asvs/test-plans"),
        ("POST", "/v1/admin/asvs/test-plans/{generation_id}/execute"),
        ("GET", "/v1/admin/workflow-graph"),
        ("POST", "/v1/admin/workflows/validate"),
        ("POST", "/v1/admin/workflows"),
        ("GET", "/v1/admin/repository-graphs"),
        ("POST", "/v1/admin/repository-graphs"),
        ("GET", "/v1/admin/repository-graphs/{snapshot_id}"),
        (
            "POST",
            "/v1/admin/repository-graphs/{snapshot_id}/workflows/validate",
        ),
        ("POST", "/v1/admin/repository-graphs/{snapshot_id}/workflows"),
        ("GET", "/v1/admin/company-financials"),
        ("POST", "/v1/admin/company-financials"),
        ("GET", "/v1/admin/attack-scenarios"),
        ("POST", "/v1/admin/attack-scenarios"),
        ("GET", "/v1/admin/attack-scenarios/{scenario_set_id}"),
        ("POST", "/v1/admin/attack-scenarios/{scenario_set_id}/simulations"),
        (
            "POST",
            "/v1/admin/attack-scenarios/{scenario_set_id}"
            "/simulations/{simulation_id}/remediations",
        ),
        ("PATCH", "/v1/admin/customers/{customer_id}/kyc"),
        ("PATCH", "/v1/admin/accounts/{account_id}/status"),
        ("POST", "/v1/admin/accounts/{account_id}/demo-deposit"),
        ("POST", "/v1/admin/transactions/{transaction_id}/reverse"),
        ("GET", "/v1/admin/transactions"),
        ("GET", "/v1/risk/alerts"),
        ("POST", "/v1/risk/alerts"),
        ("PATCH", "/v1/risk/alerts/{alert_id}"),
        ("GET", "/v1/audit/events"),
        ("POST", "/v1/reconciliation/runs"),
    }

    assert expected <= routes
