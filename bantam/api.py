"""FastAPI edge for Bantam's customer and operator workflows.

Routes keep authorization checks close to database ownership predicates, while
shared middleware owns cross-cutting trust-boundary controls such as request
limits, proxy resolution, security headers, cookies, and correlation IDs.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from psycopg import errors, sql
from psycopg.types.json import Jsonb
from starlette.middleware.trustedhost import TrustedHostMiddleware

from bantam import audit
from bantam.asvs import AsvsService
from bantam.asvs_ai import AsvsAiService
from bantam.attack_simulation import AttackSimulationService
from bantam.auth import (
    AuthService,
    SignedClaimService,
    check_password,
    hash_password,
    password_hash_for_check,
    revoke_access_token,
)
from bantam.config import Settings
from bantam.database import Database
from bantam.financials import CompanyFinancialsService
from bantam.domain import (
    ACCOUNT_ACTIVE,
    ADMIN_PERMISSION_SCOPES,
    ACCOUNT_FROZEN,
    KYC_PENDING,
    KYC_REJECTED,
    KYC_REVIEW,
    KYC_VERIFIED,
    ROLE_ASPIS_ADMIN,
    ROLE_ASPIS_AUDITOR,
    ROLE_BANK_ADMIN,
    ROLE_COMPLIANCE_AUDITOR,
    ROLE_CUSTOMER,
    ROLE_PENDING_APPROVAL,
    ROLE_RISK_ANALYST,
    Principal,
    TransferCommand,
)
from bantam.errors import BantamError, FORBIDDEN, validation
from bantam.mfa import MfaCompletion, MfaFailure, MfaService
from bantam.ledger import (
    ALIASED_TRANSACTION_PROJECTION,
    LedgerService,
    TRANSACTION_PROJECTION,
    transaction_payload,
)
from bantam.sca import SCAService
from bantam.repository_graph import RepositoryGraphService
from bantam.schemas import (
    AccountStatusRequest,
    AdminUserCreateRequest,
    AspisAuditorDecisionRequest,
    AspisAuditorRegisterRequest,
    AttackScenarioRequest,
    AttackSimulationRequest,
    CompanyFinancialsRequest,
    DemoDepositRequest,
    KYCDecisionRequest,
    LoginRequest,
    ManualRiskAlertRequest,
    MfaEnrollmentRequest,
    MfaPasskeyRequest,
    MfaSetupRequest,
    MfaTotpRequest,
    OpenAccountRequest,
    RegisterRequest,
    RepositoryGraphRequest,
    RepositoryWorkflowDefinitionRequest,
    ReverseRequest,
    ReviewRiskAlertRequest,
    SCAChallengeRequest,
    TransferRequest,
    WorkflowDefinitionRequest,
)
from bantam.security import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    DatabaseRateLimiter,
    RequestBodyLimitMiddleware,
    add_security_headers,
    client_ip,
    csrf_problem,
    normalise_idempotency_key,
)
from bantam.workflow_graph import WorkflowGraphService


LOGGER = logging.getLogger(__name__)
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


def request_id(request: Request) -> UUID:
    return request.state.request_id


def request_audit(
    request: Request,
    *,
    actor_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "actor_type": "USER",
        "actor_id": actor_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "request_id": request_id(request),
        "correlation_id": request_id(request),
        "ip_address": client_ip(
            request, request.app.state.settings.trusted_proxy_cidrs
        ),
        # Bound untrusted header data before it reaches durable audit storage.
        "user_agent": request.headers.get("user-agent", "")[:512] or None,
        "metadata": metadata,
    }


def query_limit(request: Request, fallback: int, maximum: int) -> int:
    raw = request.query_params.get("limit", "")
    try:
        value = int(raw)
    except ValueError:
        return fallback
    if value <= 0:
        return fallback
    return min(value, maximum)


def require_idempotency_key(raw: str | None) -> str:
    try:
        return normalise_idempotency_key(raw)
    except ValueError as error:
        if str(error) == "required":
            raise BantamError(
                "IDEMPOTENCY_KEY_REQUIRED",
                "Idempotency-Key header is required",
                400,
            ) from error
        raise BantamError(
            "INVALID_IDEMPOTENCY_KEY",
            "Idempotency-Key must be 8-128 URL-safe characters",
            400,
        ) from error


def enforce_auth_rate_limit(request: Request, purpose: str, identifier: str) -> None:
    address = client_ip(request, request.app.state.settings.trusted_proxy_cidrs)
    checks = (
        request.app.state.auth_ip_rate_limiter.check(f"{purpose}:ip:{address}"),
        request.app.state.auth_account_rate_limiter.check(
            f"{purpose}:account:{identifier.casefold()}"
        ),
    )
    blocked = next((result for result in checks if not result.allowed), None)
    if blocked:
        raise BantamError(
            "RATE_LIMITED",
            f"too many attempts; retry after {blocked.retry_after_seconds} seconds",
            429,
        )


def authenticated_principal(request: Request) -> Principal:
    header = request.headers.get("authorization", "")
    cookie_authenticated = not header.startswith("Bearer ")
    raw_token = (
        request.cookies.get(SESSION_COOKIE_NAME, "")
        if cookie_authenticated
        else header.removeprefix("Bearer ")
    )
    if not raw_token:
        raise BantamError("UNAUTHENTICATED", "authentication is required", 401)
    if cookie_authenticated:
        problem = csrf_problem(request)
        if problem:
            raise BantamError("CSRF_FAILED", problem, 403)
    try:
        parsed_token = request.app.state.auth.parse_with_claims(raw_token)
    except ValueError as error:
        raise BantamError(
            "UNAUTHENTICATED", "access token is invalid or expired", 401
        ) from error
    request.state.access_token = parsed_token
    principal = parsed_token.principal

    # Short token lifetimes limit exposure, while this database check gives
    # operators immediate revocation and prevents stale role claims surviving a
    # privilege change.
    with request.app.state.database.pool.connection() as connection:
        current = connection.execute(
            """
            SELECT role, customer_id, status
            FROM user_accounts
            WHERE user_id = %s
            """,
            (principal.user_id,),
        ).fetchone()
    if (
        not current
        or current["status"] != "ACTIVE"
        or current["role"] != principal.role
        or current["customer_id"] != principal.customer_id
    ):
        raise BantamError("UNAUTHENTICATED", "session is no longer active", 401)
    return principal


def require_roles(*roles: str):
    def dependency(
        principal: Annotated[Principal, Depends(authenticated_principal)],
    ) -> Principal:
        if principal.role not in roles:
            raise BantamError("FORBIDDEN", "this role cannot perform the action", 403)
        return principal

    return dependency


CustomerPrincipal = Annotated[Principal, Depends(require_roles(ROLE_CUSTOMER))]
AdminPrincipal = Annotated[Principal, Depends(require_roles(ROLE_BANK_ADMIN))]
AspisAdminPrincipal = Annotated[
    Principal, Depends(require_roles(ROLE_BANK_ADMIN, ROLE_ASPIS_ADMIN))
]
AspisPrincipal = Annotated[
    Principal,
    Depends(require_roles(ROLE_BANK_ADMIN, ROLE_ASPIS_ADMIN, ROLE_ASPIS_AUDITOR)),
]
MfaPrincipal = Annotated[
    Principal,
    Depends(require_roles(ROLE_BANK_ADMIN, ROLE_ASPIS_ADMIN, ROLE_ASPIS_AUDITOR)),
]
OperatorPrincipal = Annotated[
    Principal, Depends(require_roles(ROLE_BANK_ADMIN, ROLE_RISK_ANALYST))
]
AuditPrincipal = Annotated[
    Principal,
    Depends(require_roles(ROLE_BANK_ADMIN, ROLE_RISK_ANALYST, ROLE_COMPLIANCE_AUDITOR)),
]
ReconcilePrincipal = Annotated[
    Principal, Depends(require_roles(ROLE_BANK_ADMIN, ROLE_COMPLIANCE_AUDITOR))
]
AnyPrincipal = Annotated[Principal, Depends(authenticated_principal)]


def describe_admin_access(
    connection,
    request: Request,
    principal: Principal,
) -> tuple[bool, tuple[str, ...]]:
    if principal.role != ROLE_BANK_ADMIN:
        return False, ()
    super_email = request.app.state.settings.super_admin_email
    if super_email:
        current = connection.execute(
            """
            SELECT email
            FROM user_accounts
            WHERE user_id = %s
              AND role = %s
              AND status = 'ACTIVE'
            """,
            (principal.user_id, ROLE_BANK_ADMIN),
        ).fetchone()
        if current and current["email"].casefold() == super_email.casefold():
            return True, ADMIN_PERMISSION_SCOPES
    rows = connection.execute(
        """
        SELECT scope
        FROM admin_permissions
        WHERE user_id = %s
        ORDER BY scope
        """,
        (principal.user_id,),
    ).fetchall()
    return False, tuple(row["scope"] for row in rows)


def require_admin_scope(request: Request, principal: Principal, scope: str) -> None:
    if principal.role != ROLE_BANK_ADMIN:
        return
    if scope not in ADMIN_PERMISSION_SCOPES:
        raise RuntimeError(f"unknown admin scope: {scope}")
    with request.app.state.database.pool.connection() as connection:
        is_super_admin, scopes = describe_admin_access(connection, request, principal)
    if is_super_admin or scope in scopes:
        return
    raise BantamError(
        "FORBIDDEN",
        f"this administrator cannot access the {scope.replace('_', ' ')} workspace",
        403,
    )


def admin_user_payload(row: dict[str, object], settings: Settings) -> dict[str, object]:
    email = str(row["email"])
    is_super_admin = bool(
        settings.super_admin_email
        and email.casefold() == settings.super_admin_email.casefold()
    )
    permissions = list(row.get("permissions") or ())
    if is_super_admin:
        permissions = list(ADMIN_PERMISSION_SCOPES)
    return {
        "user_id": row["user_id"],
        "email": email,
        "role": row["role"],
        "status": row["status"],
        "mfa_enabled": row["mfa_enabled"],
        "permissions": permissions,
        "is_super_admin": is_super_admin,
        "created_at": row["created_at"],
    }


def issue_session(
    request: Request,
    response: Response,
    principal: Principal,
    *,
    auth_methods: tuple[str, ...],
    mfa_at: datetime | None = None,
) -> dict[str, object]:
    token, expires_at = request.app.state.auth.issue(
        principal,
        auth_methods=auth_methods,
        mfa_at=mfa_at,
    )
    csrf_token = secrets.token_urlsafe(32)
    max_age = int(request.app.state.settings.jwt_ttl.total_seconds())
    cookie_options = {
        "secure": request.app.state.settings.secure_cookies,
        "samesite": "strict",
        "path": "/",
        "max_age": max_age,
    }
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        **cookie_options,
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf_token,
        httponly=False,
        **cookie_options,
    )
    return {
        "expires_at": expires_at,
        "role": principal.role,
        "csrf_token": csrf_token,
    }


def require_recent_mfa(request: Request) -> None:
    mfa_at = request.state.access_token.mfa_at
    if (
        mfa_at is None
        or datetime.now(UTC) - mfa_at > request.app.state.settings.mfa_step_up_ttl
    ):
        raise BantamError(
            "MFA_STEP_UP_REQUIRED",
            "Sign in with MFA again before performing this action.",
            403,
        )


def finish_mfa_session(
    request: Request,
    response: Response,
    completion: MfaCompletion,
) -> dict[str, object]:
    principal = Principal(
        user_id=completion.user_id,
        customer_id=completion.customer_id,
        role=completion.role,
    )
    mfa_at = datetime.now(UTC)
    assurance_method = "otp" if completion.method == "totp" else completion.method
    with request.app.state.database.pool.connection() as connection:
        if completion.enrolled:
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="MFA_FACTOR_ENROLLED",
                    resource_type="user_account",
                    resource_id=str(principal.user_id),
                    metadata={"method": completion.method},
                ),
            )
        audit.record(
            connection,
            **request_audit(
                request,
                actor_id=str(principal.user_id),
                action="LOGIN_SUCCEEDED",
                resource_type="user_account",
                resource_id=str(principal.user_id),
                metadata={"amr": ["pwd", assurance_method]},
            ),
        )
    return issue_session(
        request,
        response,
        principal,
        auth_methods=("pwd", assurance_method),
        mfa_at=mfa_at,
    )


def create_app(
    settings: Settings | None = None, database: Database | None = None
) -> FastAPI:
    settings = settings or Settings.from_env()
    database = database or Database(
        settings.database_url,
        min_size=settings.database_pool_min_size,
        max_size=settings.database_pool_max_size,
    )
    auth_service = AuthService(settings.jwt_secret, settings.jwt_ttl)
    mfa_service = MfaService(
        database.pool,
        encryption_key=settings.mfa_encryption_key,
        transaction_ttl=settings.mfa_transaction_ttl,
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        allowed_origins=settings.webauthn_allowed_origins,
    )
    claim_service = SignedClaimService(settings.claims_secret)
    sca_service = SCAService(
        settings.sca_secret,
        settings.sca_ttl,
        settings.sca_threshold_minor,
        settings.demo_mode,
    )
    ledger_service = LedgerService(database.pool, sca_service)
    _, api_port = settings.uvicorn_address()
    asvs_service = AsvsService(
        database.pool,
        runner_enabled=settings.asvs_live_runner_enabled,
        target_commit=settings.asvs_target_commit,
        api_port=api_port,
    )
    asvs_ai_service = AsvsAiService(
        database.pool,
        feature_enabled=settings.asvs_ai_generator_enabled,
        api_key=settings.aspis_mistral_api_key,
        target_commit=settings.asvs_target_commit,
        application_source_root=settings.aspis_application_source_root,
        terraform_source_root=settings.aspis_terraform_source_root,
    )
    workflow_graph_service = WorkflowGraphService(database.pool)
    repository_graph_service = RepositoryGraphService(
        database.pool,
        github_token=settings.workflow_github_token,
        mistral_api_key=settings.aspis_mistral_api_key,
    )
    company_financials_service = CompanyFinancialsService(database.pool)
    attack_simulation_service = AttackSimulationService(
        database.pool,
        builtin_catalog=workflow_graph_service.catalog,
        financials=company_financials_service,
        models_client=repository_graph_service.models_client,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.open(migrate=settings.run_migrations_on_startup)
        try:
            yield
        finally:
            database.close()

    app = FastAPI(
        title="Bantam API",
        version="0.2.0",
        description="Fake-money banking API for architecture practice.",
        lifespan=lifespan,
        docs_url="/docs" if settings.api_docs_enabled else None,
        redoc_url="/redoc" if settings.api_docs_enabled else None,
        openapi_url="/openapi.json" if settings.api_docs_enabled else None,
    )
    app.add_middleware(
        RequestBodyLimitMiddleware, max_bytes=settings.request_body_limit_bytes
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(
            settings.allowed_hosts or ("localhost", "127.0.0.1", "testserver")
        ),
    )
    app.state.settings = settings
    app.state.database = database
    app.state.auth = auth_service
    app.state.mfa = mfa_service
    app.state.claims = claim_service
    app.state.sca = sca_service
    app.state.ledger = ledger_service
    app.state.asvs = asvs_service
    app.state.asvs_ai = asvs_ai_service
    app.state.workflow_graph = workflow_graph_service
    app.state.repository_graph = repository_graph_service
    app.state.company_financials = company_financials_service
    app.state.attack_simulation = attack_simulation_service
    # PostgreSQL keeps throttling effective across workers, replicas, and
    # rolling deployments without adding a separate paid cache dependency.
    app.state.auth_account_rate_limiter = DatabaseRateLimiter(
        database.pool,
        limit=settings.auth_account_rate_limit_max,
        window=settings.auth_rate_limit_window,
    )
    app.state.auth_ip_rate_limiter = DatabaseRateLimiter(
        database.pool,
        limit=settings.auth_ip_rate_limit_max,
        window=settings.auth_rate_limit_window,
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        started = time.perf_counter()
        try:
            incoming = UUID(request.headers.get("x-request-id", ""))
        except ValueError:
            incoming = uuid4()
        request.state.request_id = incoming
        response = await call_next(request)
        response.headers["X-Request-ID"] = str(incoming)
        add_security_headers(request, response)
        LOGGER.info(
            "http request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000),
                "request_id": str(incoming),
            },
        )
        return response

    @app.exception_handler(BantamError)
    async def bantam_error_handler(_: Request, error: BantamError):
        return error_response(error.status_code, error.code, error.message)

    @app.exception_handler(MfaFailure)
    async def mfa_error_handler(_: Request, error: MfaFailure):
        return error_response(error.status_code, error.code, error.message)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_: Request, error: RequestValidationError):
        issue = error.errors()[0] if error.errors() else None
        location = (
            ".".join(str(item) for item in issue.get("loc", [])[1:])
            if issue
            else "request"
        )
        message = (
            f"{location}: {issue['msg']}"
            if issue and location
            else "request validation failed"
        )
        return error_response(422, "VALIDATION_FAILED", message)

    @app.exception_handler(Exception)
    async def internal_error_handler(request: Request, error: Exception):
        LOGGER.exception(
            "unhandled request error",
            extra={"request_id": str(getattr(request.state, "request_id", ""))},
        )
        return error_response(
            500, "INTERNAL_ERROR", "the request could not be completed"
        )

    register_routes(app)
    return app


def register_routes(app: FastAPI) -> None:
    @app.get("/healthz")
    def health(request: Request):
        try:
            request.app.state.database.ping()
        except Exception as error:
            raise BantamError(
                "DATABASE_UNAVAILABLE", "database is unavailable", 503
            ) from error
        return {"status": "ok", "service": "bantam-api"}

    @app.post("/v1/auth/register", status_code=202)
    def register(input: RegisterRequest, request: Request):
        legal_name = input.legal_name.strip()
        email = input.email.strip().lower()
        phone = input.phone.strip()
        enforce_auth_rate_limit(request, "register", email)
        if len(legal_name) < 2:
            raise validation("legal_name is required")
        if not EMAIL_PATTERN.fullmatch(email):
            raise validation("email is invalid")
        try:
            date_of_birth = date.fromisoformat(input.date_of_birth)
        except ValueError as error:
            raise validation("customer must be at least 18 years old") from error
        today = datetime.now(UTC).date()
        try:
            adult_cutoff = today.replace(year=today.year - 18)
        except ValueError:
            adult_cutoff = today.replace(year=today.year - 18, day=28)
        if date_of_birth > adult_cutoff:
            raise validation("customer must be at least 18 years old")
        try:
            password_hash = hash_password(
                input.password,
                disallowed_values=(email, legal_name),
            )
        except ValueError as error:
            raise validation(str(error)) from error

        customer_id = uuid4()
        user_id = uuid4()
        pool = request.app.state.database.pool
        try:
            with pool.connection() as connection:
                with connection.transaction():
                    connection.execute(
                        """
                        INSERT INTO customers (
                            customer_id, legal_name, date_of_birth, email, phone
                        ) VALUES (%s,%s,%s,%s,%s)
                        """,
                        (customer_id, legal_name, date_of_birth, email, phone),
                    )
                    connection.execute(
                        """
                        INSERT INTO user_accounts (
                            user_id, email, password_hash, role, customer_id
                        ) VALUES (%s,%s,%s,'CUSTOMER',%s)
                        """,
                        (user_id, email, password_hash, customer_id),
                    )
                    connection.execute(
                        """
                        INSERT INTO outbox_events (
                            outbox_event_id, aggregate_type, aggregate_id,
                            event_type, event_version, payload
                        ) VALUES (%s,'customer',%s,'customer.created.v1',1,%s)
                        """,
                        (
                            uuid4(),
                            customer_id,
                            Jsonb(
                                {
                                    "customer_id": str(customer_id),
                                    "kyc_status": KYC_PENDING,
                                }
                            ),
                        ),
                    )
                    audit.record(
                        connection,
                        **request_audit(
                            request,
                            actor_id=str(user_id),
                            action="CUSTOMER_REGISTERED",
                            resource_type="customer",
                            resource_id=str(customer_id),
                        ),
                    )
        except errors.UniqueViolation:
            # Registration deliberately returns the same result for an existing
            # address.  The password hash was already computed, reducing both
            # response and timing-based account enumeration.
            LOGGER.info(
                "registration accepted for existing identity",
                extra={"request_id": str(request_id(request))},
            )
        return {
            "status": "accepted",
            "message": "If eligible, the synthetic customer profile is ready for sign-in.",
        }

    @app.post("/v1/auth/register/aspis-auditor", status_code=202)
    def register_aspis_auditor(
        input: AspisAuditorRegisterRequest,
        request: Request,
    ):
        email = input.email.strip().lower()
        enforce_auth_rate_limit(request, "register", email)
        if not EMAIL_PATTERN.fullmatch(email):
            raise validation("email is invalid")
        try:
            password_hash = hash_password(
                input.password,
                disallowed_values=(email, "aspis auditor"),
            )
        except ValueError as error:
            raise validation(str(error)) from error

        user_id = uuid4()
        approval_request_id = uuid4()
        pool = request.app.state.database.pool
        try:
            with pool.connection() as connection:
                with connection.transaction():
                    connection.execute(
                        """
                        INSERT INTO user_accounts (
                            user_id, email, password_hash, role, customer_id
                        ) VALUES (%s,%s,%s,%s,NULL)
                        """,
                        (user_id, email, password_hash, ROLE_PENDING_APPROVAL),
                    )
                    connection.execute(
                        """
                        INSERT INTO aspis_auditor_requests (
                            request_id, user_id
                        ) VALUES (%s,%s)
                        """,
                        (approval_request_id, user_id),
                    )
                    audit.record(
                        connection,
                        **request_audit(
                            request,
                            actor_id=str(user_id),
                            action="ASPIS_AUDITOR_REQUESTED",
                            resource_type="aspis_auditor_request",
                            resource_id=str(approval_request_id),
                            metadata={"requested_role": ROLE_ASPIS_AUDITOR},
                        ),
                    )
        except errors.UniqueViolation:
            # Keep duplicate-address behavior indistinguishable from a new
            # account, including the expensive password-hash work above.
            LOGGER.info(
                "Aspis auditor registration accepted for existing identity",
                extra={"request_id": str(request_id(request))},
            )
        return {
            "status": "accepted",
            "message": (
                "If eligible, your Aspis auditor request is awaiting "
                "administrator approval."
            ),
        }

    @app.post("/v1/auth/login")
    def login(input: LoginRequest, request: Request, response: Response):
        email = input.email.strip().lower()
        enforce_auth_rate_limit(request, "login", email)
        pool = request.app.state.database.pool
        with pool.connection() as connection:
            user = connection.execute(
                """
                SELECT user_id, customer_id, role, password_hash, status
                FROM user_accounts WHERE email = %s
                """,
                (email,),
            ).fetchone()
            password_hash = password_hash_for_check(
                user["password_hash"] if user else None
            )
            password_valid = check_password(password_hash, input.password)
            valid = bool(user and user["status"] == "ACTIVE" and password_valid)
            if not valid:
                audit.record(
                    connection,
                    **request_audit(
                        request,
                        actor_id=email,
                        action="LOGIN_FAILED",
                        resource_type="user_account",
                        resource_id=email,
                        metadata={"reason": "invalid_credentials"},
                    ),
                )
                raise BantamError(
                    "INVALID_CREDENTIALS", "email or password is incorrect", 401
                )
            if user["role"] == ROLE_PENDING_APPROVAL:
                audit.record(
                    connection,
                    **request_audit(
                        request,
                        actor_id=str(user["user_id"]),
                        action="LOGIN_BLOCKED_PENDING_APPROVAL",
                        resource_type="user_account",
                        resource_id=str(user["user_id"]),
                    ),
                )
                raise BantamError(
                    "APPROVAL_PENDING",
                    "Your Aspis auditor request is awaiting administrator approval.",
                    403,
                )

            principal = Principal(
                user_id=user["user_id"],
                customer_id=user["customer_id"],
                role=user["role"],
            )
            challenge = request.app.state.mfa.begin_login(connection, dict(user))
            if challenge:
                response.status_code = 202
                audit.record(
                    connection,
                    **request_audit(
                        request,
                        actor_id=str(principal.user_id),
                        action="LOGIN_PASSWORD_VERIFIED",
                        resource_type="user_account",
                        resource_id=str(principal.user_id),
                        metadata={"next_step": challenge["status"]},
                    ),
                )
                return challenge
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="LOGIN_SUCCEEDED",
                    resource_type="user_account",
                    resource_id=str(principal.user_id),
                    metadata={"amr": ["pwd"]},
                ),
            )
        return issue_session(
            request,
            response,
            principal,
            auth_methods=("pwd",),
        )

    @app.post("/v1/auth/mfa/setup")
    def setup_mfa(input: MfaSetupRequest, request: Request):
        enforce_auth_rate_limit(request, "mfa-setup", str(input.transaction_id))
        with request.app.state.database.pool.connection() as connection:
            return request.app.state.mfa.prepare_enrollment(
                connection,
                transaction_id=input.transaction_id,
                method=input.method,
                label=input.label,
            )

    @app.post("/v1/auth/mfa/passkey")
    def complete_passkey_mfa(
        input: MfaPasskeyRequest,
        request: Request,
        response: Response,
    ):
        enforce_auth_rate_limit(request, "mfa-passkey", str(input.transaction_id))
        with request.app.state.database.pool.connection() as connection:
            completion = request.app.state.mfa.complete_passkey(
                connection,
                transaction_id=input.transaction_id,
                credential=input.credential,
            )
        return finish_mfa_session(request, response, completion)

    @app.post("/v1/auth/mfa/totp")
    def complete_totp_mfa(
        input: MfaTotpRequest,
        request: Request,
        response: Response,
    ):
        enforce_auth_rate_limit(request, "mfa-totp", str(input.transaction_id))
        with request.app.state.database.pool.connection() as connection:
            completion = request.app.state.mfa.complete_totp(
                connection,
                transaction_id=input.transaction_id,
                code=input.code,
            )
        return finish_mfa_session(request, response, completion)

    @app.get("/v1/me/mfa")
    def mfa_state(principal: MfaPrincipal, request: Request):
        with request.app.state.database.pool.connection() as connection:
            return request.app.state.mfa.describe(
                connection,
                principal.user_id,
                principal.role,
            )

    @app.post("/v1/me/mfa/enrollment")
    def begin_mfa_enrollment(
        input: MfaEnrollmentRequest,
        principal: MfaPrincipal,
        request: Request,
    ):
        with request.app.state.database.pool.connection() as connection:
            user = connection.execute(
                """
                SELECT email, password_hash
                FROM user_accounts
                WHERE user_id = %s AND status = 'ACTIVE'
                """,
                (principal.user_id,),
            ).fetchone()
            identifier = user["email"] if user else str(principal.user_id)
            enforce_auth_rate_limit(request, "mfa-enroll", identifier)
            password_hash = password_hash_for_check(
                user["password_hash"] if user else None
            )
            if not check_password(password_hash, input.password):
                raise BantamError(
                    "INVALID_CREDENTIALS",
                    "Password verification failed.",
                    401,
                )
            transaction_id = request.app.state.mfa.begin_authenticated_enrollment(
                connection,
                user_id=principal.user_id,
                source_jti=request.state.access_token.jti,
                source_expires_at=request.state.access_token.expires_at,
            )
            setup = request.app.state.mfa.prepare_enrollment(
                connection,
                transaction_id=transaction_id,
                method=input.method,
                label=input.label,
            )
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="MFA_ENROLLMENT_STARTED",
                    resource_type="user_account",
                    resource_id=str(principal.user_id),
                    metadata={"method": input.method},
                ),
            )
        return setup

    @app.delete("/v1/me/mfa/passkeys/{credential_id}")
    def remove_passkey(
        credential_id: UUID,
        principal: MfaPrincipal,
        request: Request,
    ):
        require_recent_mfa(request)
        with request.app.state.database.pool.connection() as connection:
            request.app.state.mfa.remove_passkey(
                connection,
                user_id=principal.user_id,
                role=principal.role,
                credential_id=credential_id,
            )
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="MFA_FACTOR_REMOVED",
                    resource_type="webauthn_credential",
                    resource_id=str(credential_id),
                    metadata={"method": "passkey"},
                ),
            )
        return {"status": "removed"}

    @app.delete("/v1/me/mfa/totp")
    def remove_totp(principal: MfaPrincipal, request: Request):
        require_recent_mfa(request)
        with request.app.state.database.pool.connection() as connection:
            request.app.state.mfa.remove_totp(
                connection,
                user_id=principal.user_id,
                role=principal.role,
            )
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="MFA_FACTOR_REMOVED",
                    resource_type="totp_credential",
                    resource_id=str(principal.user_id),
                    metadata={"method": "totp"},
                ),
            )
        return {"status": "removed"}

    @app.post("/v1/auth/logout")
    def logout(principal: AnyPrincipal, request: Request, response: Response):
        with request.app.state.database.pool.connection() as connection:
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="LOGOUT_SUCCEEDED",
                    resource_type="user_account",
                    resource_id=str(principal.user_id),
                ),
            )
            revoke_access_token(connection, request.state.access_token)
        response.delete_cookie(SESSION_COOKIE_NAME, path="/")
        response.delete_cookie(CSRF_COOKIE_NAME, path="/")
        return {"status": "logged_out"}

    @app.get("/v1/me")
    def me(principal: AnyPrincipal, request: Request):
        with request.app.state.database.pool.connection() as connection:
            user = connection.execute(
                """
                SELECT u.user_id, u.email, u.role, u.status,
                       (
                           EXISTS (
                               SELECT 1 FROM webauthn_credentials w
                               WHERE w.user_id = u.user_id
                                 AND w.revoked_at IS NULL
                           )
                           OR EXISTS (
                               SELECT 1 FROM totp_credentials t
                               WHERE t.user_id = u.user_id
                                 AND t.revoked_at IS NULL
                           )
                       ) AS mfa_enabled,
                       c.customer_id, c.legal_name, c.kyc_status,
                       c.risk_rating, c.status AS customer_status
                FROM user_accounts u
                LEFT JOIN customers c ON c.customer_id = u.customer_id
                WHERE u.user_id = %s
                """,
                (principal.user_id,),
            ).fetchone()
            if not user:
                raise BantamError("NOT_FOUND", "user account was not found", 404)
            is_super_admin, admin_permissions = describe_admin_access(
                connection, request, principal
            )
        payload = dict(user)
        payload["is_super_admin"] = is_super_admin
        payload["admin_permissions"] = list(admin_permissions)
        return payload

    @app.post("/v1/me/kyc/submit")
    def submit_kyc(principal: CustomerPrincipal, request: Request):
        if principal.customer_id is None:
            raise FORBIDDEN()
        with request.app.state.database.pool.connection() as connection:
            updated = connection.execute(
                """
                UPDATE customers
                SET kyc_status = 'PENDING_REVIEW', updated_at = now()
                WHERE customer_id = %s
                  AND kyc_status IN ('PENDING_KYC', 'KYC_REJECTED')
                RETURNING customer_id
                """,
                (principal.customer_id,),
            ).fetchone()
            if not updated:
                raise BantamError(
                    "INVALID_KYC_STATE",
                    "KYC cannot be submitted in its current state",
                    409,
                )
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="KYC_SUBMITTED",
                    resource_type="customer",
                    resource_id=str(principal.customer_id),
                ),
            )
        return {"kyc_status": KYC_REVIEW}

    register_account_routes(app)
    register_transfer_routes(app)
    register_admin_routes(app)
    register_operations_routes(app)


def register_account_routes(app: FastAPI) -> None:
    @app.get("/v1/accounts")
    def list_accounts(principal: CustomerPrincipal, request: Request):
        if principal.customer_id is None:
            raise FORBIDDEN()
        with request.app.state.database.pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT a.account_id, a.customer_id, a.account_reference,
                       a.account_type, a.currency, a.status,
                       b.current_balance_minor AS balance_minor, a.opened_at
                FROM bank_accounts a
                JOIN account_balances b USING (account_id)
                WHERE a.customer_id = %s
                ORDER BY a.opened_at
                """,
                (principal.customer_id,),
            ).fetchall()
        return {"accounts": [dict(row) for row in rows]}

    @app.post("/v1/accounts", status_code=201)
    def open_account(
        input: OpenAccountRequest, principal: CustomerPrincipal, request: Request
    ):
        if principal.customer_id is None:
            raise FORBIDDEN()
        currency = input.currency.strip().upper() or "GBP"
        if currency != "GBP":
            raise validation("only GBP is supported in V1", "UNSUPPORTED_CURRENCY")

        pool = request.app.state.database.pool
        with pool.connection() as connection:
            customer = connection.execute(
                "SELECT kyc_status, status FROM customers WHERE customer_id = %s",
                (principal.customer_id,),
            ).fetchone()
            if not customer:
                raise BantamError("NOT_FOUND", "customer profile was not found", 404)
            if customer["kyc_status"] != KYC_VERIFIED or customer["status"] != "ACTIVE":
                raise BantamError(
                    "KYC_NOT_VERIFIED",
                    "an active, KYC-verified customer is required",
                    422,
                )

            account_id = uuid4()
            reference = "XB-" + account_id.hex[:12].upper()
            reference_hash = hashlib.sha256(reference.encode()).hexdigest()
            opened_at = datetime.now(UTC)
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO bank_accounts (
                        account_id, customer_id, account_number_hash,
                        account_reference, account_type, currency, status,
                        opened_at
                    ) VALUES (%s,%s,%s,%s,'CURRENT',%s,'ACTIVE',%s)
                    """,
                    (
                        account_id,
                        principal.customer_id,
                        reference_hash,
                        reference,
                        currency,
                        opened_at,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO account_balances (
                        account_id, available_balance_minor,
                        current_balance_minor, currency
                    ) VALUES (%s,0,0,%s)
                    """,
                    (account_id, currency),
                )
                connection.execute(
                    """
                    INSERT INTO outbox_events (
                        outbox_event_id, aggregate_type, aggregate_id,
                        event_type, event_version, payload
                    ) VALUES (%s,'account',%s,'account.opened.v1',1,%s)
                    """,
                    (
                        uuid4(),
                        account_id,
                        Jsonb(
                            {
                                "account_id": str(account_id),
                                "customer_id": str(principal.customer_id),
                                "currency": currency,
                            }
                        ),
                    ),
                )
                audit.record(
                    connection,
                    **request_audit(
                        request,
                        actor_id=str(principal.user_id),
                        action="ACCOUNT_OPENED",
                        resource_type="bank_account",
                        resource_id=str(account_id),
                    ),
                )
        return {
            "account_id": account_id,
            "customer_id": principal.customer_id,
            "account_reference": reference,
            "account_type": "CURRENT",
            "currency": currency,
            "status": "ACTIVE",
            "balance_minor": 0,
            "opened_at": opened_at,
        }

    @app.get("/v1/accounts/{account_id}")
    def get_account(account_id: UUID, principal: CustomerPrincipal, request: Request):
        if principal.customer_id is None:
            raise FORBIDDEN()
        with request.app.state.database.pool.connection() as connection:
            account = connection.execute(
                """
                SELECT a.account_id, a.customer_id, a.account_reference,
                       a.account_type, a.currency, a.status,
                       b.current_balance_minor AS balance_minor, a.opened_at
                FROM bank_accounts a
                JOIN account_balances b USING (account_id)
                WHERE a.account_id = %s AND a.customer_id = %s
                """,
                (account_id, principal.customer_id),
            ).fetchone()
        if not account:
            raise BantamError("NOT_FOUND", "account was not found", 404)
        return dict(account)

    @app.get("/v1/accounts/{account_id}/transactions")
    def list_account_transactions(
        account_id: UUID, principal: CustomerPrincipal, request: Request
    ):
        if principal.customer_id is None:
            raise FORBIDDEN()
        with request.app.state.database.pool.connection() as connection:
            account = connection.execute(
                """
                SELECT 1 FROM bank_accounts
                WHERE account_id = %s AND customer_id = %s
                """,
                (account_id, principal.customer_id),
            ).fetchone()
            if not account:
                raise BantamError("NOT_FOUND", "account was not found", 404)
            rows = connection.execute(
                sql.SQL(
                    """
                SELECT {}
                FROM transactions
                WHERE source_account_id = %s OR destination_account_id = %s
                ORDER BY created_at DESC
                LIMIT %s
                """
                ).format(TRANSACTION_PROJECTION),
                (account_id, account_id, query_limit(request, 50, 100)),
            ).fetchall()
        return {"transactions": [transaction_payload(row) for row in rows]}

    @app.get("/v1/notifications")
    def list_notifications(principal: CustomerPrincipal, request: Request):
        if principal.customer_id is None:
            raise FORBIDDEN()
        with request.app.state.database.pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT notification_id, notification_type AS type, subject,
                       body, created_at, read_at
                FROM notifications
                WHERE customer_id = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (principal.customer_id, query_limit(request, 50, 100)),
            ).fetchall()
        return {"notifications": [dict(row) for row in rows]}

    @app.post("/v1/claims/account-status")
    def account_status_claim(principal: CustomerPrincipal, request: Request):
        if principal.customer_id is None:
            raise FORBIDDEN()
        with request.app.state.database.pool.connection() as connection:
            customer = connection.execute(
                """
                SELECT c.kyc_status,
                       EXISTS (
                           SELECT 1 FROM bank_accounts a
                           WHERE a.customer_id = c.customer_id
                             AND a.status = 'ACTIVE'
                       ) AS has_active_account
                FROM customers c WHERE c.customer_id = %s
                """,
                (principal.customer_id,),
            ).fetchone()
            if not customer:
                raise BantamError("NOT_FOUND", "customer profile was not found", 404)
            claim_id = uuid4()
            kyc_status = customer["kyc_status"].removeprefix("KYC_").lower()
            proof_jwt, valid_until = request.app.state.claims.issue_account_status(
                claim_id=claim_id,
                customer_id=principal.customer_id,
                has_active_account=customer["has_active_account"],
                kyc_status=kyc_status,
            )
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="FEDERATION_CLAIM_ISSUED",
                    resource_type="claim",
                    resource_id=str(claim_id),
                    metadata={"claim_type": "bank_account_status"},
                ),
            )
        return {
            "claim_id": claim_id,
            "issuer": "did:xbank:bantam",
            "subject_id": f"did:xid:person:{principal.customer_id}",
            "claim_type": "bank_account_status",
            "has_active_account": customer["has_active_account"],
            "kyc_status": kyc_status,
            "valid_until": valid_until,
            "proof_format": "JWS compact serialization (HS256 demo trust domain)",
            "proof_jwt": proof_jwt,
        }


def register_transfer_routes(app: FastAPI) -> None:
    @app.post("/v1/sca/challenges", status_code=201)
    def create_sca_challenge(
        input: SCAChallengeRequest,
        principal: CustomerPrincipal,
        request: Request,
    ):
        enforce_auth_rate_limit(request, "sca-challenge", str(principal.user_id))
        challenge = request.app.state.sca.create(
            request.app.state.database.pool,
            principal,
            input.source_account_id,
            input.destination_account_id,
            input.amount_minor,
        )
        action = "SCA_NOT_REQUIRED"
        resource_id = str(input.source_account_id)
        if challenge["required"]:
            action = "SCA_CHALLENGE_CREATED"
            resource_id = str(challenge["challenge_id"])
        with request.app.state.database.pool.connection() as connection:
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action=action,
                    resource_type="sca_challenge",
                    resource_id=resource_id,
                    metadata={
                        "source_account_id": str(input.source_account_id),
                        "destination_account_id": str(input.destination_account_id),
                        "amount_minor": input.amount_minor,
                    },
                ),
            )
        return challenge

    @app.post("/v1/transfers", status_code=201)
    def create_transfer(
        input: TransferRequest,
        response: Response,
        principal: CustomerPrincipal,
        request: Request,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ):
        idempotency_key = require_idempotency_key(idempotency_key)
        if request.app.state.sca.required(input.amount_minor):
            enforce_auth_rate_limit(request, "sca-verify", str(principal.user_id))
        command = TransferCommand(
            request_id=request_id(request),
            idempotency_key=idempotency_key,
            actor=principal,
            source_account_id=input.source_account_id,
            destination_account_id=input.destination_account_id,
            amount_minor=input.amount_minor,
            currency=input.currency,
            description=input.description,
            sca_challenge_id=input.sca_challenge_id,
            sca_code=input.sca_code,
        )
        try:
            transaction, replayed = request.app.state.ledger.create_transfer(command)
        except BantamError as error:
            with request.app.state.database.pool.connection() as connection:
                audit.record(
                    connection,
                    **request_audit(
                        request,
                        actor_id=str(principal.user_id),
                        action="TRANSFER_FAILED",
                        resource_type="bank_account",
                        resource_id=str(input.source_account_id),
                        metadata={
                            "destination_account_id": str(input.destination_account_id),
                            "amount_minor": input.amount_minor,
                            "reason": error.message,
                        },
                    ),
                )
            raise
        if replayed:
            response.status_code = 200
            response.headers["Idempotent-Replayed"] = "true"
        return transaction

    @app.get("/v1/transfers/{transaction_id}")
    def get_transfer(
        transaction_id: UUID,
        principal: CustomerPrincipal,
        request: Request,
    ):
        if principal.customer_id is None:
            raise FORBIDDEN()
        with request.app.state.database.pool.connection() as connection:
            transaction = connection.execute(
                sql.SQL(
                    """
                SELECT {}
                FROM transactions t
                JOIN bank_accounts source
                  ON source.account_id = t.source_account_id
                JOIN bank_accounts destination
                  ON destination.account_id = t.destination_account_id
                WHERE t.transaction_id = %s
                  AND (source.customer_id = %s OR destination.customer_id = %s)
                """
                ).format(ALIASED_TRANSACTION_PROJECTION),
                (transaction_id, principal.customer_id, principal.customer_id),
            ).fetchone()
        if not transaction:
            raise BantamError("NOT_FOUND", "transaction was not found", 404)
        return transaction_payload(transaction)


def register_admin_routes(app: FastAPI) -> None:
    @app.get("/v1/admin/users")
    def admin_list_users(principal: AdminPrincipal, request: Request):
        require_admin_scope(request, principal, "admin_users")
        with request.app.state.database.pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT u.user_id, u.email, u.role, u.status,
                       (
                           EXISTS (
                               SELECT 1 FROM webauthn_credentials w
                               WHERE w.user_id = u.user_id
                                 AND w.revoked_at IS NULL
                           )
                           OR EXISTS (
                               SELECT 1 FROM totp_credentials t
                               WHERE t.user_id = u.user_id
                                 AND t.revoked_at IS NULL
                           )
                       ) AS mfa_enabled,
                       COALESCE(
                           array_remove(array_agg(p.scope ORDER BY p.scope), NULL),
                           ARRAY[]::text[]
                       ) AS permissions,
                       u.created_at
                FROM user_accounts u
                LEFT JOIN admin_permissions p ON p.user_id = u.user_id
                WHERE u.role = %s
                GROUP BY u.user_id, u.email, u.role, u.status, u.created_at
                ORDER BY u.created_at DESC
                LIMIT %s
                """,
                (ROLE_BANK_ADMIN, query_limit(request, 100, 250)),
            ).fetchall()
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="ADMIN_VIEWED_USERS",
                    resource_type="user_account_collection",
                    resource_id="bank_admins",
                ),
            )
        return {
            "users": [
                admin_user_payload(dict(row), request.app.state.settings)
                for row in rows
            ],
            "available_permissions": list(ADMIN_PERMISSION_SCOPES),
        }

    @app.post("/v1/admin/users", status_code=201)
    def admin_create_user(
        input: AdminUserCreateRequest,
        principal: AdminPrincipal,
        request: Request,
    ):
        require_recent_mfa(request)
        require_admin_scope(request, principal, "admin_users")
        email = input.email.strip().lower()
        if not EMAIL_PATTERN.fullmatch(email):
            raise validation("email is invalid")
        requested_permissions = set(input.permissions)
        permissions = tuple(
            scope for scope in ADMIN_PERMISSION_SCOPES if scope in requested_permissions
        )
        if len(permissions) != len(requested_permissions):
            raise validation("permissions include an unsupported scope")
        if not permissions:
            raise validation("at least one permission is required")
        try:
            password_hash = hash_password(
                input.password,
                disallowed_values=(email, "bank admin"),
            )
        except ValueError as error:
            raise validation(str(error)) from error

        user_id = uuid4()
        try:
            with request.app.state.database.pool.connection() as connection:
                with connection.transaction():
                    created = connection.execute(
                        """
                        INSERT INTO user_accounts (
                            user_id, email, password_hash, role, customer_id,
                            mfa_enabled
                        ) VALUES (%s,%s,%s,%s,NULL,false)
                        RETURNING user_id, email, role, status, mfa_enabled, created_at
                        """,
                        (user_id, email, password_hash, ROLE_BANK_ADMIN),
                    ).fetchone()
                    for scope in permissions:
                        connection.execute(
                            """
                            INSERT INTO admin_permissions (
                                user_id, scope, granted_by
                            ) VALUES (%s,%s,%s)
                            """,
                            (user_id, scope, principal.user_id),
                        )
                    audit.record(
                        connection,
                        **request_audit(
                            request,
                            actor_id=str(principal.user_id),
                            action="ADMIN_USER_CREATED",
                            resource_type="user_account",
                            resource_id=str(user_id),
                            metadata={
                                "subject_email": email,
                                "permissions": list(permissions),
                            },
                        ),
                    )
        except errors.UniqueViolation as error:
            raise BantamError(
                "EMAIL_EXISTS",
                "email already belongs to an account",
                409,
            ) from error

        payload = dict(created)
        payload["permissions"] = list(permissions)
        return admin_user_payload(payload, request.app.state.settings)

    @app.get("/v1/admin/workflow-graph")
    def admin_workflow_graph(principal: AdminPrincipal, request: Request):
        require_admin_scope(request, principal, "workflows")
        return request.app.state.workflow_graph.overview()

    @app.post("/v1/admin/workflows/validate")
    def admin_validate_workflow(
        input: WorkflowDefinitionRequest,
        principal: AdminPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "workflows")
        return request.app.state.workflow_graph.validate(input.model_dump())

    @app.post("/v1/admin/workflows", status_code=201)
    def admin_create_workflow(
        input: WorkflowDefinitionRequest,
        principal: AdminPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "workflows")
        return request.app.state.workflow_graph.create(
            input.model_dump(),
            created_by=principal.user_id,
            audit_fields=request_audit(
                request,
                actor_id=str(principal.user_id),
                action="WORKFLOW_CREATED",
                resource_type="workflow_definition",
                resource_id="pending",
            ),
        )

    @app.get("/v1/admin/repository-graphs")
    def list_repository_graphs(principal: AdminPrincipal, request: Request):
        require_admin_scope(request, principal, "workflows")
        return request.app.state.repository_graph.sources()

    @app.post("/v1/admin/repository-graphs", status_code=201)
    def generate_repository_graph(
        input: RepositoryGraphRequest,
        principal: AdminPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "workflows")
        return request.app.state.repository_graph.generate(
            input.model_dump(),
            created_by=principal.user_id,
            audit_fields=request_audit(
                request,
                actor_id=str(principal.user_id),
                action="REPOSITORY_GRAPH_GENERATED",
                resource_type="repository_graph_snapshot",
                resource_id="pending",
            ),
        )

    @app.get("/v1/admin/repository-graphs/{snapshot_id}")
    def get_repository_graph(
        snapshot_id: UUID,
        principal: AdminPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "workflows")
        return request.app.state.repository_graph.get(snapshot_id)

    @app.post("/v1/admin/repository-graphs/{snapshot_id}/workflows/validate")
    def validate_repository_workflow(
        snapshot_id: UUID,
        input: RepositoryWorkflowDefinitionRequest,
        principal: AdminPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "workflows")
        return request.app.state.repository_graph.validate_workflow(
            snapshot_id, input.model_dump()
        )

    @app.post(
        "/v1/admin/repository-graphs/{snapshot_id}/workflows",
        status_code=201,
    )
    def create_repository_workflow(
        snapshot_id: UUID,
        input: RepositoryWorkflowDefinitionRequest,
        principal: AdminPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "workflows")
        return request.app.state.repository_graph.create_workflow(
            snapshot_id,
            input.model_dump(),
            created_by=principal.user_id,
            audit_fields=request_audit(
                request,
                actor_id=str(principal.user_id),
                action="WORKFLOW_CREATED",
                resource_type="workflow_definition",
                resource_id="pending",
            ),
        )

    @app.get("/v1/admin/company-financials")
    def admin_company_financials(principal: OperatorPrincipal, request: Request):
        require_admin_scope(request, principal, "company_financials")
        return request.app.state.company_financials.overview()

    @app.post("/v1/admin/company-financials", status_code=201)
    def admin_update_company_financials(
        input: CompanyFinancialsRequest,
        principal: AdminPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "company_financials")
        return request.app.state.company_financials.update(
            input.model_dump(),
            created_by=principal.user_id,
            audit_fields=request_audit(
                request,
                actor_id=str(principal.user_id),
                action="COMPANY_FINANCIALS_UPDATED",
                resource_type="company_financial_profile",
                resource_id="pending",
            ),
        )

    @app.get("/v1/admin/attack-scenarios")
    def list_attack_scenarios(principal: OperatorPrincipal, request: Request):
        require_admin_scope(request, principal, "attack_lab")
        return request.app.state.attack_simulation.overview()

    @app.post("/v1/admin/attack-scenarios", status_code=201)
    def generate_attack_scenarios(
        input: AttackScenarioRequest,
        principal: OperatorPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "attack_lab")
        payload = input.model_dump()
        payload["snapshot_id"] = (
            str(payload["snapshot_id"]) if payload["snapshot_id"] else None
        )
        return request.app.state.attack_simulation.generate_scenarios(
            payload,
            created_by=principal.user_id,
            audit_fields=request_audit(
                request,
                actor_id=str(principal.user_id),
                action="ATTACK_SCENARIOS_GENERATED",
                resource_type="attack_scenario_set",
                resource_id="pending",
            ),
        )

    @app.get("/v1/admin/attack-scenarios/{scenario_set_id}")
    def get_attack_scenarios(
        scenario_set_id: UUID,
        principal: OperatorPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "attack_lab")
        return request.app.state.attack_simulation.get(scenario_set_id)

    @app.post(
        "/v1/admin/attack-scenarios/{scenario_set_id}/simulations",
        status_code=201,
    )
    def run_attack_simulation(
        scenario_set_id: UUID,
        input: AttackSimulationRequest,
        principal: OperatorPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "attack_lab")
        return request.app.state.attack_simulation.simulate(
            scenario_set_id,
            input.model_dump(),
            created_by=principal.user_id,
            audit_fields=request_audit(
                request,
                actor_id=str(principal.user_id),
                action="ATTACK_SIMULATION_RUN",
                resource_type="attack_simulation",
                resource_id="pending",
            ),
        )

    @app.post(
        "/v1/admin/attack-scenarios/{scenario_set_id}"
        "/simulations/{simulation_id}/remediations",
        status_code=201,
    )
    def generate_attack_remediations(
        scenario_set_id: UUID,
        simulation_id: UUID,
        principal: OperatorPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "attack_lab")
        return request.app.state.attack_simulation.remediate(
            scenario_set_id,
            simulation_id,
            created_by=principal.user_id,
            audit_fields=request_audit(
                request,
                actor_id=str(principal.user_id),
                action="ATTACK_REMEDIATIONS_GENERATED",
                resource_type="attack_remediation_plan",
                resource_id="pending",
            ),
        )

    @app.get("/v1/admin/aspis-auditor-requests")
    def list_aspis_auditor_requests(
        principal: AspisAdminPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "aspis_auditors")
        with request.app.state.database.pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT r.request_id, r.status, r.requested_at, r.decided_at,
                       r.decision_reason, u.email
                FROM aspis_auditor_requests r
                JOIN user_accounts u ON u.user_id = r.user_id
                ORDER BY
                    CASE WHEN r.status = 'PENDING' THEN 0 ELSE 1 END,
                    r.requested_at
                LIMIT %s
                """,
                (query_limit(request, 100, 250),),
            ).fetchall()
        return {"requests": [dict(row) for row in rows]}

    @app.post("/v1/admin/aspis-auditor-requests/{approval_request_id}/decision")
    def decide_aspis_auditor_request(
        approval_request_id: UUID,
        input: AspisAuditorDecisionRequest,
        principal: AspisAdminPrincipal,
        request: Request,
    ):
        require_recent_mfa(request)
        require_admin_scope(request, principal, "aspis_auditors")
        reason = input.reason.strip()
        if input.decision == "REJECT" and not reason:
            raise validation("A reason is required when rejecting an auditor.")
        with request.app.state.database.pool.connection() as connection:
            with connection.transaction():
                approval = connection.execute(
                    """
                    SELECT r.request_id, r.user_id, r.status, u.email
                    FROM aspis_auditor_requests r
                    JOIN user_accounts u ON u.user_id = r.user_id
                    WHERE r.request_id = %s
                    FOR UPDATE OF r, u
                    """,
                    (approval_request_id,),
                ).fetchone()
                if not approval:
                    raise BantamError(
                        "NOT_FOUND",
                        "Auditor request was not found.",
                        404,
                    )
                if approval["status"] != "PENDING":
                    raise BantamError(
                        "INVALID_APPROVAL_STATE",
                        "This auditor request was already decided.",
                        409,
                    )
                if input.decision == "APPROVE":
                    updated = connection.execute(
                        """
                        UPDATE user_accounts
                        SET role = %s, status = 'ACTIVE', updated_at = now()
                        WHERE user_id = %s AND role = %s
                        RETURNING user_id
                        """,
                        (
                            ROLE_ASPIS_AUDITOR,
                            approval["user_id"],
                            ROLE_PENDING_APPROVAL,
                        ),
                    ).fetchone()
                    next_status = "APPROVED"
                else:
                    updated = connection.execute(
                        """
                        UPDATE user_accounts
                        SET status = 'DISABLED', updated_at = now()
                        WHERE user_id = %s AND role = %s
                        RETURNING user_id
                        """,
                        (approval["user_id"], ROLE_PENDING_APPROVAL),
                    ).fetchone()
                    next_status = "REJECTED"
                if not updated:
                    raise BantamError(
                        "INVALID_APPROVAL_STATE",
                        "The applicant account is no longer pending.",
                        409,
                    )
                connection.execute(
                    """
                    UPDATE aspis_auditor_requests
                    SET status = %s, decided_by = %s,
                        decision_reason = %s, decided_at = now()
                    WHERE request_id = %s
                    """,
                    (
                        next_status,
                        principal.user_id,
                        reason or None,
                        approval_request_id,
                    ),
                )
                audit.record(
                    connection,
                    **request_audit(
                        request,
                        actor_id=str(principal.user_id),
                        action=f"ASPIS_AUDITOR_{next_status}",
                        resource_type="aspis_auditor_request",
                        resource_id=str(approval_request_id),
                        metadata={
                            "subject_user_id": str(approval["user_id"]),
                            "reason": reason or None,
                        },
                    ),
                )
        return {
            "request_id": approval_request_id,
            "status": next_status,
            "email": approval["email"],
        }

    @app.get("/v1/admin/asvs")
    def admin_asvs_overview(principal: AspisPrincipal, request: Request):
        require_admin_scope(request, principal, "asvs")
        overview = request.app.state.asvs.overview(
            query_limit(request, fallback=10, maximum=25)
        )
        overview["ai_generator"] = request.app.state.asvs_ai.overview(
            principal.user_id,
            request.state.access_token.jti,
        )
        latest = overview["latest_run"]
        with request.app.state.database.pool.connection() as connection:
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="ASVS_EVIDENCE_VIEWED",
                    resource_type="asvs_evidence",
                    resource_id=(
                        str(latest["run_id"]) if isinstance(latest, dict) else "catalog"
                    ),
                    metadata={
                        "runner_enabled": overview["runner_enabled"],
                        "latest_status": (
                            latest["status"] if isinstance(latest, dict) else None
                        ),
                    },
                ),
            )
        return overview

    @app.post("/v1/admin/asvs/runs", status_code=201)
    def admin_run_asvs(principal: AspisPrincipal, request: Request):
        require_admin_scope(request, principal, "asvs")
        return request.app.state.asvs.execute(
            principal.user_id,
            request_audit(
                request,
                actor_id=str(principal.user_id),
                action="ASVS_VERIFICATION_EXECUTED",
                resource_type="asvs_run",
                resource_id="pending",
            ),
        )

    @app.post("/v1/admin/asvs/test-plans", status_code=201)
    def admin_generate_asvs_test_plan(
        principal: AspisPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "asvs")
        return request.app.state.asvs_ai.generate(
            principal.user_id,
            request.state.access_token.jti,
            request_audit(
                request,
                actor_id=str(principal.user_id),
                action="ASVS_AI_TEST_PLAN_REQUESTED",
                resource_type="asvs_ai_test_plan",
                resource_id="pending",
            ),
            request.app.openapi(),
        )

    @app.post(
        "/v1/admin/asvs/test-plans/{generation_id}/execute",
        status_code=201,
    )
    def admin_execute_asvs_test_plan(
        generation_id: UUID,
        principal: AspisPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "asvs")
        return request.app.state.asvs_ai.approve_and_execute(
            generation_id,
            principal.user_id,
            request.state.access_token.jti,
            request_audit(
                request,
                actor_id=str(principal.user_id),
                action="ASVS_VERIFICATION_EXECUTED",
                resource_type="asvs_run",
                resource_id="pending",
            ),
            request.app.state.asvs,
        )

    @app.get("/v1/admin/customers")
    def admin_list_customers(principal: AdminPrincipal, request: Request):
        require_admin_scope(request, principal, "customers")
        with request.app.state.database.pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT customer_id, legal_name, date_of_birth, email, phone,
                       kyc_status, risk_rating, status, created_at
                FROM customers
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (query_limit(request, 100, 250),),
            ).fetchall()
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="ADMIN_VIEWED_CUSTOMERS",
                    resource_type="customer_collection",
                    resource_id="customers",
                ),
            )
        return {"customers": [dict(row) for row in rows]}

    @app.patch("/v1/admin/customers/{customer_id}/kyc")
    def admin_decide_kyc(
        customer_id: UUID,
        input: KYCDecisionRequest,
        principal: AdminPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "customers")
        decision = input.decision.strip().upper()
        if decision in {"APPROVE", KYC_VERIFIED}:
            decision = KYC_VERIFIED
            event_type = "customer.kyc_verified.v1"
        elif decision in {"REJECT", KYC_REJECTED}:
            decision = KYC_REJECTED
            event_type = "customer.kyc_rejected.v1"
        else:
            raise validation("decision must be APPROVE or REJECT", "INVALID_DECISION")

        with request.app.state.database.pool.connection() as connection:
            with connection.transaction():
                updated = connection.execute(
                    """
                    UPDATE customers
                    SET kyc_status = %s, updated_at = now()
                    WHERE customer_id = %s AND kyc_status = 'PENDING_REVIEW'
                    RETURNING customer_id
                    """,
                    (decision, customer_id),
                ).fetchone()
                if not updated:
                    raise BantamError(
                        "INVALID_KYC_STATE",
                        "customer must be pending KYC review",
                        409,
                    )
                connection.execute(
                    """
                    INSERT INTO outbox_events (
                        outbox_event_id, aggregate_type, aggregate_id,
                        event_type, event_version, payload
                    ) VALUES (%s,'customer',%s,%s,1,%s)
                    """,
                    (
                        uuid4(),
                        customer_id,
                        event_type,
                        Jsonb(
                            {
                                "customer_id": str(customer_id),
                                "kyc_status": decision,
                            }
                        ),
                    ),
                )
                audit.record(
                    connection,
                    **request_audit(
                        request,
                        actor_id=str(principal.user_id),
                        action="KYC_DECIDED",
                        resource_type="customer",
                        resource_id=str(customer_id),
                        metadata={
                            "decision": decision,
                            "reason": input.reason,
                        },
                    ),
                )
        return {"kyc_status": decision}

    @app.patch("/v1/admin/accounts/{account_id}/status")
    def operator_set_account_status(
        account_id: UUID,
        input: AccountStatusRequest,
        principal: OperatorPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "transactions")
        status = input.status.strip().upper()
        if status not in {ACCOUNT_ACTIVE, ACCOUNT_FROZEN}:
            raise validation("status must be ACTIVE or FROZEN", "INVALID_STATUS")
        event_type = (
            "account.frozen.v1" if status == ACCOUNT_FROZEN else "account.unfrozen.v1"
        )
        action = "ACCOUNT_FROZEN" if status == ACCOUNT_FROZEN else "ACCOUNT_UNFROZEN"
        with request.app.state.database.pool.connection() as connection:
            with connection.transaction():
                updated = connection.execute(
                    """
                    UPDATE bank_accounts SET status = %s
                    WHERE account_id = %s
                      AND account_type = 'CURRENT'
                      AND status <> 'CLOSED'
                    RETURNING account_id
                    """,
                    (status, account_id),
                ).fetchone()
                if not updated:
                    raise BantamError("NOT_FOUND", "account was not found", 404)
                connection.execute(
                    """
                    INSERT INTO outbox_events (
                        outbox_event_id, aggregate_type, aggregate_id,
                        event_type, event_version, payload
                    ) VALUES (%s,'account',%s,%s,1,%s)
                    """,
                    (
                        uuid4(),
                        account_id,
                        event_type,
                        Jsonb(
                            {
                                "account_id": str(account_id),
                                "status": status,
                                "reason": input.reason,
                            }
                        ),
                    ),
                )
                audit.record(
                    connection,
                    **request_audit(
                        request,
                        actor_id=str(principal.user_id),
                        action=action,
                        resource_type="bank_account",
                        resource_id=str(account_id),
                        metadata={"reason": input.reason},
                    ),
                )
        return {"status": status}

    @app.post("/v1/admin/accounts/{account_id}/demo-deposit", status_code=201)
    def admin_demo_deposit(
        account_id: UUID,
        input: DemoDepositRequest,
        response: Response,
        principal: AdminPrincipal,
        request: Request,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ):
        require_admin_scope(request, principal, "transactions")
        idempotency_key = require_idempotency_key(idempotency_key)
        with request.app.state.database.pool.connection() as connection:
            system_account = connection.execute(
                """
                SELECT account_id FROM bank_accounts
                WHERE account_type = 'SYSTEM' AND currency = 'GBP'
                  AND status = 'ACTIVE'
                LIMIT 1
                """
            ).fetchone()
        if not system_account:
            raise BantamError(
                "SYSTEM_ACCOUNT_MISSING",
                "run the seed command to create the demo treasury account",
                409,
            )
        transaction, replayed = request.app.state.ledger.create_transfer(
            TransferCommand(
                request_id=request_id(request),
                idempotency_key=idempotency_key,
                actor=principal,
                source_account_id=system_account["account_id"],
                destination_account_id=account_id,
                amount_minor=input.amount_minor,
                currency=input.currency or "GBP",
                description=input.description,
                operator_override=True,
                transaction_type="DEMO_DEPOSIT",
            )
        )
        if replayed:
            response.status_code = 200
            response.headers["Idempotent-Replayed"] = "true"
        return transaction

    @app.post("/v1/admin/transactions/{transaction_id}/reverse", status_code=201)
    def admin_reverse_transaction(
        transaction_id: UUID,
        input: ReverseRequest,
        response: Response,
        principal: AdminPrincipal,
        request: Request,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ):
        require_admin_scope(request, principal, "transactions")
        idempotency_key = require_idempotency_key(idempotency_key)
        with request.app.state.database.pool.connection() as connection:
            original = connection.execute(
                """
                SELECT source_account_id, destination_account_id,
                       amount_minor, currency, status
                FROM transactions WHERE transaction_id = %s
                """,
                (transaction_id,),
            ).fetchone()
        if not original:
            raise BantamError("NOT_FOUND", "transaction was not found", 404)
        if original["status"] != "POSTED":
            raise BantamError(
                "NOT_REVERSIBLE",
                "only posted transactions can be reversed",
                409,
            )
        reversal, replayed = request.app.state.ledger.create_transfer(
            TransferCommand(
                request_id=request_id(request),
                idempotency_key=idempotency_key,
                actor=principal,
                source_account_id=original["destination_account_id"],
                destination_account_id=original["source_account_id"],
                amount_minor=original["amount_minor"],
                currency=original["currency"],
                description=f"Reversal: {input.reason.strip()}",
                operator_override=True,
                transaction_type="REVERSAL",
                reverses_transaction_id=transaction_id,
            )
        )
        if replayed:
            response.status_code = 200
            response.headers["Idempotent-Replayed"] = "true"
        return reversal

    @app.get("/v1/admin/transactions")
    def operator_list_transactions(principal: OperatorPrincipal, request: Request):
        require_admin_scope(request, principal, "transactions")
        raw = request.query_params.get("min_amount_minor", "").strip()
        try:
            minimum = int(raw) if raw else 0
        except ValueError as error:
            raise BantamError(
                "INVALID_AMOUNT",
                "min_amount_minor must be a non-negative integer",
                400,
            ) from error
        if minimum < 0:
            raise BantamError(
                "INVALID_AMOUNT",
                "min_amount_minor must be a non-negative integer",
                400,
            )
        with request.app.state.database.pool.connection() as connection:
            rows = connection.execute(
                sql.SQL(
                    """
                SELECT {}
                FROM transactions
                WHERE amount_minor >= %s
                ORDER BY created_at DESC
                LIMIT %s
                """
                ).format(TRANSACTION_PROJECTION),
                (minimum, query_limit(request, 100, 250)),
            ).fetchall()
        return {"transactions": [transaction_payload(row) for row in rows]}


def register_operations_routes(app: FastAPI) -> None:
    @app.get("/v1/risk/alerts")
    def list_risk_alerts(principal: OperatorPrincipal, request: Request):
        require_admin_scope(request, principal, "risk")
        status = request.query_params.get("status", "OPEN").strip().upper()
        if status not in {"OPEN", "REVIEWED", "DISMISSED"}:
            raise BantamError(
                "INVALID_STATUS",
                "status must be OPEN, REVIEWED, or DISMISSED",
                400,
            )
        with request.app.state.database.pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT risk_alert_id, transaction_id, customer_id, rule_id,
                       severity, status, explanation, created_at,
                       reviewed_at, reviewed_by
                FROM risk_alerts
                WHERE status = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (status, query_limit(request, 100, 250)),
            ).fetchall()
        return {"alerts": [dict(row) for row in rows]}

    @app.post("/v1/risk/alerts", status_code=201)
    def create_manual_risk_alert(
        input: ManualRiskAlertRequest,
        principal: OperatorPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "risk")
        severity = input.severity.strip().upper()
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise validation(
                "severity must be LOW, MEDIUM, HIGH, or CRITICAL",
                "INVALID_SEVERITY",
            )
        explanation = input.explanation.strip()
        if not explanation:
            raise validation("explanation is required")

        alert_id = uuid4()
        with request.app.state.database.pool.connection() as connection:
            customer = connection.execute(
                """
                SELECT COALESCE(source.customer_id, destination.customer_id)
                    AS customer_id
                FROM transactions t
                JOIN bank_accounts source
                  ON source.account_id = t.source_account_id
                JOIN bank_accounts destination
                  ON destination.account_id = t.destination_account_id
                WHERE t.transaction_id = %s
                """,
                (input.transaction_id,),
            ).fetchone()
            if not customer:
                raise BantamError("NOT_FOUND", "transaction was not found", 404)
            try:
                connection.execute(
                    """
                    INSERT INTO risk_alerts (
                        risk_alert_id, transaction_id, customer_id, rule_id,
                        severity, explanation
                    ) VALUES (%s,%s,%s,'MANUAL_REVIEW',%s,%s)
                    """,
                    (
                        alert_id,
                        input.transaction_id,
                        customer["customer_id"],
                        severity,
                        explanation,
                    ),
                )
            except errors.UniqueViolation as error:
                raise BantamError(
                    "ALERT_EXISTS",
                    "a manual alert already exists for this transaction",
                    409,
                ) from error
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="RISK_ALERT_CREATED",
                    resource_type="risk_alert",
                    resource_id=str(alert_id),
                    metadata={
                        "transaction_id": str(input.transaction_id),
                        "severity": severity,
                    },
                ),
            )
        return {"risk_alert_id": alert_id, "status": "OPEN"}

    @app.patch("/v1/risk/alerts/{alert_id}")
    def review_risk_alert(
        alert_id: UUID,
        input: ReviewRiskAlertRequest,
        principal: OperatorPrincipal,
        request: Request,
    ):
        require_admin_scope(request, principal, "risk")
        status = input.status.strip().upper()
        if status not in {"REVIEWED", "DISMISSED"}:
            raise validation("status must be REVIEWED or DISMISSED", "INVALID_STATUS")
        with request.app.state.database.pool.connection() as connection:
            updated = connection.execute(
                """
                UPDATE risk_alerts
                SET status = %s, reviewed_at = now(), reviewed_by = %s
                WHERE risk_alert_id = %s AND status = 'OPEN'
                RETURNING risk_alert_id
                """,
                (status, principal.user_id, alert_id),
            ).fetchone()
            if not updated:
                raise BantamError("INVALID_ALERT_STATE", "risk alert is not open", 409)
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="RISK_ALERT_REVIEWED",
                    resource_type="risk_alert",
                    resource_id=str(alert_id),
                    metadata={"status": status, "note": input.note},
                ),
            )
        return {"status": status}

    @app.get("/v1/audit/events")
    def list_audit_events(principal: AuditPrincipal, request: Request):
        require_admin_scope(request, principal, "audit")
        with request.app.state.database.pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT audit_event_id, actor_type, actor_id, action,
                       resource_type, resource_id, request_id, correlation_id,
                       ip_address::text AS ip_address, user_agent, metadata,
                       created_at
                FROM audit_events
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (query_limit(request, 100, 500),),
            ).fetchall()
        return {"events": [dict(row) for row in rows]}

    @app.post("/v1/reconciliation/runs")
    def run_reconciliation(principal: ReconcilePrincipal, request: Request):
        require_admin_scope(request, principal, "reconciliation")
        results = request.app.state.ledger.reconcile()
        mismatches = sum(1 for result in results if not result["matches"])
        with request.app.state.database.pool.connection() as connection:
            audit.record(
                connection,
                **request_audit(
                    request,
                    actor_id=str(principal.user_id),
                    action="RECONCILIATION_COMPLETED",
                    resource_type="ledger",
                    resource_id="all_accounts",
                    metadata={
                        "accounts_checked": len(results),
                        "mismatches": mismatches,
                    },
                ),
            )
        return {
            "status": "FAIL" if mismatches else "PASS",
            "accounts_checked": len(results),
            "mismatches": mismatches,
            "results": results,
        }
