-- Persist bounded AI test-plan attempts without storing provider credentials.
CREATE TABLE IF NOT EXISTS asvs_ai_generations (
    generation_id UUID PRIMARY KEY,
    initiated_by UUID NOT NULL REFERENCES user_accounts(user_id),
    session_jti UUID NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('PENDING', 'READY', 'EXECUTING', 'EXECUTED', 'FAILED')
    ),
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    catalog_version TEXT NOT NULL,
    target_commit TEXT NOT NULL,
    prompt_sha256 CHAR(64) NOT NULL,
    provenance JSONB NOT NULL,
    plan_sha256 CHAR(64),
    plan JSONB,
    compiled_pytest TEXT,
    provider_request_id TEXT,
    input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
    output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
    error_code TEXT,
    asvs_run_id UUID REFERENCES asvs_runs(run_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    CHECK (
        status IN ('PENDING', 'FAILED')
        OR (
            plan IS NOT NULL
            AND plan_sha256 IS NOT NULL
            AND compiled_pytest IS NOT NULL
        )
    ),
    CHECK (compiled_pytest IS NULL OR char_length(compiled_pytest) <= 50000),
    CHECK (octet_length(provenance::text) <= 262144)
);

CREATE INDEX IF NOT EXISTS idx_asvs_ai_generations_session
    ON asvs_ai_generations (session_jti, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_asvs_ai_generations_created
    ON asvs_ai_generations (created_at DESC);

COMMENT ON TABLE asvs_ai_generations IS
    'Quota reservations, redacted model-request provenance, and validated ASVS AI candidate plans; never stores tokens';
