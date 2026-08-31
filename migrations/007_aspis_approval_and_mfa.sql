-- Add approval-gated Aspis identities and real passkey/TOTP factor state.
ALTER TABLE user_accounts
    DROP CONSTRAINT user_accounts_role_check;

ALTER TABLE user_accounts
    ADD CONSTRAINT user_accounts_role_check
    CHECK (
        role IN (
            'CUSTOMER',
            'BANK_ADMIN',
            'RISK_ANALYST',
            'COMPLIANCE_AUDITOR',
            'ASPIS_AUDITOR',
            'ASPIS_ADMIN',
            'PENDING_APPROVAL',
            'SERVICE_ACCOUNT'
        )
    );

CREATE TABLE IF NOT EXISTS aspis_auditor_requests (
    request_id UUID PRIMARY KEY,
    user_id UUID NOT NULL UNIQUE
        REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    decided_by UUID REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    decision_reason TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ,
    CHECK (
        (status = 'PENDING' AND decided_by IS NULL AND decided_at IS NULL)
        OR (status <> 'PENDING' AND decided_by IS NOT NULL AND decided_at IS NOT NULL)
    )
);

-- Existing self-service auditors become pending instead of being grandfathered
-- into the new approval boundary.
INSERT INTO aspis_auditor_requests (request_id, user_id)
SELECT gen_random_uuid(), user_id
FROM user_accounts
WHERE role = 'ASPIS_AUDITOR'
ON CONFLICT (user_id) DO NOTHING;

UPDATE user_accounts
SET role = 'PENDING_APPROVAL', updated_at = now()
WHERE role = 'ASPIS_AUDITOR';

CREATE INDEX IF NOT EXISTS aspis_auditor_requests_status_requested_idx
    ON aspis_auditor_requests (status, requested_at);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    webauthn_credential_id UUID PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    transports TEXT[] NOT NULL DEFAULT '{}',
    device_type TEXT NOT NULL,
    backed_up BOOLEAN NOT NULL DEFAULT false,
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 80),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS webauthn_credentials_user_active_idx
    ON webauthn_credentials (user_id)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS totp_credentials (
    user_id UUID PRIMARY KEY
        REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    encrypted_secret BYTEA NOT NULL,
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 80),
    last_used_step BIGINT NOT NULL DEFAULT -1,
    confirmed_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS mfa_transactions (
    transaction_id UUID PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES user_accounts(user_id) ON DELETE CASCADE,
    purpose TEXT NOT NULL
        CHECK (
            purpose IN (
                'LOGIN',
                'ENROLL_CHOICE',
                'ENROLL_PASSKEY',
                'ENROLL_TOTP'
            )
        ),
    challenge BYTEA,
    pending_secret BYTEA,
    factor_label TEXT,
    source_jti UUID,
    source_expires_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0
        CHECK (attempts BETWEEN 0 AND 5),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (source_jti IS NULL AND source_expires_at IS NULL)
        OR (source_jti IS NOT NULL AND source_expires_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS mfa_transactions_user_expiry_idx
    ON mfa_transactions (user_id, expires_at);

-- The legacy flag is retained for API compatibility, but factor rows are the
-- authority from this migration onward.
UPDATE user_accounts SET mfa_enabled = false;
