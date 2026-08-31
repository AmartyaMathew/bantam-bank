CREATE TABLE IF NOT EXISTS session_revocations (
    jti UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES user_accounts(user_id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_session_revocations_user
    ON session_revocations (user_id, revoked_at DESC);

CREATE INDEX IF NOT EXISTS idx_session_revocations_expires
    ON session_revocations (expires_at);

COMMENT ON TABLE session_revocations IS
    'Server-side revocation list for short-lived JWTs that were explicitly logged out.';
