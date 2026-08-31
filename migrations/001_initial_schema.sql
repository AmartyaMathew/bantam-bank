CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS customers (
    customer_id UUID PRIMARY KEY,
    legal_name TEXT NOT NULL,
    date_of_birth DATE NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    kyc_status TEXT NOT NULL DEFAULT 'PENDING_KYC'
        CHECK (kyc_status IN ('PENDING_KYC', 'PENDING_REVIEW', 'KYC_VERIFIED', 'KYC_REJECTED')),
    risk_rating TEXT NOT NULL DEFAULT 'LOW'
        CHECK (risk_rating IN ('LOW', 'MEDIUM', 'HIGH')),
    status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_accounts (
    user_id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
        CHECK (role IN ('CUSTOMER', 'BANK_ADMIN', 'RISK_ANALYST', 'COMPLIANCE_AUDITOR', 'SERVICE_ACCOUNT')),
    customer_id UUID UNIQUE REFERENCES customers(customer_id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'LOCKED', 'DISABLED')),
    mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (role = 'CUSTOMER' AND customer_id IS NOT NULL)
        OR (role <> 'CUSTOMER' AND customer_id IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS bank_accounts (
    account_id UUID PRIMARY KEY,
    customer_id UUID REFERENCES customers(customer_id) ON DELETE RESTRICT,
    account_number_hash TEXT NOT NULL UNIQUE,
    account_reference TEXT NOT NULL UNIQUE,
    account_type TEXT NOT NULL CHECK (account_type IN ('CURRENT', 'SYSTEM')),
    currency CHAR(3) NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('PENDING', 'ACTIVE', 'FROZEN', 'CLOSED')),
    allow_negative BOOLEAN NOT NULL DEFAULT false,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ,
    CHECK (
        (account_type = 'SYSTEM' AND customer_id IS NULL AND allow_negative = true)
        OR (account_type = 'CURRENT' AND customer_id IS NOT NULL AND allow_negative = false)
    )
);

CREATE TABLE IF NOT EXISTS transactions (
    transaction_id UUID PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    request_id UUID NOT NULL,
    initiated_by_user_id UUID NOT NULL REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    source_account_id UUID NOT NULL REFERENCES bank_accounts(account_id) ON DELETE RESTRICT,
    destination_account_id UUID NOT NULL REFERENCES bank_accounts(account_id) ON DELETE RESTRICT,
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    currency CHAR(3) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    transaction_type TEXT NOT NULL DEFAULT 'TRANSFER'
        CHECK (transaction_type IN ('TRANSFER', 'DEMO_DEPOSIT', 'REVERSAL')),
    reverses_transaction_id UUID REFERENCES transactions(transaction_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'POSTED', 'FAILED', 'REVERSED')),
    failure_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    posted_at TIMESTAMPTZ,
    UNIQUE (initiated_by_user_id, idempotency_key),
    CHECK (source_account_id <> destination_account_id)
);

CREATE TABLE IF NOT EXISTS ledger_entries (
    ledger_entry_id UUID PRIMARY KEY,
    transaction_id UUID NOT NULL REFERENCES transactions(transaction_id) ON DELETE RESTRICT,
    account_id UUID NOT NULL REFERENCES bank_accounts(account_id) ON DELETE RESTRICT,
    amount_minor BIGINT NOT NULL CHECK (amount_minor <> 0),
    currency CHAR(3) NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('DEBIT', 'CREDIT')),
    entry_type TEXT NOT NULL CHECK (entry_type IN ('TRANSFER', 'DEMO_DEPOSIT', 'REVERSAL')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (direction = 'DEBIT' AND amount_minor < 0)
        OR (direction = 'CREDIT' AND amount_minor > 0)
    )
);

CREATE TABLE IF NOT EXISTS account_balances (
    account_id UUID PRIMARY KEY REFERENCES bank_accounts(account_id) ON DELETE RESTRICT,
    available_balance_minor BIGINT NOT NULL DEFAULT 0,
    current_balance_minor BIGINT NOT NULL DEFAULT 0,
    currency CHAR(3) NOT NULL,
    last_ledger_entry_id UUID REFERENCES ledger_entries(ledger_entry_id) ON DELETE RESTRICT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sca_challenges (
    challenge_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES user_accounts(user_id) ON DELETE CASCADE,
    source_account_id UUID NOT NULL REFERENCES bank_accounts(account_id) ON DELETE RESTRICT,
    destination_account_id UUID NOT NULL REFERENCES bank_accounts(account_id) ON DELETE RESTRICT,
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    code_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'CONSUMED', 'EXPIRED', 'FAILED')),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS outbox_events (
    outbox_event_id UUID PRIMARY KEY,
    aggregate_type TEXT NOT NULL,
    aggregate_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    event_version INT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'PUBLISHING', 'PUBLISHED')),
    publish_attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,
    claimed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_events (
    audit_event_id UUID PRIMARY KEY,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    request_id UUID NOT NULL,
    correlation_id UUID NOT NULL,
    ip_address INET,
    user_agent TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS risk_alerts (
    risk_alert_id UUID PRIMARY KEY,
    transaction_id UUID NOT NULL REFERENCES transactions(transaction_id) ON DELETE RESTRICT,
    customer_id UUID REFERENCES customers(customer_id) ON DELETE RESTRICT,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'REVIEWED', 'DISMISSED')),
    explanation TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at TIMESTAMPTZ,
    reviewed_by UUID REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    UNIQUE (transaction_id, rule_id)
);

CREATE TABLE IF NOT EXISTS notifications (
    notification_id UUID PRIMARY KEY,
    customer_id UUID NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
    event_id UUID NOT NULL,
    notification_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at TIMESTAMPTZ,
    UNIQUE (customer_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_accounts_customer_id
    ON bank_accounts(customer_id);
CREATE INDEX IF NOT EXISTS idx_transactions_source_account_created
    ON transactions(source_account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_destination_account_created
    ON transactions(destination_account_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_transactions_idempotency
    ON transactions(initiated_by_user_id, idempotency_key);
CREATE UNIQUE INDEX IF NOT EXISTS idx_transactions_single_reversal
    ON transactions(reverses_transaction_id)
    WHERE reverses_transaction_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ledger_entries_account_created
    ON ledger_entries(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_created
    ON audit_events(actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_created
    ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_outbox_unpublished
    ON outbox_events(status, created_at)
    WHERE status <> 'PUBLISHED';
CREATE INDEX IF NOT EXISTS idx_risk_alerts_status_created
    ON risk_alerts(status, created_at DESC);

CREATE OR REPLACE FUNCTION reject_ledger_entry_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'ledger entries are append-only';
END;
$$;

DROP TRIGGER IF EXISTS ledger_entries_immutable ON ledger_entries;
CREATE TRIGGER ledger_entries_immutable
BEFORE UPDATE OR DELETE ON ledger_entries
FOR EACH ROW EXECUTE FUNCTION reject_ledger_entry_mutation();

CREATE OR REPLACE FUNCTION assert_transaction_balanced()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_transaction UUID;
    posting_sum BIGINT;
    posting_count BIGINT;
BEGIN
    target_transaction := NEW.transaction_id;
    SELECT COALESCE(SUM(amount_minor), 0), COUNT(*)
      INTO posting_sum, posting_count
      FROM ledger_entries
     WHERE transaction_id = target_transaction;

    IF posting_count < 2 OR posting_sum <> 0 THEN
        RAISE EXCEPTION 'transaction % is not balanced: entries=%, sum=%',
            target_transaction, posting_count, posting_sum;
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS ledger_transaction_balanced ON ledger_entries;
CREATE CONSTRAINT TRIGGER ledger_transaction_balanced
AFTER INSERT ON ledger_entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_transaction_balanced();

CREATE OR REPLACE FUNCTION reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events;
CREATE TRIGGER audit_events_immutable
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();
