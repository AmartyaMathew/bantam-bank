-- Central abuse controls. Keys are SHA-256 digests; raw emails and IP addresses
-- intentionally never enter this table.
CREATE TABLE IF NOT EXISTS auth_rate_limits (
    key_hash TEXT PRIMARY KEY CHECK (length(key_hash) = 64),
    window_started_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts > 0),
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_rate_limits_updated_at
    ON auth_rate_limits(updated_at);

-- A customer may transfer between two accounts they own. Event/customer alone
-- therefore cannot distinguish the sent and received notification projections.
ALTER TABLE notifications
    ADD COLUMN IF NOT EXISTS account_id UUID
        REFERENCES bank_accounts(account_id) ON DELETE CASCADE;
ALTER TABLE notifications
    ADD COLUMN IF NOT EXISTS direction TEXT
        CHECK (direction IN ('SENT', 'RECEIVED'));
ALTER TABLE notifications
    DROP CONSTRAINT IF EXISTS notifications_customer_id_event_id_key;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'notifications_customer_event_account_direction_key'
          AND conrelid = 'notifications'::regclass
    ) THEN
        ALTER TABLE notifications
            ADD CONSTRAINT notifications_customer_event_account_direction_key
            UNIQUE (customer_id, event_id, account_id, direction);
    END IF;
END;
$$;

-- Available funds may be lower than current funds once holds exist, but they
-- must never be greater. NOT VALID makes the migration safe to introduce, then
-- validation proves the existing projection before enforcing future writes.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'account_balances_available_not_above_current'
          AND conrelid = 'account_balances'::regclass
    ) THEN
        ALTER TABLE account_balances
            ADD CONSTRAINT account_balances_available_not_above_current
            CHECK (available_balance_minor <= current_balance_minor) NOT VALID;
    END IF;
END;
$$;

ALTER TABLE account_balances
    VALIDATE CONSTRAINT account_balances_available_not_above_current;

-- SQL CHECK constraints cannot join bank_accounts, so a trigger provides the
-- database-layer twin of the application insufficient-funds check.
CREATE OR REPLACE FUNCTION reject_negative_customer_balance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    negative_allowed BOOLEAN;
BEGIN
    SELECT allow_negative
      INTO negative_allowed
      FROM bank_accounts
     WHERE account_id = NEW.account_id;

    IF negative_allowed IS NULL THEN
        RAISE EXCEPTION 'balance references an unknown account %', NEW.account_id;
    END IF;
    IF negative_allowed = false
       AND (NEW.current_balance_minor < 0 OR NEW.available_balance_minor < 0) THEN
        RAISE EXCEPTION 'customer account % cannot have a negative balance',
            NEW.account_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS account_balances_non_negative ON account_balances;
CREATE TRIGGER account_balances_non_negative
BEFORE INSERT OR UPDATE OF current_balance_minor, available_balance_minor
ON account_balances
FOR EACH ROW EXECUTE FUNCTION reject_negative_customer_balance();

-- Account type, ownership, and overdraft permission are structural identity,
-- not editable profile fields. Freezing them prevents a negative system
-- account from being reclassified as a customer account behind the balance
-- trigger's back.
CREATE OR REPLACE FUNCTION reject_account_classification_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.account_type IS DISTINCT FROM OLD.account_type
       OR NEW.customer_id IS DISTINCT FROM OLD.customer_id
       OR NEW.allow_negative IS DISTINCT FROM OLD.allow_negative THEN
        RAISE EXCEPTION 'account classification is immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS bank_accounts_classification_immutable ON bank_accounts;
CREATE TRIGGER bank_accounts_classification_immutable
BEFORE UPDATE OF account_type, customer_id, allow_negative
ON bank_accounts
FOR EACH ROW EXECUTE FUNCTION reject_account_classification_mutation();

-- Posted transaction metadata is durable history. The only permitted update
-- is the POSTED -> REVERSED lifecycle transition; the reversal itself is a new
-- transaction with compensating ledger entries.
CREATE OR REPLACE FUNCTION restrict_transaction_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'transaction history cannot be deleted';
    END IF;
    IF OLD.status <> 'POSTED'
       OR NEW.status <> 'REVERSED'
       OR (to_jsonb(NEW) - 'status') IS DISTINCT FROM
          (to_jsonb(OLD) - 'status') THEN
        RAISE EXCEPTION 'posted transaction history is immutable';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS transactions_history_restricted ON transactions;
CREATE TRIGGER transactions_history_restricted
BEFORE UPDATE OR DELETE ON transactions
FOR EACH ROW EXECUTE FUNCTION restrict_transaction_history_mutation();
