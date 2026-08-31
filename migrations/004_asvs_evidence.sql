-- Durable, administrator-visible ASVS evidence. Live execution is separately
-- gated to seeded development environments, but previously produced evidence
-- remains readable through the regular operations panel.
CREATE TABLE IF NOT EXISTS asvs_runs (
    run_id UUID PRIMARY KEY,
    initiated_by UUID NOT NULL
        REFERENCES user_accounts(user_id) ON DELETE RESTRICT,
    status TEXT NOT NULL
        CHECK (status IN ('PASS', 'FAIL', 'INCONCLUSIVE', 'ERROR')),
    catalog_version TEXT NOT NULL
        CHECK (length(catalog_version) BETWEEN 1 AND 32),
    target_commit TEXT NOT NULL
        CHECK (length(target_commit) BETWEEN 1 AND 128),
    controls_total INTEGER NOT NULL
        CHECK (controls_total BETWEEN 1 AND 25),
    controls_passed INTEGER NOT NULL CHECK (controls_passed >= 0),
    controls_failed INTEGER NOT NULL CHECK (controls_failed >= 0),
    controls_inconclusive INTEGER NOT NULL CHECK (controls_inconclusive >= 0),
    controls_error INTEGER NOT NULL CHECK (controls_error >= 0),
    evidence JSONB NOT NULL
        CHECK (
            jsonb_typeof(evidence) = 'array'
            AND jsonb_array_length(evidence) BETWEEN 1 AND 25
        ),
    evidence_sha256 CHAR(64) NOT NULL
        CHECK (evidence_sha256 ~ '^[0-9a-f]{64}$'),
    duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0),
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    CHECK (completed_at >= started_at),
    CHECK (
        controls_total = controls_passed
            + controls_failed
            + controls_inconclusive
            + controls_error
    )
);

CREATE INDEX IF NOT EXISTS idx_asvs_runs_completed
    ON asvs_runs(completed_at DESC);

CREATE OR REPLACE FUNCTION reject_asvs_run_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'ASVS evidence runs are append-only';
END;
$$;

DROP TRIGGER IF EXISTS asvs_runs_immutable ON asvs_runs;
CREATE TRIGGER asvs_runs_immutable
BEFORE UPDATE OR DELETE ON asvs_runs
FOR EACH ROW EXECUTE FUNCTION reject_asvs_run_mutation();

COMMENT ON TABLE asvs_runs IS
    'Append-only, redacted evidence from administrator-triggered ASVS probes.';
